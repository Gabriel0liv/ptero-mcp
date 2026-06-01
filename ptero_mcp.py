import os
import fnmatch
import re
import tempfile
import zipfile
import gzip
import json
import asyncio
from urllib.parse import unquote

import requests
import websockets
import pymysql

import mcp.types as types
import mcp.server.stdio
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

PANEL = os.environ["PTERO_PANEL"].rstrip("/")
KEY = os.environ["PTERO_KEY"].strip()
SERVER = os.environ["PTERO_SERVER"].strip()  # identifier (8 chars)

DEFAULT_TIMEOUT = float(os.environ.get("PTERO_TIMEOUT", "30"))

# Safety: block dangerous console commands by default
ALLOW_DANGEROUS_CONSOLE = os.environ.get("ALLOW_DANGEROUS_CONSOLE", "0") == "1"
DANGEROUS_CMD_RE = re.compile(r"^\s*(stop|restart|end|shutdown)\b", re.IGNORECASE)


def get_co_db_config() -> dict:
    """Reads CoreProtect's config.yml from the remote server and parses MySQL credentials."""
    config_text = api_get_text(f"/api/client/servers/{SERVER}/files/contents", {"file": "plugins/CoreProtect/config.yml"})
    
    def parse_yaml_value(key: str) -> str:
        m = re.search(rf"^\s*{key}\s*:\s*(.+)$", config_text, re.MULTILINE)
        if m:
            val = m.group(1).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            return val
        return ""
    
    return {
        "use_mysql": parse_yaml_value("use-mysql").lower() == "true",
        "prefix": parse_yaml_value("table-prefix") or "co_",
        "host": parse_yaml_value("mysql-host"),
        "port": int(parse_yaml_value("mysql-port") or "3306"),
        "db": parse_yaml_value("mysql-database"),
        "user": parse_yaml_value("mysql-username"),
        "password": parse_yaml_value("mysql-password"),
    }


def is_safe_select_query(query: str) -> bool:
    """Validates if a SQL query is read-only (SELECT, SHOW, DESCRIBE, EXPLAIN)."""
    # Remove single-line and multi-line comments
    cleaned = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
    cleaned = cleaned.strip().lower()
    
    # Must start with select, show, describe, explain
    allowed_starts = ("select", "show", "describe", "explain")
    if not any(cleaned.startswith(start) for start in allowed_starts):
        return False
        
    # Block query chaining or dangerous words (defense in depth)
    dangerous_keywords = {"insert", "update", "delete", "drop", "truncate", "alter", "create", "replace", "grant", "revoke"}
    words = set(re.findall(r'\b\w+\b', cleaned))
    if words.intersection(dangerous_keywords):
        return False
        
    return True


def is_shell_command(cmd: str) -> bool:
    cmd_stripped = cmd.strip()
    parts = cmd_stripped.split()
    if not parts:
        return False
    first = parts[0].lower().lstrip("/")
    shell_tools = {"grep", "zgrep", "zcat", "tail", "wc", "cat", "cut", "awk", "sed", "gzip", "gunzip"}
    if first in shell_tools:
        return True
    # Bloqueia operadores se o comando contiver alguma ferramenta de shell (ex: zcat ... | tail -1)
    operators = {"|", ">", "<", "&&", ";"}
    has_operator = any(op in cmd_stripped for op in operators)
    if has_operator:
        words = {w.lower() for w in parts}
        if words.intersection(shell_tools):
            return True
    return False

ZIP_EXTS = (".zip", ".jar", ".mrpack", ".mcpack", ".resourcepack", ".datapack")
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

HEADERS = {
    "Authorization": f"Bearer {KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

SESSION = requests.Session()
SESSION.headers.update(HEADERS)

# Separate session for signed download URLs (avoid leaking Panel auth headers)
DL_SESSION = requests.Session()

server = Server("redhosting-ptero")


def _url(path: str) -> str:
    return f"{PANEL}{path}"


def norm_path(p: str, default: str = "/") -> str:
    """Raw server path (not URL-encoded). Also decodes accidental %2F input."""
    p = (p or "").strip()
    if not p:
        return default
    p = unquote(p)
    if not p.startswith("/"):
        p = "/" + p
    return p


def _raise_with_details(r: requests.Response) -> None:
    detail = ""
    try:
        j = r.json()
        if isinstance(j, dict) and "errors" in j and j["errors"]:
            e0 = j["errors"][0]
            detail = f"{e0.get('code','')} ({e0.get('status', r.status_code)}): {e0.get('detail','')}"
    except Exception:
        pass

    if not detail:
        body = (r.text or "").strip()
        detail = body[:500] + ("…" if len(body) > 500 else "") if body else f"HTTP {r.status_code}"
    raise requests.HTTPError(f"HTTP {r.status_code} - {detail}", response=r)


def api_get_json(path: str, params: dict | None = None) -> dict:
    r = SESSION.get(_url(path), params=params or {}, timeout=DEFAULT_TIMEOUT)
    if not r.ok:
        _raise_with_details(r)
    return r.json()


def api_get_text(path: str, params: dict | None = None) -> str:
    r = SESSION.get(_url(path), params=params or {}, timeout=max(DEFAULT_TIMEOUT, 60))
    if not r.ok:
        _raise_with_details(r)
    return r.text


def api_get_binary(path: str, params: dict | None = None) -> bytes:
    r = SESSION.get(_url(path), params=params or {}, timeout=max(DEFAULT_TIMEOUT, 60), stream=True)
    if not r.ok:
        _raise_with_details(r)
    try:
        return b"".join(chunk for chunk in r.iter_content(chunk_size=1024 * 256) if chunk)
    finally:
        r.close()


def api_post_json(path: str, body: dict) -> dict:
    r = SESSION.post(_url(path), json=body, timeout=DEFAULT_TIMEOUT)
    if not r.ok:
        _raise_with_details(r)
    return r.json() if r.text and r.text.strip() else {}


def format_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.2f} {u}"
        f /= 1024
    return f"{n} B"


def is_zip_like_path(path: str) -> bool:
    return path.lower().endswith(ZIP_EXTS)


def zip_safe_member(name: str) -> bool:
    # Prevent ZipSlip-style paths and treat directories like "folder/" as valid.
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        return False
    parts = [p for p in normalized.split("/") if p]  # drop empty parts from leading/trailing slashes
    return all(part != ".." for part in parts)



async def get_signed_download_url(file_path: str) -> str:
    signed = await asyncio.to_thread(api_get_json, f"/api/client/servers/{SERVER}/files/download", {"file": file_path})
    if isinstance(signed, dict) and "attributes" in signed and isinstance(signed["attributes"], dict):
        url = signed["attributes"].get("url")
    else:
        url = signed.get("url") if isinstance(signed, dict) else None
    if not url:
        raise ValueError(f"Resposta inesperada de /files/download: {signed}")
    return url


async def remote_peek_bytes(file_path: str, n: int = 8) -> bytes:
    """Read the first N bytes of a remote file via a signed download URL."""
    url = await get_signed_download_url(file_path)

    # Try HTTP range; if the backend ignores it, we still stop after N bytes.
    headers = {"Range": f"bytes=0-{n - 1}"}
    with DL_SESSION.get(url, headers=headers, stream=True, timeout=max(DEFAULT_TIMEOUT, 60)) as r:
        if not r.ok:
            _raise_with_details(r)
        data = b""
        for chunk in r.iter_content(chunk_size=1024):
            if not chunk:
                continue
            data += chunk
            if len(data) >= n:
                return data[:n]
        return data



async def is_remote_zip(file_path: str) -> bool:
    try:
        return (await remote_peek_bytes(file_path, 4)) in ZIP_MAGIC
    except Exception:
        return False


async def download_to_temp(file_path: str, max_download_mb: int, suffix: str = ".tmp") -> str:
    """Download a remote file to a temporary local file (size-limited)."""
    url = await get_signed_download_url(file_path)

    max_bytes = max_download_mb * 1024 * 1024
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    try:
        total = 0
        with os.fdopen(fd, "wb") as f:
            with DL_SESSION.get(url, stream=True, timeout=max(DEFAULT_TIMEOUT, 60)) as r:
                if not r.ok:
                    _raise_with_details(r)
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"Arquivo grande demais (> {max_download_mb} MB)")
                    f.write(chunk)
        return tmp_path
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


async def download_zip_to_temp(zip_file: str, max_download_mb: int) -> str:
    """Download a remote ZIP/JAR to a temporary local file (size-limited)."""
    return await download_to_temp(zip_file, max_download_mb, suffix=".zip")



async def ws_get_token_and_socket() -> tuple[str, str]:
    """
    Client API: GET /api/client/servers/{server}/websocket
    Returns token + socket URL.
    """
    data = await asyncio.to_thread(api_get_json, f"/api/client/servers/{SERVER}/websocket", {})
    # Usualmente: {"data":{"token":"...","socket":"wss://.../ws"}}
    if "data" in data and isinstance(data["data"], dict):
        token = data["data"].get("token")
        socket_url = data["data"].get("socket")
    else:
        token = data.get("token")
        socket_url = data.get("socket")
    if not token or not socket_url:
        raise ValueError(f"Resposta inesperada de /websocket: {data}")
    return token, socket_url


async def ws_connect(subscribe_logs: bool = True, subscribe_stats: bool = True, auth_timeout: float = 5.0):
    """Connect to the server WebSocket and optionally subscribe to logs/stats streams."""
    token, socket_url = await ws_get_token_and_socket()

    connect_kwargs = {
        "origin": PANEL,
        "ping_interval": 20,
        "ping_timeout": 20,
        "close_timeout": 5,
        "max_size": 2**23,
    }
    auth_headers = {"Authorization": f"Bearer {token}"}

    try:
        ws = await websockets.connect(socket_url, additional_headers=auth_headers, **connect_kwargs)
    except TypeError:
        ws = await websockets.connect(socket_url, extra_headers=auth_headers, **connect_kwargs)

    # 1) auth
    await ws.send(json.dumps({"event": "auth", "args": [token]}))

    # 2) wait auth success (or fail fast)
    end_at = asyncio.get_event_loop().time() + auth_timeout
    while True:
        timeout = max(0.1, end_at - asyncio.get_event_loop().time())
        if timeout <= 0:
            await ws.close()
            raise TimeoutError("Timeout ao aguardar 'auth success' do WebSocket.")

        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
        data = json.loads(msg)
        ev = data.get("event")

        if ev == "auth success":
            break
        if ev in ("jwt error", "daemon error", "error"):
            await ws.close()
            raise RuntimeError(f"Falha ao autenticar WebSocket: {ev} - {data.get('args')}")

        # Ignora outras mensagens iniciais (ex.: status)

    # 3) subscribe AFTER auth success
    if subscribe_logs:
        await ws.send(json.dumps({"event": "send logs", "args": []}))
    if subscribe_stats:
        await ws.send(json.dumps({"event": "send stats", "args": []}))

    return ws



@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="ptero_ls",
            description="Lista arquivos/diretórios no servidor (Pterodactyl files/list).",
            inputSchema={"type": "object", "properties": {"directory": {"type": "string", "default": "/"}}},
        ),
        types.Tool(
            name="ptero_read",
            description="Lê conteúdo de um arquivo (Pterodactyl files/contents) com limite de chars. Detecta ZIP por extensão e/ou magic bytes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "max_chars": {"type": "integer", "default": 120000},
                    "detect_zip": {"type": "boolean", "default": True},
                },
                "required": ["file"],
            },
        ),
        types.Tool(
            name="ptero_tail",
            description="Retorna as últimas N linhas de um arquivo (faz read e corta).",
            inputSchema={
                "type": "object",
                "properties": {"file": {"type": "string"}, "lines": {"type": "integer", "default": 200}},
                "required": ["file"],
            },
        ),
        types.Tool(
            name="ptero_grep",
            description="Procura padrão (regex simples) dentro de um arquivo.",
            inputSchema={
                "type": "object",
                "properties": {"file": {"type": "string"}, "pattern": {"type": "string"}, "max_matches": {"type": "integer", "default": 50}},
                "required": ["file", "pattern"],
            },
        ),
        types.Tool(
            name="ptero_command",
            description="Envia comando para o console via REST (não retorna output).",
            inputSchema={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        ),
        types.Tool(
            name="ptero_resources",
            description="Uso atual de CPU/memória/disco/rede (Client API /resources).",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="ptero_download_url",
            description="Gera um URL assinado para baixar um arquivo (Client API files/download).",
            inputSchema={"type": "object", "properties": {"file": {"type": "string"}}, "required": ["file"]},
        ),
        types.Tool(
            name="ptero_zip_list",
            description="Lista entradas de um arquivo ZIP remoto (baixa temporariamente e lista).",
            inputSchema={
                "type": "object",
                "properties": {
                    "zip_file": {"type": "string"},
                    "glob": {"type": "string", "default": "*"},
                    "max_entries": {"type": "integer", "default": 5000},
                    "max_download_mb": {"type": "integer", "default": 200},
                },
                "required": ["zip_file"],
            },
        ),
        types.Tool(
            name="ptero_zip_read",
            description="Lê uma entrada (arquivo) dentro de um ZIP remoto.",
            inputSchema={
                "type": "object",
                "properties": {
                    "zip_file": {"type": "string"},
                    "entry": {"type": "string"},
                    "max_chars": {"type": "integer", "default": 120000},
                    "max_entry_mb": {"type": "integer", "default": 10},
                    "max_download_mb": {"type": "integer", "default": 200},
                },
                "required": ["zip_file", "entry"],
            },
        ),
        types.Tool(
            name="ptero_zip_grep",
            description="Procura regex em arquivos (texto) dentro de um ZIP remoto.",
            inputSchema={
                "type": "object",
                "properties": {
                    "zip_file": {"type": "string"},
                    "pattern": {"type": "string"},
                    "entry_glob": {"type": "string", "default": "*"},
                    "max_matches": {"type": "integer", "default": 50},
                    "max_entry_mb": {"type": "integer", "default": 5},
                    "max_download_mb": {"type": "integer", "default": 200},
                },
                "required": ["zip_file", "pattern"],
            },
        ),
        # WebSocket tools
        types.Tool(
            name="ptero_ws_tail",
            description="Escuta console output via WebSocket por X segundos e devolve as linhas capturadas.",
            inputSchema={
                "type": "object",
                "properties": {
                    "seconds": {"type": "number", "default": 5},
                    "max_lines": {"type": "integer", "default": 200},
                },
            },
        ),
        types.Tool(
            name="ptero_ws_stats_once",
            description="Obtém 1 evento stats via WebSocket (CPU/memória/disk/rede/uptime/state).",
            inputSchema={"type": "object", "properties": {"timeout_seconds": {"type": "number", "default": 5}}},
        ),
        types.Tool(
            name="ptero_ws_command_capture",
            description="Envia comando via WebSocket e captura as próximas linhas do console por X segundos.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "seconds": {"type": "number", "default": 3},
                    "max_lines": {"type": "integer", "default": 200},
                },
                "required": ["command"],
            },
        ),
        types.Tool(
            name="ptero_gz_grep",
            description="Procura regex dentro de um arquivo de log comprimido (.gz). Retorna no formato nome_do_arquivo:linha: conteudo.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_gz": {"type": "string", "description": "Caminho do arquivo .log.gz"},
                    "pattern": {"type": "string", "description": "Expressão regular para buscar"},
                    "max_matches": {"type": "integer", "default": 50},
                    "max_download_mb": {"type": "integer", "default": 100},
                },
                "required": ["file_gz", "pattern"],
            },
        ),
        types.Tool(
            name="ptero_last_disconnect",
            description="Encontra a última vez que um determinado jogador desconectou do servidor, buscando no latest.log e retrocedendo nos arquivos .log.gz ou .log.",
            inputSchema={
                "type": "object",
                "properties": {
                    "player": {"type": "string", "description": "Nome do jogador (ex: dZeus)"},
                },
                "required": ["player"],
            },
        ),
        types.Tool(
            name="ptero_databases",
            description="Lista os bancos de dados criados e seus metadados (nome, host, user). Senha mascarada por padrão.",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_password": {
                        "type": "boolean",
                        "default": False,
                        "description": "Se verdadeiro, exibe a senha real do banco. Caso contrário, mascara com ********."
                    }
                }
            }
        ),
        types.Tool(
            name="ptero_backups",
            description="Lista backups do servidor (UUID, nome, checksum, tamanho em bytes, status, datas).",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="ptero_backup_download",
            description="Gera uma URL assinada para baixar um backup específico.",
            inputSchema={
                "type": "object",
                "properties": {
                    "backup_uuid": {"type": "string", "description": "UUID do backup"}
                },
                "required": ["backup_uuid"]
            }
        ),
        types.Tool(
            name="ptero_network",
            description="Lista as alocações de rede do servidor (IP, porta, se é primária, notas).",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="ptero_schedules",
            description="Lista os cronogramas (schedules) ativos/inativos e suas tarefas agendadas.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="ptero_startup",
            description="Lista o comando de inicialização do servidor e as variáveis (Egg Variables) configuradas.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="ptero_co_mysql_query",
            description="Executa uma consulta SQL read-only SELECT direta no banco MySQL do CoreProtect (credenciais resolvidas dinamicamente da config.yml remota).",
            inputSchema={
                "type": "object",
                "properties": {
                    "sql_query": {
                        "type": "string",
                        "description": "A consulta SQL (SELECT/SHOW/DESCRIBE/EXPLAIN) para rodar. Suporta o placeholder {prefix} que é automaticamente substituído pelo prefixo configurado (ex: co_)."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "description": "Número máximo de linhas a retornar (limite absoluto de 500)."
                    }
                },
                "required": ["sql_query"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
    async def run_blocking(fn, *args):
        return await asyncio.to_thread(fn, *args)

    try:
        if name == "ptero_ls":
            directory = norm_path(str(arguments.get("directory", "/")), default="/")
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/files/list", {"directory": directory})
            items = []
            for it in data.get("data", []):
                a = it.get("attributes", {})
                is_file = a.get("is_file", True)
                items.append(f'{a.get("name","?")}\t{"DIR" if not is_file else "FILE"}\t{a.get("size","")}')
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(items) if items else "(vazio)")])

        if name == "ptero_read":
            file = norm_path(str(arguments["file"]), default="/server.properties")
            max_chars = int(arguments.get("max_chars", 120000))
            detect_zip = bool(arguments.get("detect_zip", True))
            if is_zip_like_path(file):
                return types.CallToolResult(content=[types.TextContent(type="text", text="Arquivo ZIP/JAR detectado por extensão. Use ptero_zip_list, ptero_zip_read ou ptero_zip_grep.")])
            if detect_zip and await is_remote_zip(file):
                return types.CallToolResult(content=[types.TextContent(type="text", text="Arquivo ZIP detectado por assinatura (magic bytes). Use ptero_zip_list, ptero_zip_read ou ptero_zip_grep.")])
            text = await run_blocking(api_get_text, f"/api/client/servers/{SERVER}/files/contents", {"file": file})
            if len(text) > max_chars:
                text = text[:max_chars] + "\n\n…(cortado)"
            return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

        if name == "ptero_download_url":
            file = norm_path(str(arguments["file"]), default="/")
            url = await get_signed_download_url(file)
            return types.CallToolResult(content=[types.TextContent(type="text", text=url)])

        if name == "ptero_zip_list":
            zip_file = norm_path(str(arguments["zip_file"]), default="/")
            glob_pat = str(arguments.get("glob", "*"))
            max_entries = int(arguments.get("max_entries", 5000))
            max_download_mb = int(arguments.get("max_download_mb", 200))

            tmp_path = await download_zip_to_temp(zip_file, max_download_mb)
            try:
                if not zipfile.is_zipfile(tmp_path):
                    raise ValueError("Arquivo baixado não é um ZIP válido.")
                with zipfile.ZipFile(tmp_path, "r") as zf:
                    out = []
                    for info in zf.infolist():
                        if not zip_safe_member(info.filename):
                            continue
                        if not fnmatch.fnmatch(info.filename, glob_pat):
                            continue
                        kind = "DIR" if info.is_dir() else "FILE"
                        out.append(f"{info.filename}\t{kind}\t{format_bytes(info.file_size)}")
                        if len(out) >= max_entries:
                            out.append("…(limite atingido)")
                            break
                return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(out) if out else "(vazio)")])
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        if name == "ptero_zip_read":
            zip_file = norm_path(str(arguments["zip_file"]), default="/")
            entry = str(arguments["entry"])
            max_chars = int(arguments.get("max_chars", 120000))
            max_entry_mb = int(arguments.get("max_entry_mb", 10))
            max_download_mb = int(arguments.get("max_download_mb", 200))

            if not zip_safe_member(entry):
                return types.CallToolResult(content=[types.TextContent(type="text", text="ERRO: entrada inválida no ZIP.")])

            tmp_path = await download_zip_to_temp(zip_file, max_download_mb)
            try:
                if not zipfile.is_zipfile(tmp_path):
                    raise ValueError("Arquivo baixado não é um ZIP válido.")
                with zipfile.ZipFile(tmp_path, "r") as zf:
                    info = zf.getinfo(entry)
                    if info.file_size > max_entry_mb * 1024 * 1024:
                        raise ValueError(f"Entrada grande demais ({format_bytes(info.file_size)}).")
                    raw = zf.read(info)
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw[:256].hex() + ("\n…(binário)" if len(raw) > 256 else "")
                if len(text) > max_chars:
                    text = text[:max_chars] + "\n\n…(cortado)"
                return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        if name == "ptero_zip_grep":
            zip_file = norm_path(str(arguments["zip_file"]), default="/")
            pattern = str(arguments["pattern"])
            entry_glob = str(arguments.get("entry_glob", "*"))
            max_matches = int(arguments.get("max_matches", 50))
            max_entry_mb = int(arguments.get("max_entry_mb", 5))
            max_download_mb = int(arguments.get("max_download_mb", 200))

            rx = re.compile(pattern)
            tmp_path = await download_zip_to_temp(zip_file, max_download_mb)
            try:
                if not zipfile.is_zipfile(tmp_path):
                    raise ValueError("Arquivo baixado não é um ZIP válido.")
                matches = []
                with zipfile.ZipFile(tmp_path, "r") as zf:
                    for info in zf.infolist():
                        if not zip_safe_member(info.filename):
                            continue
                        if not fnmatch.fnmatch(info.filename, entry_glob):
                            continue
                        if info.is_dir() or info.file_size > max_entry_mb * 1024 * 1024:
                            continue
                        try:
                            text = zf.read(info).decode("utf-8", errors="ignore")
                        except Exception:
                            continue
                        for idx, line in enumerate(text.splitlines(), start=1):
                            if rx.search(line):
                                matches.append(f"{info.filename}:{idx}: {line}")
                                if len(matches) >= max_matches:
                                    matches.append("…(limite atingido)")
                                    return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(matches))])
                return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(matches) if matches else "(nenhum match)")])
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        if name == "ptero_tail":
            file = norm_path(str(arguments["file"]), default="/logs/latest.log")
            lines = int(arguments.get("lines", 200))
            text = await run_blocking(api_get_text, f"/api/client/servers/{SERVER}/files/contents", {"file": file})
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(text.splitlines()[-lines:]))])

        if name == "ptero_grep":
            file = norm_path(str(arguments["file"]), default="/logs/latest.log")
            pattern = str(arguments["pattern"])
            max_matches = int(arguments.get("max_matches", 50))
            text = await run_blocking(api_get_text, f"/api/client/servers/{SERVER}/files/contents", {"file": file})
            rx = re.compile(pattern)
            matches = []
            for i, line in enumerate(text.splitlines(), start=1):
                if rx.search(line):
                    matches.append(f"{i}: {line}")
                    if len(matches) >= max_matches:
                        matches.append("…(limite atingido)")
                        break
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(matches) if matches else "(nenhum match)")])

        if name == "ptero_gz_grep":
            file_gz = norm_path(str(arguments["file_gz"]), default="/")
            pattern = str(arguments["pattern"])
            max_matches = int(arguments.get("max_matches", 50))
            max_download_mb = int(arguments.get("max_download_mb", 100))

            tmp_path = await download_to_temp(file_gz, max_download_mb, suffix=".gz")
            try:
                rx = re.compile(pattern)
                matches = []
                with gzip.open(tmp_path, "rt", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, start=1):
                        if rx.search(line):
                            matches.append(f"{file_gz}:{i}: {line.strip()}")
                            if len(matches) >= max_matches:
                                matches.append("…(limite atingido)")
                                break
                return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(matches) if matches else "(nenhum match)")])
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        if name == "ptero_last_disconnect":
            player = str(arguments["player"]).strip()
            rx = re.compile(rf"(?i)(\b{re.escape(player)}\b.*(lost connection|left the game|disconnect|saiu|desconect))|(disconnecting.*\b{re.escape(player)}\b)")
            
            # Step 1: Check latest.log
            latest_path = "/logs/latest.log"
            last_match = None
            
            try:
                # To prevent out-of-memory issues on large log files, download and read line by line
                tmp_latest = await download_to_temp(latest_path, max_download_mb=100, suffix=".log")
                try:
                    with open(tmp_latest, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, start=1):
                            line_strip = line.strip()
                            if rx.search(line_strip):
                                if any(x in line_strip for x in ("issued server command:", "Checking command", "grep")):
                                    continue
                                last_match = f"{latest_path}:{i}: {line_strip}"
                finally:
                    try:
                        os.unlink(tmp_latest)
                    except Exception:
                        pass
            except Exception:
                # If latest.log doesn't exist or fails to download, proceed to rotated logs
                pass
                
            if last_match:
                return types.CallToolResult(content=[types.TextContent(type="text", text=last_match)])
                
            # Step 2: List and sort rotated logs
            try:
                data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/files/list", {"directory": "/logs"})
            except Exception as e:
                return types.CallToolResult(content=[types.TextContent(type="text", text=f"ERRO ao listar diretório /logs: {e}")])
                
            log_items = []
            for it in data.get("data", []):
                a = it.get("attributes", {})
                if a.get("is_file", True):
                    name_str = a.get("name", "")
                    # Ignore latest.log since we already searched it, and ignore huge debug/crash logs to optimize speed
                    if (name_str.endswith(".log.gz") or name_str.endswith(".log")) and name_str != "latest.log" and not name_str.startswith("debug") and not name_str.startswith("crash"):
                        log_items.append({
                            "name": name_str,
                            "modified_at": a.get("modified_at", "")
                        })
            
            # Sort: items with modified_at come first (by modified_at descending), fallback/tie-break to name descending
            def sort_key(item):
                mtime = item.get("modified_at", "")
                return (1 if mtime else 0, mtime, item.get("name", ""))
                
            log_items.sort(key=sort_key, reverse=True)
            
            # Step 3: Traverse log files from newest to oldest
            for log_file in log_items:
                name_str = log_file["name"]
                full_path = f"/logs/{name_str}"
                
                try:
                    tmp_log = await download_to_temp(full_path, max_download_mb=100, suffix=(".gz" if name_str.endswith(".gz") else ".log"))
                    try:
                        found_in_file = None
                        if name_str.endswith(".gz"):
                            with gzip.open(tmp_log, "rt", encoding="utf-8", errors="ignore") as f:
                                for i, line in enumerate(f, start=1):
                                    line_strip = line.strip()
                                    if rx.search(line_strip):
                                        if any(x in line_strip for x in ("issued server command:", "Checking command", "grep")):
                                            continue
                                        found_in_file = f"{full_path}:{i}: {line_strip}"
                        else:
                            with open(tmp_log, "r", encoding="utf-8", errors="ignore") as f:
                                for i, line in enumerate(f, start=1):
                                    line_strip = line.strip()
                                    if rx.search(line_strip):
                                        if any(x in line_strip for x in ("issued server command:", "Checking command", "grep")):
                                            continue
                                        found_in_file = f"{full_path}:{i}: {line_strip}"
                                        
                        if found_in_file:
                            return types.CallToolResult(content=[types.TextContent(type="text", text=found_in_file)])
                    finally:
                        try:
                            os.unlink(tmp_log)
                        except Exception:
                            pass
                except Exception:
                    # If download/read fails, skip to next file to be resilient
                    continue
                    
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"Nenhuma desconexão encontrada para o jogador: {player}")])

        if name == "ptero_command":
            cmd = str(arguments["command"]).strip()
            if is_shell_command(cmd):
                return types.CallToolResult(content=[types.TextContent(type="text", text="BLOQUEADO: isto é o console do Minecraft (RCON/stdin) e não um terminal bash/PowerShell. O console aceita apenas comandos de jogo (ex: 'list', 'op', 'say'). Para ler, filtrar ou pesquisar em arquivos de log, use as ferramentas apropriadas: 'ptero_tail', 'ptero_grep' ou 'ptero_gz_grep'.")])
            if (not ALLOW_DANGEROUS_CONSOLE) and DANGEROUS_CMD_RE.search(cmd):
                return types.CallToolResult(content=[types.TextContent(type="text", text="BLOQUEADO: comando potencialmente destrutivo.")])
            await run_blocking(api_post_json, f"/api/client/servers/{SERVER}/command", {"command": cmd})
            return types.CallToolResult(content=[types.TextContent(type="text", text="OK")])

        if name == "ptero_resources":
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/resources", {})
            attr = data.get("attributes", {})
            res = attr.get("resources", {})
            out = "\n".join(
                [
                    f"state: {attr.get('current_state')}",
                    f"cpu_absolute: {res.get('cpu_absolute')}%",
                    f"memory: {format_bytes(int(res.get('memory_bytes', 0)))}",
                    f"disk: {format_bytes(int(res.get('disk_bytes', 0)))}",
                    f"network_rx: {format_bytes(int(res.get('network_rx_bytes', 0)))}",
                    f"network_tx: {format_bytes(int(res.get('network_tx_bytes', 0)))}",
                ]
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=out)])

        # ---------- WebSocket tools ----------
        if name == "ptero_ws_tail":
            seconds = float(arguments.get("seconds", 5))
            max_lines = int(arguments.get("max_lines", 200))
            lines: list[str] = []

            ws = await ws_connect(subscribe_logs=True, subscribe_stats=False)
            try:
                end_at = asyncio.get_event_loop().time() + seconds
                while asyncio.get_event_loop().time() < end_at and len(lines) < max_lines:
                    timeout = max(0.1, end_at - asyncio.get_event_loop().time())
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    except asyncio.TimeoutError:
                        break

                    data = json.loads(msg)
                    ev = data.get("event")
                    if ev == "console output":
                        args = data.get("args", [])
                        if args:
                            lines.append(args[0])
            finally:
                await ws.close()

            return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(lines) if lines else "(sem output)")])

        if name == "ptero_ws_stats_once":
            timeout_seconds = float(arguments.get("timeout_seconds", 5))
            ws = await ws_connect(subscribe_logs=False, subscribe_stats=True)
            try:
                # Stats chegam como event='stats' e args[0] é JSON string. :contentReference[oaicite:6]{index=6}
                end_at = asyncio.get_event_loop().time() + timeout_seconds
                while asyncio.get_event_loop().time() < end_at:
                    msg = await asyncio.wait_for(ws.recv(), timeout=max(0.1, end_at - asyncio.get_event_loop().time()))
                    data = json.loads(msg)
                    if data.get("event") in ("jwt error", "daemon error"):
                        return types.CallToolResult(content=[types.TextContent(type="text", text=f"{data.get('event')}: {data.get('args')}")])
                    if data.get("event") == "stats":
                        args = data.get("args", [])
                        payload = json.loads(args[0]) if args else {}
                        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))])
            finally:
                await ws.close()

            return types.CallToolResult(content=[types.TextContent(type="text", text="(timeout sem stats)")])

        if name == "ptero_ws_command_capture":
            cmd = str(arguments["command"]).strip()
            if is_shell_command(cmd):
                return types.CallToolResult(content=[types.TextContent(type="text", text="BLOQUEADO: isto é o console do Minecraft (RCON/stdin) e não um terminal bash/PowerShell. O console aceita apenas comandos de jogo (ex: 'list', 'op', 'say'). Para ler, filtrar ou pesquisar em arquivos de log, use as ferramentas apropriadas: 'ptero_tail', 'ptero_grep' ou 'ptero_gz_grep'.")])
            if (not ALLOW_DANGEROUS_CONSOLE) and DANGEROUS_CMD_RE.search(cmd):
                return types.CallToolResult(content=[types.TextContent(type="text", text="BLOQUEADO: comando potencialmente destrutivo.")])

            seconds = float(arguments.get("seconds", 3))
            max_lines = int(arguments.get("max_lines", 200))
            lines: list[str] = []

            ws = await ws_connect(subscribe_logs=True, subscribe_stats=False)
            try:
                # Envia comando via WS: event='send command', args=[command].
                await ws.send(json.dumps({"event": "send command", "args": [cmd]}))

                end_at = asyncio.get_event_loop().time() + seconds
                while asyncio.get_event_loop().time() < end_at and len(lines) < max_lines:
                    timeout = max(0.1, end_at - asyncio.get_event_loop().time())
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    except asyncio.TimeoutError:
                        break

                    data = json.loads(msg)
                    ev = data.get("event")

                    if ev in ("jwt error", "daemon error", "error"):
                        return types.CallToolResult(content=[
                            types.TextContent(type="text", text=f"{ev}: {data.get('args')}")
                        ])

                    if ev == "console output":
                        args = data.get("args", [])
                        if args:
                            lines.append(args[0])
            finally:
                await ws.close()

            return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(lines) if lines else "(sem output)")])

        if name == "ptero_databases":
            include_password = bool(arguments.get("include_password", False))
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/databases", {"include": "password"})
            out = []
            for db in data.get("data", []):
                attrs = db.get("attributes", {})
                host_info = attrs.get("host", {})
                host_str = f"{host_info.get('address')}:{host_info.get('port')}"
                
                pwd_val = "[REDACTED]"
                if include_password:
                    rel = attrs.get("relationships", {})
                    pwd_obj = rel.get("password", {})
                    pwd_attrs = pwd_obj.get("attributes", {})
                    pwd_val = pwd_attrs.get("password", "********")
                
                out.append("\n".join([
                    f"Database: {attrs.get('name')}",
                    f"  Username: {attrs.get('username')}",
                    f"  Host: {host_str}",
                    f"  Connections From: {attrs.get('connections_from')}",
                    f"  Password: {pwd_val}",
                ]))
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n\n".join(out) if out else "(nenhum banco de dados criado)")])

        if name == "ptero_backups":
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/backups", {})
            out = []
            for bk in data.get("data", []):
                attrs = bk.get("attributes", {})
                size_str = format_bytes(attrs.get("bytes", 0))
                completed = "Sim" if attrs.get("is_successful") or attrs.get("completed_at") else "Não/Pendente"
                out.append("\n".join([
                    f"Backup: {attrs.get('name')}",
                    f"  UUID: {attrs.get('uuid')}",
                    f"  Tamanho: {size_str}",
                    f"  Checksum: {attrs.get('checksum', 'N/A')}",
                    f"  Concluído: {completed}",
                    f"  Criado em: {attrs.get('created_at')}",
                ]))
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n\n".join(out) if out else "(nenhum backup encontrado)")])

        if name == "ptero_backup_download":
            backup_uuid = str(arguments["backup_uuid"]).strip()
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/backups/{backup_uuid}/download", {})
            url = ""
            if "attributes" in data and isinstance(data["attributes"], dict):
                url = data["attributes"].get("url", "")
            else:
                url = data.get("url", "")
            if not url:
                raise ValueError(f"Resposta inesperada do endpoint de download: {data}")
            return types.CallToolResult(content=[types.TextContent(type="text", text=url)])

        if name == "ptero_network":
            # O endpoint separado de network não é suportado pelo Wings do Redhosting.
            # No entanto, os detalhes do servidor expõem alocações na relação 'allocations'.
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}", {})
            attrs = data.get("attributes", {})
            rel = attrs.get("relationships", {})
            allocs = rel.get("allocations", {}).get("data", [])
            out = []
            for alloc in allocs:
                a_attrs = alloc.get("attributes", {})
                ip_alias = a_attrs.get("ip_alias")
                ip_alias_str = f" ({ip_alias})" if ip_alias else ""
                prim = "Sim" if a_attrs.get("is_default") else "Não"
                out.append("\n".join([
                    f"Alocação: {a_attrs.get('ip')}{ip_alias_str}:{a_attrs.get('port')}",
                    f"  ID: {a_attrs.get('id')}",
                    f"  Primária: {prim}",
                    f"  Notas: {a_attrs.get('notes') or 'Nenhuma'}",
                ]))
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n\n".join(out) if out else "(nenhuma alocação de rede)")])

        if name == "ptero_schedules":
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/schedules", {})
            out = []
            for sc in data.get("data", []):
                attrs = sc.get("attributes", {})
                cron_info = attrs.get("cron", {})
                cron_str = f"{cron_info.get('minute')} {cron_info.get('hour')} {cron_info.get('day_of_month')} {cron_info.get('month')} {cron_info.get('day_of_week')}"
                
                tasks_list = []
                rel = attrs.get("relationships", {})
                tasks_data = rel.get("tasks", {}).get("data", [])
                if not tasks_data:
                    tasks_data = attrs.get("tasks", [])
                
                for task in tasks_data:
                    t_attrs = task.get("attributes", {})
                    act = t_attrs.get("action", "")
                    payload = t_attrs.get("payload", "")
                    power_warn = " [Ação de Energia]" if act == "power" else ""
                    tasks_list.append(f"    - Seq {t_attrs.get('sequence_id')}: Ação={act}{power_warn}, Payload={payload}")
                
                tasks_str = "\n".join(tasks_list) if tasks_list else "    (nenhuma tarefa configurada)"
                
                out.append("\n".join([
                    f"Schedule: {attrs.get('name')} (ID: {attrs.get('id')})",
                    f"  Cron Expression: {cron_str}",
                    f"  Ativa: {'Sim' if attrs.get('is_active') else 'Não'}",
                    f"  Última execução: {attrs.get('last_run_at') or 'Nunca'}",
                    f"  Próxima execução: {attrs.get('next_run_at') or 'N/A'}",
                    f"  Tarefas:",
                    tasks_str
                ]))
            return types.CallToolResult(content=[types.TextContent(type="text", text="\n\n".join(out) if out else "(nenhum cronograma agendado)")])

        if name == "ptero_startup":
            data = await run_blocking(api_get_json, f"/api/client/servers/{SERVER}/startup", {})
            meta = data.get("meta", {})
            egg_variables = data.get("data", [])
            
            vars_list = []
            for var in egg_variables:
                v_attrs = var.get("attributes", {})
                vars_list.append("\n".join([
                    f"  Nome: {v_attrs.get('name')} ({v_attrs.get('env_variable')})",
                    f"    Descrição: {v_attrs.get('description')}",
                    f"    Valor Atual: {v_attrs.get('server_value')}",
                    f"    Valor Padrão: {v_attrs.get('default_value')}",
                ]))
                
            vars_str = "\n\n".join(vars_list) if vars_list else "  (nenhuma variável de Egg configurada)"
            
            out = "\n".join([
                f"Comando de Inicialização:",
                f"  {meta.get('startup_command')}",
                f"Comando de Inicialização Bruto:",
                f"  {meta.get('raw_startup_command')}",
                f"\nVariáveis de Inicialização (Egg Variables):",
                vars_str
            ])
            return types.CallToolResult(content=[types.TextContent(type="text", text=out)])

        if name == "ptero_co_mysql_query":
            sql_query = str(arguments["sql_query"]).strip()
            limit = int(arguments.get("limit", 100))
            if limit < 1:
                limit = 1
            if limit > 500:
                limit = 500

            # 1. Safety validation
            if not is_safe_select_query(sql_query):
                return types.CallToolResult(content=[types.TextContent(type="text", text="BLOQUEADO: Apenas consultas SELECT, SHOW, DESCRIBE ou EXPLAIN são permitidas e modificações foram bloqueadas por segurança.")])

            # 2. Get DB Config
            try:
                db_config = await run_blocking(get_co_db_config)
            except Exception as e:
                return types.CallToolResult(content=[types.TextContent(type="text", text=f"ERRO ao obter configuração do CoreProtect: {e}")])

            if not db_config["use_mysql"]:
                return types.CallToolResult(content=[types.TextContent(type="text", text="ERRO: O CoreProtect do servidor não está configurado para usar MySQL (use-mysql=false).")])

            # 3. Apply prefix replacement
            prefix = db_config.get("prefix", "co_")
            actual_query = sql_query.replace("{prefix}", prefix)

            # 4. Connect and execute
            try:
                def execute_query():
                    conn = pymysql.connect(
                        host=db_config["host"],
                        port=db_config["port"],
                        user=db_config["user"],
                        password=db_config["password"],
                        database=db_config["db"],
                        charset='utf8mb4',
                        cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=10
                    )
                    try:
                        with conn.cursor() as cursor:
                            cursor.execute(actual_query)
                            rows = cursor.fetchmany(limit + 1)
                            return rows
                    finally:
                        conn.close()

                rows = await run_blocking(execute_query)
            except Exception as e:
                return types.CallToolResult(content=[types.TextContent(type="text", text=f"ERRO ao executar query MySQL: {e}")])

            if not rows:
                return types.CallToolResult(content=[types.TextContent(type="text", text="(sem resultados)")])

            has_more = len(rows) > limit
            display_rows = rows[:limit]

            # 5. Format output as a markdown table
            headers = list(display_rows[0].keys())
            table_lines = []
            # Header
            table_lines.append("| " + " | ".join(headers) + " |")
            # Separator
            table_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
            # Data rows
            for row in display_rows:
                row_vals = []
                for h in headers:
                    val = row[h]
                    if val is None:
                        val_str = "NULL"
                    else:
                        val_str = str(val).replace("\n", " ").replace("|", "\\|")
                    row_vals.append(val_str)
                table_lines.append("| " + " | ".join(row_vals) + " |")

            output_text = "\n".join(table_lines)
            if has_more:
                output_text += f"\n\n*(Consulta limitada às primeiras {limit} linhas)*"

            return types.CallToolResult(content=[types.TextContent(type="text", text=output_text)])


        return types.CallToolResult(content=[types.TextContent(type="text", text=f"ERRO: Tool desconhecida: {name}")])

    except Exception as e:
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"ERRO: {e}")])


async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="redhosting-ptero",
                server_version="0.2.0-ws",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())