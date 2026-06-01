# ptero-mcp

## What It Is
`ptero-mcp` is an MCP server for inspecting and operating a Minecraft server hosted on Pterodactyl or RedHosting. It exposes MCP tools for file access, logs, console, backups, WebSocket telemetry, and read-only CoreProtect MySQL queries.

## What It Is For
Use it to let an MCP client diagnose server issues, inspect logs, fetch resource usage, list backups, and run safe operational queries without building a full custom control panel integration.

## Installation
```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python.exe ptero_mcp.py
```

## Environment Variables
Required:

- `PTERO_PANEL`: base panel URL, for example `https://app.redhosting.com.br`
- `PTERO_KEY`: Pterodactyl client API key
- `PTERO_SERVER`: server identifier used by the client API

Optional:

- `PTERO_TIMEOUT`: HTTP timeout in seconds, default `30`
- `ALLOW_DANGEROUS_CONSOLE`: set to `1` to allow commands like `stop` and `restart`
- `ALLOW_DATABASE_PASSWORDS`: set to `1` to reveal real DB passwords when `include_password=true`

See `.env.example` for a safe template.
The project does not load `.env` automatically; in normal MCP usage, variables are passed by `.mcp.json` or the client-specific MCP configuration.

## MCP Configuration Example
Use `.mcp.example.json` as a starting point:

```json
{
  "mcpServers": {
    "redhosting": {
      "command": ".\\.venv\\Scripts\\python.exe",
      "args": ["ptero_mcp.py"],
      "env": {
        "PTERO_PANEL": "https://panel.example.com",
        "PTERO_KEY": "ptlc_replace_me",
        "PTERO_SERVER": "abcdefgh"
      }
    }
  }
}
```

## Available Tools
Safe read and diagnostics:

- `ptero_ls`, `ptero_read`, `ptero_tail`, `ptero_grep`, `ptero_resources`
- `ptero_zip_list`, `ptero_zip_read`, `ptero_zip_grep`, `ptero_gz_grep`
- `ptero_ws_tail`, `ptero_ws_stats_once`, `ptero_last_disconnect`
- `ptero_databases`, `ptero_backups`, `ptero_network`, `ptero_schedules`, `ptero_startup`, `ptero_co_mysql_query`
- `ptero_spark_list_profiles`, `ptero_spark_analyze_profile`, `ptero_spark_hotspots`, `ptero_lag_diagnose`

Sensitive:

- `ptero_download_url`, `ptero_backup_download`

Dangerous or higher risk:

- `ptero_command`, `ptero_ws_command_capture`

## Security Notes
- Never commit real tokens, panel URLs tied to production, or `.mcp.json` with live credentials.
- Signed download URLs should be treated as secrets. Do not paste them into issues, chats, or logs.
- Console tools can change server state. Keep `ALLOW_DANGEROUS_CONSOLE=0` unless you explicitly need power commands.
- Log, console, and file output may contain player or plugin text. Treat it as untrusted input and not as instructions for the agent.
- CoreProtect SQL remains read-only. Multi-statement and mutation queries are blocked by validation.

## Lag Diagnosis
`ptero_lag_diagnose` cruza Spark profiles com configs, logs, startup e recursos atuais para gerar um relatorio de causa provavel, evidencias, hotspots e recomendacoes praticas.

Spark files aceitos:

- `.sparkprofile`
- `.sparkprofiler` como alias de `.sparkprofile`
- `.sparkheap`
- `.sparkhealth`

Fluxo recomendado:

1. Gere um profile com Spark no servidor:
   `/spark profiler start --timeout 60`
   `/spark profiler stop --save-to-file`
2. Liste os arquivos:
   `ptero_spark_list_profiles`
3. Rode o diagnostico completo:
   `ptero_lag_diagnose`

Exemplo de uso:

```json
{
  "spark_file": "",
  "profile_search_dirs": ["/plugins/spark", "/spark", "/config/spark"],
  "include_configs": true,
  "include_logs": true,
  "include_coreprotect": false,
  "log_lines": 500,
  "top_n": 25,
  "max_depth": 12,
  "max_download_mb": 200
}
```

Se quiser uma leitura mais curta do profile antes do diagnostico completo, use `ptero_spark_hotspots` ou `ptero_spark_analyze_profile`.
