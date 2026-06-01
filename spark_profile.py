import json
import re
from collections import Counter, defaultdict


SPARK_EXTENSIONS = {
    ".sparkprofile": "sparkprofile",
    ".sparkprofiler": "sparkprofile",
    ".sparkheap": "sparkheap",
    ".sparkhealth": "sparkhealth",
}

SUSPECT_RULES = [
    {
        "category": "entity_ticking",
        "label": "Entity ticking",
        "patterns": [
            r"entity",
            r"tickentity",
            r"ticknonpassenger",
            r"activationrange",
            r"mob",
            r"pathfind",
            r"goalselector",
        ],
        "summary": "Muitas amostras apontam para entidades, IA ou tick de mobs.",
        "recommendation": "Reduza simulation-distance, investigue farms/mobcaps e verifique acumulacao de entidades.",
    },
    {
        "category": "chunk_loading",
        "label": "Chunk loading",
        "patterns": [
            r"chunk",
            r"poi",
            r"distancemanager",
            r"regionfile",
            r"playerchunk",
            r"ticket",
        ],
        "summary": "As amostras indicam custo alto em carregamento ou gerenciamento de chunks.",
        "recommendation": "Reduza view-distance, revise carregadores de chunk e verifique exploracao intensa.",
    },
    {
        "category": "worldgen",
        "label": "World generation",
        "patterns": [
            r"worldgen",
            r"noise",
            r"carver",
            r"feature",
            r"biome",
            r"structure",
            r"chunkstatus",
        ],
        "summary": "Ha sinais de geracao de mundo pesada.",
        "recommendation": "Pre-gere o mapa, use Chunky e revise mods/plugins de dimensao ou worldgen.",
    },
    {
        "category": "block_entities",
        "label": "Block entities e hoppers",
        "patterns": [
            r"blockentity",
            r"tileentity",
            r"hopper",
            r"container",
            r"inventory",
            r"furnace",
            r"chest",
        ],
        "summary": "Block entities, hoppers ou inventarios aparecem com frequencia.",
        "recommendation": "Ajuste configuracoes de hopper/tick rate e revise farms de hoppers e storage automatizado.",
    },
    {
        "category": "database_storage",
        "label": "Database/storage",
        "patterns": [
            r"coreprotect",
            r"sqlite",
            r"mysql",
            r"mariadb",
            r"hikari",
            r"jdbc",
            r"database",
            r"storage",
        ],
        "summary": "As amostras sugerem custo em database ou armazenamento.",
        "recommendation": "Revise latencia de banco, uso de SQLite, conexoes e writes sincronas.",
    },
    {
        "category": "map_rendering",
        "label": "Mapa/render",
        "patterns": [
            r"dynmap",
            r"bluemap",
            r"render",
            r"tiles",
            r"map",
        ],
        "summary": "Renderizacao de mapa ou tiles parece estar pesando.",
        "recommendation": "Pause fullrenders, reduza threads e evite renderizacao em horario de pico.",
    },
    {
        "category": "gc_memory",
        "label": "GC/memoria",
        "patterns": [
            r"gc",
            r"garbagecollector",
            r"g1gc",
            r"allocation",
            r"heap",
            r"oom",
            r"outofmemory",
        ],
        "summary": "Ha sinais de pressao de memoria ou garbage collection.",
        "recommendation": "Revise Xms/Xmx, flags JVM, vazamentos de memoria e mods/plugins consumidores.",
    },
    {
        "category": "disk_io",
        "label": "Disco/I-O",
        "patterns": [
            r"filechannel",
            r"nio",
            r"disk",
            r"flush",
            r"save",
            r"write",
            r"read",
            r"io",
        ],
        "summary": "Amostras indicam espera por leitura/escrita em disco ou I/O.",
        "recommendation": "Investigue backups, saves, bancos, armazenamento lento e plugins que gravam com frequencia.",
    },
    {
        "category": "worldedit",
        "label": "WorldEdit/FAWE",
        "patterns": [
            r"worldedit",
            r"fawe",
            r"fastasyncworldedit",
            r"clipboard",
            r"extent",
        ],
        "summary": "WorldEdit ou FAWE aparecem como suspeitos.",
        "recommendation": "Revise operacoes massivas, filas pendentes e configuracoes async do plugin.",
    },
]


def detect_spark_type(path: str) -> str | None:
    lowered = path.lower()
    for ext, kind in SPARK_EXTENSIONS.items():
        if lowered.endswith(ext):
            return kind
    return None


def extract_text_tokens(data: bytes) -> list[str]:
    pattern = re.compile(rb"[A-Za-z0-9_.$/:\-<>]{4,}")
    tokens = []
    for raw in pattern.findall(data):
        token = raw.decode("utf-8", errors="ignore").strip()
        if len(token) < 4:
            continue
        tokens.append(token.replace("/", "."))
    return tokens


def guess_encoding_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in text[:5000] if ch.isprintable() or ch in "\r\n\t")
        total = max(1, len(text[:5000]))
        if printable / total > 0.8:
            return text
    return ""


def _extract_thread_names(tokens: list[str]) -> list[str]:
    results = []
    seen = set()
    patterns = (
        "server thread",
        "worker",
        "netty",
        "chunk",
        "io thread",
        "render",
        "pool",
        "watchdog",
    )
    for token in tokens:
        lower = token.lower()
        if any(piece in lower for piece in patterns):
            if token not in seen:
                seen.add(token)
                results.append(token)
        if len(results) >= 12:
            break
    return results


def _score_rules(tokens: list[str]) -> tuple[dict, list[dict], list[dict]]:
    counter = Counter(token.lower() for token in tokens)
    category_scores = defaultdict(int)
    hotspots = []
    causes = []

    for rule in SUSPECT_RULES:
        matched = []
        score = 0
        for token, count in counter.items():
            if any(re.search(pattern, token) for pattern in rule["patterns"]):
                matched.append((token, count))
                score += count
        if score <= 0:
            continue
        matched.sort(key=lambda item: item[1], reverse=True)
        category_scores[rule["category"]] += score
        hotspots.append(
            {
                "label": rule["label"],
                "score": score,
                "examples": [token for token, _ in matched[:5]],
            }
        )
        causes.append(
            {
                "category": rule["category"],
                "label": rule["label"],
                "score": score,
                "summary": rule["summary"],
                "recommendation": rule["recommendation"],
                "examples": [token for token, _ in matched[:5]],
            }
        )

    hotspots.sort(key=lambda item: item["score"], reverse=True)
    causes.sort(key=lambda item: item["score"], reverse=True)
    return dict(category_scores), hotspots, causes


def _extract_plugin_candidates(tokens: list[str], top_n: int) -> list[str]:
    candidates = Counter()
    for token in tokens:
        lower = token.lower()
        if "." not in lower:
            continue
        if lower.startswith(("java.", "javax.", "sun.", "jdk.")):
            continue
        if lower.startswith(("net.minecraft", "org.bukkit", "io.papermc", "com.destroystokyo")):
            continue
        head = lower.split(".")[0:3]
        candidates[".".join(head)] += 1
    return [name for name, _ in candidates.most_common(top_n)]


def analyze_spark_bytes(file_path: str, data: bytes, top_n: int = 25, max_depth: int = 12) -> dict:
    spark_type = detect_spark_type(file_path) or "desconhecido"
    decoded_text = guess_encoding_text(data)
    tokens = extract_text_tokens(data)
    category_scores, hotspots, causes = _score_rules(tokens)
    plugin_candidates = _extract_plugin_candidates(tokens, top_n)

    metadata = {
        "file": file_path,
        "spark_type": spark_type,
        "size_bytes": len(data),
        "max_depth": max_depth,
        "text_like": bool(decoded_text),
        "token_count": len(tokens),
    }

    threads = _extract_thread_names(tokens)
    raw_top_tokens = Counter(token for token in tokens if len(token) <= 120).most_common(top_n)

    confidence = "baixa"
    if hotspots:
        confidence = "media"
    if len(hotspots) >= 3 or any(item["score"] > 20 for item in hotspots):
        confidence = "alta"

    summary = (
        f"Profile {spark_type} com {len(data)} bytes. "
        f"Foram extraidos {len(tokens)} tokens e {len(hotspots)} grupos suspeitos."
    )

    return {
        "metadata": metadata,
        "summary": summary,
        "confidence": confidence,
        "threads": threads,
        "hotspots": hotspots[:top_n],
        "suspected_causes": causes[:top_n],
        "plugin_candidates": plugin_candidates,
        "top_tokens": [{"token": token, "count": count} for token, count in raw_top_tokens],
        "category_scores": category_scores,
        "notes": [
            "A analise do Spark e heuristica. Perfis binarios do Spark podem exigir interpretacao por strings e stacks detectadas.",
        ],
    }


def format_profile_analysis(analysis: dict, short: bool = False, top_n: int = 15) -> str:
    lines = [
        "# Analise Spark",
        "",
        f"Arquivo: {analysis['metadata']['file']}",
        f"Tipo: {analysis['metadata']['spark_type']}",
        f"Confianca: {analysis['confidence'].capitalize()}",
        f"Resumo: {analysis['summary']}",
        "",
        "## Hotspots",
    ]

    hotspots = analysis.get("hotspots", [])[:top_n]
    if hotspots:
        for item in hotspots:
            examples = ", ".join(item.get("examples", [])[:4]) or "sem exemplos"
            lines.append(f"- {item['label']}: score {item['score']} ({examples})")
    else:
        lines.append("- Nenhum hotspot forte foi detectado no profile.")

    if short:
        return "\n".join(lines)

    lines.extend(["", "## Possiveis causas"])
    causes = analysis.get("suspected_causes", [])[: min(top_n, 8)]
    if causes:
        for item in causes:
            examples = ", ".join(item.get("examples", [])[:3]) or "sem exemplos"
            lines.append(f"- {item['label']}: {item['summary']} Evidencias: {examples}")
    else:
        lines.append("- O profile nao mostrou uma causa dominante por si so.")

    if analysis.get("threads"):
        lines.extend(["", "## Threads/nomes relevantes"])
        for thread_name in analysis["threads"][:8]:
            lines.append(f"- {thread_name}")

    if analysis.get("plugin_candidates"):
        lines.extend(["", "## Plugins/mods/classes suspeitas"])
        for candidate in analysis["plugin_candidates"][:10]:
            lines.append(f"- {candidate}")

    lines.extend(["", "## Recomendacoes diretas"])
    if causes:
        used = set()
        for item in causes:
            recommendation = item["recommendation"]
            if recommendation in used:
                continue
            used.add(recommendation)
            lines.append(f"- {recommendation}")
            if len(used) >= 5:
                break
    else:
        lines.append("- Cruce este profile com configs, logs e recursos atuais para aumentar a confianca do diagnostico.")

    return "\n".join(lines)
