import json
import re
from collections import Counter, defaultdict

from spark_pb2 import (
    HealthData,
    HeapData,
    PlatformMetadata,
    SamplerData,
    SamplerMetadata,
)


SPARK_EXTENSIONS = {
    ".sparkprofile": "sparkprofile",
    ".sparkprofiler": "sparkprofile",
    ".sparkheap": "sparkheap",
    ".sparkhealth": "sparkhealth",
}

IDLE_PATTERNS = (
    "waitfornexttick",
    "thread.sleep",
    "unsafe.park",
    "locksupport.park",
    "managedblock",
    "parknanos",
    "park",
    "pthread_cond_wait",
    "awaitwork",
    "delayedworkqueue#take",
    "__poll",
    "epollwait",
    "epoll_pwait",
    "epoll_pwait2",
)

MAIN_THREAD_PATTERNS = (
    "server thread",
    "main",
)

CATEGORY_RULES = [
    {
        "category": "entity_ticking",
        "label": "Entity ticking",
        "patterns": [r"entity", r"tickentity", r"ticknonpassenger", r"mob", r"pathfind", r"goalselector"],
        "recommendation": "Reduza simulation-distance, investigue farms/mobcaps e verifique acumulacao de entidades.",
    },
    {
        "category": "block_entities",
        "label": "Block entities/hoppers",
        "patterns": [r"blockentity", r"tileentity", r"hopper", r"container", r"inventory", r"furnace", r"chest", r"stove"],
        "recommendation": "Ajuste hopper tick rate/checks e revise farms de hoppers, funis e storages automatizados.",
    },
    {
        "category": "chunk_loading",
        "label": "Chunks/chunk ticking",
        "patterns": [r"chunk", r"playerchunk", r"ticket", r"distancemanager", r"poi", r"regionfile"],
        "recommendation": "Reduza view-distance, investigue chunk loaders e revise exploracao intensa ou dimensoes extras.",
    },
    {
        "category": "worldgen",
        "label": "Worldgen",
        "patterns": [r"worldgen", r"noise", r"feature", r"biome", r"structure", r"chunkstatus", r"carver"],
        "recommendation": "Pre-gere o mapa com Chunky e revise mods/plugins de dimensao ou worldgen pesado.",
    },
    {
        "category": "networking",
        "label": "Networking/Netty",
        "patterns": [r"netty", r"packet", r"network", r"connection", r"chat"],
        "recommendation": "Revise trafego de rede, proxies, plugins de chat e picos de pacotes por jogador.",
    },
    {
        "category": "database_storage",
        "label": "Database/storage",
        "patterns": [r"coreprotect", r"sqlite", r"mysql", r"mariadb", r"hikari", r"jdbc", r"database", r"storage"],
        "recommendation": "Revise latencia de banco, uso de SQLite, pool de conexoes e writes sincronas.",
    },
    {
        "category": "map_rendering",
        "label": "Map rendering",
        "patterns": [r"dynmap", r"bluemap", r"render", r"tiles", r"journeymap", r"map"],
        "recommendation": "Pause fullrenders e limite threads/render intervals de Dynmap, BlueMap ou mods de mapa.",
    },
    {
        "category": "worldedit",
        "label": "WorldEdit/FAWE",
        "patterns": [r"worldedit", r"fawe", r"fastasyncworldedit", r"clipboard", r"extent"],
        "recommendation": "Revise operacoes massivas, filas pendentes e configuracoes async do WorldEdit/FAWE.",
    },
    {
        "category": "gc_memory",
        "label": "GC/memory",
        "patterns": [r"gc", r"garbagecollector", r"heap", r"allocation", r"outofmemory", r"g1", r"zgc", r"shenandoah"],
        "recommendation": "Revise Xms/Xmx, flags JVM, pressao de memoria e possiveis vazamentos de mods/plugins.",
    },
    {
        "category": "disk_io",
        "label": "Disk I/O",
        "patterns": [r"filechannel", r"\bnio\b", r"flush", r"save", r"write", r"read", r"regionfile", r"disk"],
        "recommendation": "Investigue backups, saves, plugins de storage e armazenamento lento no host.",
    },
    {
        "category": "event_bus",
        "label": "Event bus/mod events",
        "patterns": [r"event", r"forgeevent", r"bus", r"mixinextras", r"\$\$lambda", r"handler"],
        "recommendation": "Revise handlers de eventos muito frequentes e mods/plugins que interceptam tick, damage, block ou chat.",
    },
    {
        "category": "scheduler",
        "label": "Scheduler/async tasks",
        "patterns": [r"scheduler", r"task", r"executor", r"forkjoin", r"pool"],
        "recommendation": "Revise tarefas agendadas, jobs async e pools de workers com consumo excessivo.",
    },
]

HEURISTIC_NOTES = [
    "Parser estruturado Protobuf falhou; usando analise heuristica por strings.",
    "Perfis binarios do Spark sem parse estruturado ficam com menor confianca.",
]


def detect_spark_type(path: str) -> str | None:
    lowered = path.lower()
    for ext, kind in SPARK_EXTENSIONS.items():
        if lowered.endswith(ext):
            return kind
    return None


def _enum_name(enum_cls, value: int, default: str = "UNKNOWN") -> str:
    try:
        return enum_cls.Name(value)
    except ValueError:
        return default


def _safe_ratio(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return numerator / denominator


def _format_duration_ms(value: int | float | None) -> str:
    if not value:
        return "desconhecida"
    seconds = float(value) / 1000.0
    if seconds >= 60:
        return f"{seconds / 60.0:.1f} min"
    return f"{seconds:.1f} s"


def _normalize_text(value: str) -> str:
    return value.replace("/", ".").strip()


def _signature_for(class_name: str, method_name: str, line_number: int = 0) -> str:
    class_name = _normalize_text(class_name) or "<unknown>"
    method_name = method_name or "<unknown>"
    if line_number:
        return f"{class_name}#{method_name}:{line_number}"
    return f"{class_name}#{method_name}"


def _is_idle_signature(signature: str) -> bool:
    lowered = signature.lower()
    return any(pattern in lowered for pattern in IDLE_PATTERNS)


def _is_main_thread_name(name: str) -> bool:
    return _main_thread_priority(name) >= 70


def _main_thread_priority(name: str) -> int:
    lowered = name.strip().lower()
    if lowered == "server thread":
        return 100
    if lowered == "main":
        return 90
    if "server thread" in lowered:
        return 80
    if lowered.startswith("main "):
        return 70
    if "worker-main" in lowered:
        return 10
    return 0


def _parse_embedded_config_value(name: str, raw_value: str):
    text = raw_value.strip()
    if not text:
        return raw_value
    if name.endswith("server.properties"):
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass
    if text.startswith("{") or text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return raw_value
    return raw_value


def _build_prefix_source_index(class_sources: dict[str, str]) -> dict[str, str]:
    counters = defaultdict(Counter)
    for class_name, source_id in class_sources.items():
        parts = class_name.split(".")
        if len(parts) < 2:
            continue
        package_parts = parts[:-1]
        for length in range(2, min(5, len(package_parts)) + 1):
            prefix = ".".join(package_parts[:length])
            counters[prefix][source_id] += 1

    index = {}
    for prefix, counter in counters.items():
        source_id, _ = counter.most_common(1)[0]
        index[prefix] = source_id
    return index


def _resolve_source_id(class_name: str, class_sources: dict[str, str], prefix_index: dict[str, str]) -> str:
    if class_name in class_sources:
        return class_sources[class_name]
    parts = class_name.split(".")
    for length in range(min(5, len(parts) - 1), 1, -1):
        prefix = ".".join(parts[:length])
        if prefix in prefix_index:
            return prefix_index[prefix]

    lowered = class_name.lower()
    if lowered.startswith("net.minecraft"):
        return "minecraft"
    if lowered.startswith("net.minecraftforge"):
        return "forge"
    if lowered.startswith(("org.bukkit", "io.papermc", "com.destroystokyo")):
        return "paper"
    if lowered.startswith(("java.", "jdk.", "sun.", "javax.")):
        return "java"
    if "." in class_name:
        return ".".join(class_name.split(".")[:2]).lower()
    return "unknown"


def _source_label(source_id: str, sources: dict) -> str:
    metadata = sources.get(source_id)
    if metadata:
        return metadata.get("name") or source_id
    return source_id


def _category_for(signature: str, source_label: str) -> str | None:
    text = f"{signature} {source_label}".lower()
    if _is_idle_signature(signature):
        return "idle_wait"
    for rule in CATEGORY_RULES:
        if any(re.search(pattern, text) for pattern in rule["patterns"]):
            return rule["category"]
    return None


def _category_label(category: str) -> str:
    if category == "idle_wait":
        return "Tempo ocioso / espera pelo proximo tick"
    for rule in CATEGORY_RULES:
        if rule["category"] == category:
            return rule["label"]
    return category


def _category_recommendation(category: str) -> str | None:
    for rule in CATEGORY_RULES:
        if rule["category"] == category:
            return rule["recommendation"]
    return None


def _calc_node_time(node) -> float:
    if getattr(node, "time", 0.0):
        return float(node.time)
    if getattr(node, "times", None):
        return float(sum(node.times))
    return 0.0


def _iter_thread_roots(thread):
    if thread.childrenRefs:
        for ref in thread.childrenRefs:
            if 0 <= ref < len(thread.children):
                yield ("pool", int(ref)), thread.children[ref]
    else:
        for idx, child in enumerate(thread.children):
            yield ("direct", idx), child


def _iter_child_nodes(thread_pool, node, path_key):
    if node.childrenRefs and thread_pool is not None:
        for ref in node.childrenRefs:
            if 0 <= ref < len(thread_pool):
                yield ("pool", int(ref)), thread_pool[ref]
    else:
        for idx, child in enumerate(node.children):
            yield (path_key, idx), child


def _traverse_thread(thread, class_sources: dict[str, str], prefix_index: dict[str, str], sources: dict, max_depth: int, max_nodes: int):
    thread_total = _calc_node_time(thread)
    if thread_total <= 0 and getattr(thread, "times", None):
        thread_total = float(sum(thread.times))

    is_main = _is_main_thread_name(thread.name)
    thread_pool = list(thread.children)
    node_records = []
    visited = set()
    state = {"count": 0}

    def walk(node, depth: int, key):
        if depth > max_depth or state["count"] >= max_nodes:
            return 0.0

        key_tuple = tuple(key) if isinstance(key, tuple) else key
        if key_tuple in visited:
            return 0.0
        visited.add(key_tuple)
        state["count"] += 1

        child_refs = list(_iter_child_nodes(thread_pool, node, key_tuple))
        child_total = 0.0
        for child_key, child in child_refs:
            child_total += walk(child, depth + 1, child_key if isinstance(child_key, tuple) else (child_key,))

        inclusive = _calc_node_time(node)
        if inclusive <= 0 and child_total > 0:
            inclusive = child_total
        self_time = inclusive - child_total
        if self_time < 0:
            self_time = 0.0

        class_name = _normalize_text(getattr(node, "className", ""))
        method_name = getattr(node, "methodName", "")
        line_number = getattr(node, "lineNumber", 0)
        signature = _signature_for(class_name, method_name, line_number)
        source_id = _resolve_source_id(class_name, class_sources, prefix_index)
        source_name = _source_label(source_id, sources)
        category = _category_for(signature, source_name)
        idle = category == "idle_wait"

        node_records.append(
            {
                "thread_name": thread.name,
                "main_thread": is_main,
                "depth": depth,
                "signature": signature,
                "class_name": class_name,
                "method_name": method_name or "<unknown>",
                "source_id": source_id,
                "source_name": source_name,
                "inclusive_time": inclusive,
                "self_time": self_time,
                "idle": idle,
                "category": category,
            }
        )
        return inclusive

    for root_key, root in _iter_thread_roots(thread):
        if state["count"] >= max_nodes:
            break
        walk(root, 1, root_key if isinstance(root_key, tuple) else (root_key,))

    if thread_total <= 0:
        thread_total = sum(record["inclusive_time"] for record in node_records if record["depth"] == 1)

    idle_time = sum(record["inclusive_time"] for record in node_records if record["idle"])
    return {
        "name": thread.name,
        "total_time": thread_total,
        "idle_time": idle_time,
        "main_thread": is_main,
        "nodes": node_records,
    }


def _aggregate_nodes(node_records: list[dict], main_thread_only: bool | None = None, thread_name: str | None = None):
    by_signature = defaultdict(lambda: {"inclusive_time": 0.0, "self_time": 0.0, "source_name": "", "category": None, "main_hits": 0})
    by_source = defaultdict(lambda: {"inclusive_time": 0.0, "self_time": 0.0, "category_hits": Counter()})
    by_category = defaultdict(float)

    for record in node_records:
        if main_thread_only is not None and record["main_thread"] != main_thread_only:
            continue
        if thread_name is not None and record["thread_name"] != thread_name:
            continue
        if record["idle"]:
            continue

        signature = record["signature"]
        by_signature[signature]["inclusive_time"] += record["inclusive_time"]
        by_signature[signature]["self_time"] += record["self_time"]
        by_signature[signature]["source_name"] = record["source_name"]
        by_signature[signature]["category"] = record["category"]
        if record["main_thread"]:
            by_signature[signature]["main_hits"] += 1

        source_name = record["source_name"]
        by_source[source_name]["inclusive_time"] += record["inclusive_time"]
        by_source[source_name]["self_time"] += record["self_time"]
        if record["category"]:
            by_source[source_name]["category_hits"][record["category"]] += 1
            by_category[record["category"]] += record["inclusive_time"]

    return by_signature, by_source, by_category


def _sort_dict_entries(mapping: dict, key_name: str, top_n: int):
    items = []
    for name, payload in mapping.items():
        item = {"name": name}
        item.update(payload)
        items.append(item)
    items.sort(key=lambda item: item.get(key_name, 0.0), reverse=True)
    return items[:top_n]


def _summarize_window_statistics(time_window_statistics: dict, top_n: int):
    if not time_window_statistics:
        return {
            "worst_mspt": [],
            "worst_tps": [],
            "entity_peaks": [],
            "summary": [],
        }

    windows = []
    for key, stats in time_window_statistics.items():
        windows.append(
            {
                "window_id": int(key),
                "ticks": int(stats.ticks),
                "cpu_process": float(stats.cpuProcess),
                "cpu_system": float(stats.cpuSystem),
                "tps": float(stats.tps),
                "mspt_median": float(stats.msptMedian),
                "mspt_max": float(stats.msptMax),
                "players": int(stats.players),
                "entities": int(stats.entities),
                "tile_entities": int(stats.tileEntities),
                "chunks": int(stats.chunks),
                "start_time": int(stats.startTime),
                "end_time": int(stats.endTime),
                "duration": int(stats.duration),
            }
        )

    worst_mspt = sorted(windows, key=lambda item: item["mspt_max"], reverse=True)[:top_n]
    worst_tps = sorted(windows, key=lambda item: item["tps"])[:top_n]
    entity_peaks = sorted(windows, key=lambda item: (item["entities"], item["tile_entities"], item["chunks"]), reverse=True)[:top_n]

    avg_players = sum(item["players"] for item in windows) / len(windows)
    avg_entities = sum(item["entities"] for item in windows) / len(windows)
    avg_chunks = sum(item["chunks"] for item in windows) / len(windows)
    summary = [
        f"Janelas: {len(windows)}",
        f"Players medio: {avg_players:.1f}",
        f"Entities medio: {avg_entities:.1f}",
        f"Chunks medio: {avg_chunks:.1f}",
    ]

    return {
        "worst_mspt": worst_mspt,
        "worst_tps": worst_tps,
        "entity_peaks": entity_peaks,
        "summary": summary,
    }


def _parse_sources_map(sources_map) -> dict:
    parsed = {}
    for source_id, metadata in sources_map.items():
        parsed[source_id] = {
            "id": source_id,
            "name": metadata.name,
            "version": metadata.version,
            "author": metadata.author,
            "description": metadata.description,
            "built_in": metadata.builtIn,
        }
    return parsed


def _extract_platform_metadata(platform) -> dict:
    return {
        "type": _enum_name(PlatformMetadata.Type, platform.type),
        "name": platform.name,
        "version": platform.version,
        "minecraft_version": platform.minecraftVersion,
        "spark_version": str(platform.sparkVersion) if platform.sparkVersion else "",
        "brand": platform.brand,
    }


def _extract_platform_statistics(platform_statistics) -> dict:
    stats = {
        "tps_1m": float(platform_statistics.tps.last1m),
        "tps_5m": float(platform_statistics.tps.last5m),
        "tps_15m": float(platform_statistics.tps.last15m),
        "mspt_1m": {
            "mean": float(platform_statistics.mspt.last1m.mean),
            "max": float(platform_statistics.mspt.last1m.max),
            "min": float(platform_statistics.mspt.last1m.min),
            "median": float(platform_statistics.mspt.last1m.median),
            "p95": float(platform_statistics.mspt.last1m.percentile95),
        },
        "mspt_5m": {
            "mean": float(platform_statistics.mspt.last5m.mean),
            "max": float(platform_statistics.mspt.last5m.max),
            "min": float(platform_statistics.mspt.last5m.min),
            "median": float(platform_statistics.mspt.last5m.median),
            "p95": float(platform_statistics.mspt.last5m.percentile95),
        },
        "player_count": int(platform_statistics.playerCount),
        "heap_used": int(platform_statistics.memory.heap.used),
        "heap_committed": int(platform_statistics.memory.heap.committed),
        "heap_max": int(platform_statistics.memory.heap.max),
        "non_heap_used": int(platform_statistics.memory.nonHeap.used),
        "world_total_entities": int(platform_statistics.world.totalEntities),
        "world_count": len(platform_statistics.world.worlds),
        "datapack_count": len(platform_statistics.world.dataPacks),
    }
    return stats


def _extract_system_statistics(system_statistics) -> dict:
    return {
        "cpu_threads": int(system_statistics.cpu.threads),
        "cpu_process_1m": float(system_statistics.cpu.processUsage.last1m),
        "cpu_process_15m": float(system_statistics.cpu.processUsage.last15m),
        "cpu_system_1m": float(system_statistics.cpu.systemUsage.last1m),
        "cpu_system_15m": float(system_statistics.cpu.systemUsage.last15m),
        "cpu_model": system_statistics.cpu.modelName,
        "memory_physical_used": int(system_statistics.memory.physical.used),
        "memory_physical_total": int(system_statistics.memory.physical.total),
        "memory_swap_used": int(system_statistics.memory.swap.used),
        "memory_swap_total": int(system_statistics.memory.swap.total),
        "disk_used": int(system_statistics.disk.used),
        "disk_total": int(system_statistics.disk.total),
        "os_name": system_statistics.os.name,
        "os_version": system_statistics.os.version,
        "os_arch": system_statistics.os.arch,
        "java_vendor": system_statistics.java.vendor,
        "java_version": system_statistics.java.version,
        "java_vendor_version": system_statistics.java.vendorVersion,
        "jvm_args": system_statistics.java.vmArgs,
        "jvm_name": system_statistics.jvm.name,
        "jvm_vendor": system_statistics.jvm.vendor,
        "jvm_version": system_statistics.jvm.version,
        "uptime": int(system_statistics.uptime),
        "network_interfaces": list(system_statistics.net.keys()),
    }


def _extract_embedded_configs(server_configurations: dict) -> tuple[dict, dict]:
    raw = {}
    parsed = {}
    for name, value in server_configurations.items():
        raw[name] = value
        parsed[name] = _parse_embedded_config_value(name, value)
    return raw, parsed


def _build_structured_sampler_analysis(file_path: str, data: bytes, top_n: int, max_depth: int) -> dict:
    message = SamplerData()
    message.ParseFromString(data)

    sources = _parse_sources_map(message.metadata.sources)
    class_sources = {key: value for key, value in message.classSources.items()}
    prefix_index = _build_prefix_source_index(class_sources)
    raw_embedded_configs, parsed_embedded_configs = _extract_embedded_configs(message.metadata.serverConfigurations)

    threads = []
    all_nodes = []
    max_nodes = max(5000, top_n * 400)
    for thread in message.threads:
        thread_summary = _traverse_thread(thread, class_sources, prefix_index, sources, max_depth=max_depth, max_nodes=max_nodes)
        threads.append(thread_summary)
        all_nodes.extend(thread_summary["nodes"])

    threads.sort(key=lambda item: item["total_time"], reverse=True)
    main_threads = [thread for thread in threads if thread["main_thread"]]
    if not main_threads:
        main_threads = [thread for thread in threads if _main_thread_priority(thread["name"]) > 0]
    main_threads.sort(key=lambda item: (_main_thread_priority(item["name"]), item["total_time"]), reverse=True)
    main_thread = main_threads[0] if main_threads else None

    by_signature, by_source, by_category = _aggregate_nodes(all_nodes, main_thread_only=None)
    main_signature, _, main_category = _aggregate_nodes(
        all_nodes,
        main_thread_only=None,
        thread_name=main_thread["name"] if main_thread else None,
    )

    hotspots_total = _sort_dict_entries(by_signature, "inclusive_time", top_n)
    hotspots_self = _sort_dict_entries(by_signature, "self_time", top_n)
    main_hotspots = _sort_dict_entries(main_signature, "inclusive_time", top_n)
    source_total = _sort_dict_entries(by_source, "inclusive_time", top_n)
    source_self = _sort_dict_entries(by_source, "self_time", top_n)
    category_scores_primary = main_category or by_category
    category_rank = sorted(
        [{"category": key, "label": _category_label(key), "inclusive_time": value} for key, value in category_scores_primary.items()],
        key=lambda item: item["inclusive_time"],
        reverse=True,
    )

    window_summary = _summarize_window_statistics(message.timeWindowStatistics, top_n=min(top_n, 3))

    idle_ratio = 0.0
    if main_thread and main_thread["total_time"] > 0:
        idle_ratio = min(1.0, _safe_ratio(main_thread["idle_time"], main_thread["total_time"]))

    confidence = "media"
    if category_rank:
        confidence = "alta"
    if idle_ratio > 0.50 and message.metadata.platformStatistics.mspt.last1m.mean < 55:
        confidence = "alta"
    elif not category_rank:
        confidence = "baixa"

    suspected_causes = []
    for item in category_rank[:6]:
        suspected_causes.append(
            {
                "category": item["category"],
                "label": item["label"],
                "score": item["inclusive_time"],
                "summary": f"Tempo agregado relevante em {item['label'].lower()}.",
                "recommendation": _category_recommendation(item["category"]) or "Investigue esse grupo no profile e nas configs atuais.",
                "examples": [entry["name"] for entry in hotspots_total if entry.get("category") == item["category"]][:4],
            }
        )

    metadata = {
        "file": file_path,
        "spark_type": "sparkprofile",
        "parser": "protobuf-structured",
        "size_bytes": len(data),
        "duration_ms": int(message.metadata.endTime - message.metadata.startTime) if message.metadata.endTime and message.metadata.startTime else 0,
        "interval": int(message.metadata.interval),
        "number_of_ticks": int(message.metadata.numberOfTicks),
        "sampler_mode": _enum_name(SamplerMetadata.SamplerMode, message.metadata.samplerMode),
        "sampler_engine": _enum_name(SamplerMetadata.SamplerEngine, message.metadata.samplerEngine),
        "thread_dumper": _enum_name(SamplerMetadata.ThreadDumper.Type, message.metadata.threadDumper.type),
        "data_aggregator": _enum_name(SamplerMetadata.DataAggregator.Type, message.metadata.dataAggregator.type),
        "thread_grouper": _enum_name(SamplerMetadata.DataAggregator.ThreadGrouper, message.metadata.dataAggregator.threadGrouper),
    }

    summary = (
        f"Profile Spark parseado via Protobuf estruturado. "
        f"{len(message.threads)} threads, {len(class_sources)} classSources, "
        f"{len(sources)} sources e {len(message.timeWindowStatistics)} janelas."
    )

    return {
        "metadata": metadata,
        "summary": summary,
        "confidence": confidence,
        "structured": True,
        "notes": ["Parser Protobuf estruturado usado com schema oficial do spark-viewer."],
        "command_sender": {
            "type": int(message.metadata.user.type),
            "name": message.metadata.user.name,
            "unique_id": message.metadata.user.uniqueId,
        },
        "platform": _extract_platform_metadata(message.metadata.platform),
        "platform_statistics": _extract_platform_statistics(message.metadata.platformStatistics),
        "system_statistics": _extract_system_statistics(message.metadata.systemStatistics),
        "embedded_configs_raw": raw_embedded_configs,
        "embedded_configs": parsed_embedded_configs,
        "server_properties_embedded": parsed_embedded_configs.get("server.properties", {}),
        "sources": sources,
        "source_count": len(sources),
        "class_source_count": len(class_sources),
        "threads": threads,
        "top_threads": threads[:top_n],
        "main_thread": main_thread,
        "hotspots_total": hotspots_total,
        "hotspots_self": hotspots_self,
        "main_thread_hotspots": main_hotspots,
        "sources_total": source_total,
        "sources_self": source_self,
        "category_scores": {item["category"]: item["inclusive_time"] for item in category_rank},
        "global_category_scores": dict(by_category),
        "category_rank": category_rank,
        "window_statistics": window_summary,
        "suspected_causes": suspected_causes,
        "extra_platform_metadata": {key: value for key, value in message.metadata.extraPlatformMetadata.items()},
    }


def _build_structured_heap_or_health_analysis(file_path: str, data: bytes, spark_type: str) -> dict:
    if spark_type == "sparkheap":
        parsed = HeapData()
        parsed.ParseFromString(data)
        metadata = parsed.metadata
        entries = sorted(parsed.entries, key=lambda entry: entry.size, reverse=True)[:15]
        summary = f"Heap summary Spark parseado via Protobuf estruturado com {len(parsed.entries)} entradas."
        return {
            "metadata": {
                "file": file_path,
                "spark_type": spark_type,
                "parser": "protobuf-structured",
                "size_bytes": len(data),
            },
            "summary": summary,
            "confidence": "media",
            "structured": True,
            "notes": [
                "Suporte estruturado completo nesta tarefa foca principalmente em SamplerData (.sparkprofile).",
                "Para .sparkheap, apenas metadata e top classes de heap foram resumidas.",
            ],
            "platform": _extract_platform_metadata(metadata.platform),
            "platform_statistics": _extract_platform_statistics(metadata.platformStatistics),
            "system_statistics": _extract_system_statistics(metadata.systemStatistics),
            "embedded_configs_raw": dict(metadata.serverConfigurations),
            "embedded_configs": {key: _parse_embedded_config_value(key, value) for key, value in metadata.serverConfigurations.items()},
            "heap_entries": [
                {"type": entry.type, "instances": int(entry.instances), "size": int(entry.size)}
                for entry in entries
            ],
            "hotspots_total": [{"name": entry.type, "inclusive_time": float(entry.size), "self_time": float(entry.size), "source_name": "heap"} for entry in entries[:10]],
            "hotspots_self": [{"name": entry.type, "inclusive_time": float(entry.size), "self_time": float(entry.size), "source_name": "heap"} for entry in entries[:10]],
            "main_thread": None,
            "top_threads": [],
            "sources_total": [],
            "sources_self": [],
            "category_scores": {},
            "suspected_causes": [],
            "window_statistics": {"worst_mspt": [], "worst_tps": [], "entity_peaks": [], "summary": []},
        }

    parsed = HealthData()
    parsed.ParseFromString(data)
    metadata = parsed.metadata
    window_summary = _summarize_window_statistics(parsed.timeWindowStatistics, top_n=3)
    summary = f"Health report Spark parseado via Protobuf estruturado com {len(parsed.timeWindowStatistics)} janelas."
    return {
        "metadata": {
            "file": file_path,
            "spark_type": spark_type,
            "parser": "protobuf-structured",
            "size_bytes": len(data),
        },
        "summary": summary,
        "confidence": "media",
        "structured": True,
        "notes": [
            "Suporte estruturado completo nesta tarefa foca principalmente em SamplerData (.sparkprofile).",
            "Para .sparkhealth, metadata e janelas de health foram resumidas.",
        ],
        "platform": _extract_platform_metadata(metadata.platform),
        "platform_statistics": _extract_platform_statistics(metadata.platformStatistics),
        "system_statistics": _extract_system_statistics(metadata.systemStatistics),
        "embedded_configs_raw": dict(metadata.serverConfigurations),
        "embedded_configs": {key: _parse_embedded_config_value(key, value) for key, value in metadata.serverConfigurations.items()},
        "hotspots_total": [],
        "hotspots_self": [],
        "main_thread": None,
        "top_threads": [],
        "sources_total": [],
        "sources_self": [],
        "category_scores": {},
        "suspected_causes": [],
        "window_statistics": window_summary,
    }


def parse_spark_profile_structured(file_path: str, data: bytes, top_n: int = 25, max_depth: int = 12) -> dict:
    spark_type = detect_spark_type(file_path)
    if spark_type in {"sparkprofile"}:
        return _build_structured_sampler_analysis(file_path, data, top_n=top_n, max_depth=max_depth)
    if spark_type in {"sparkheap", "sparkhealth"}:
        return _build_structured_heap_or_health_analysis(file_path, data, spark_type=spark_type)
    raise ValueError(f"Tipo Spark nao suportado para parser estruturado: {spark_type}")


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

    for rule in CATEGORY_RULES:
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
                "summary": f"Muitas strings combinam com {rule['label'].lower()}.",
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


def _analyze_spark_bytes_heuristic(file_path: str, data: bytes, top_n: int = 25, max_depth: int = 12) -> dict:
    spark_type = detect_spark_type(file_path) or "desconhecido"
    decoded_text = guess_encoding_text(data)
    tokens = extract_text_tokens(data)
    category_scores, hotspots, causes = _score_rules(tokens)
    plugin_candidates = _extract_plugin_candidates(tokens, top_n)

    metadata = {
        "file": file_path,
        "spark_type": spark_type,
        "parser": "heuristic-fallback",
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
        "structured": False,
        "threads": [{"name": name, "total_time": 0.0, "idle_time": 0.0, "main_thread": _is_main_thread_name(name)} for name in threads],
        "top_threads": [{"name": name, "total_time": 0.0, "idle_time": 0.0, "main_thread": _is_main_thread_name(name)} for name in threads],
        "main_thread": None,
        "hotspots_total": [{"name": item["label"], "inclusive_time": float(item["score"]), "self_time": float(item["score"]), "source_name": "heuristic"} for item in hotspots[:top_n]],
        "hotspots_self": [{"name": item["label"], "inclusive_time": float(item["score"]), "self_time": float(item["score"]), "source_name": "heuristic"} for item in hotspots[:top_n]],
        "main_thread_hotspots": [],
        "sources_total": [{"name": name, "inclusive_time": 0.0, "self_time": 0.0} for name in plugin_candidates[:top_n]],
        "sources_self": [{"name": name, "inclusive_time": 0.0, "self_time": 0.0} for name in plugin_candidates[:top_n]],
        "suspected_causes": causes[:top_n],
        "plugin_candidates": plugin_candidates,
        "top_tokens": [{"token": token, "count": count} for token, count in raw_top_tokens],
        "category_scores": category_scores,
        "window_statistics": {"worst_mspt": [], "worst_tps": [], "entity_peaks": [], "summary": []},
        "embedded_configs_raw": {},
        "embedded_configs": {},
        "server_properties_embedded": {},
        "platform": {},
        "platform_statistics": {},
        "system_statistics": {},
        "source_count": 0,
        "class_source_count": 0,
        "notes": list(HEURISTIC_NOTES),
    }


def analyze_spark_bytes(file_path: str, data: bytes, top_n: int = 25, max_depth: int = 12) -> dict:
    try:
        analysis = parse_spark_profile_structured(file_path, data, top_n=top_n, max_depth=max_depth)
        return analysis
    except Exception as exc:
        analysis = _analyze_spark_bytes_heuristic(file_path, data, top_n=top_n, max_depth=max_depth)
        analysis["notes"].insert(0, f"Parser estruturado Protobuf falhou; usando analise heuristica por strings. Motivo: {exc}")
        return analysis


def _format_hotspot_line(item: dict) -> str:
    inclusive = item.get("inclusive_time", 0.0)
    self_time = item.get("self_time", 0.0)
    source_name = item.get("source_name") or "desconhecido"
    return f"- {item['name']} [{source_name}] total={inclusive:.1f} self={self_time:.1f}"


def format_profile_analysis(analysis: dict, short: bool = False, top_n: int = 15) -> str:
    metadata = analysis.get("metadata", {})
    parser_name = "Protobuf estruturado" if analysis.get("structured") else "Fallback heuristico"
    lines = [
        "AVISO: Este relatorio usa dados do servidor e nomes de classes/mods/plugins como entrada nao confiavel.",
        "",
        "# Analise Spark",
        "",
        "## Resumo",
        f"- Arquivo: {metadata.get('file', '?')}",
        f"- Tipo: {metadata.get('spark_type', '?')}",
        f"- Parser: {parser_name}",
    ]

    platform = analysis.get("platform", {})
    platform_stats = analysis.get("platform_statistics", {})
    system_stats = analysis.get("system_statistics", {})
    main_thread = analysis.get("main_thread")

    if analysis.get("structured"):
        lines.extend(
            [
                f"- Perfil gerado por: {analysis.get('command_sender', {}).get('name', 'desconhecido')}",
                f"- Plataforma: {platform.get('type', '?')} {platform.get('name', '')} {platform.get('version', '')}".strip(),
                f"- Minecraft: {platform.get('minecraft_version', '') or 'desconhecido'}",
                f"- Brand: {platform.get('brand', '') or 'desconhecido'}",
                f"- Spark: {platform.get('spark_version', '') or 'desconhecido'}",
                f"- Engine: {metadata.get('sampler_engine', 'UNKNOWN')}",
                f"- Modo: {metadata.get('sampler_mode', 'UNKNOWN')}",
                f"- Duração: {_format_duration_ms(metadata.get('duration_ms'))}",
                f"- Intervalo: {metadata.get('interval', 0)}",
                f"- Ticks: {metadata.get('number_of_ticks', 0)}",
                f"- Players: {platform_stats.get('player_count', 'desconhecido')}",
                f"- TPS: {platform_stats.get('tps_1m', 0):.2f} / {platform_stats.get('tps_5m', 0):.2f} / {platform_stats.get('tps_15m', 0):.2f}",
                f"- MSPT: mean {platform_stats.get('mspt_1m', {}).get('mean', 0):.2f}, median {platform_stats.get('mspt_1m', {}).get('median', 0):.2f}, p95 {platform_stats.get('mspt_1m', {}).get('p95', 0):.2f}, max {platform_stats.get('mspt_1m', {}).get('max', 0):.2f}",
            ]
        )

    lines.extend(["", "## Leitura rapida"])
    if analysis.get("suspected_causes"):
        top_cause = analysis["suspected_causes"][0]
        lines.append(f"Causa provavel: {top_cause['label']}")
    else:
        lines.append("Causa provavel: ainda inconclusiva")
    lines.append(f"Confianca: {analysis.get('confidence', 'baixa').capitalize()}")

    if main_thread:
        idle_time = main_thread.get("idle_time", 0.0)
        total_time = main_thread.get("total_time", 0.0)
        idle_ratio = min(1.0, _safe_ratio(idle_time, total_time)) * 100.0
        lines.extend(
            [
                "",
                "## Server thread",
                f"- Nome: {main_thread.get('name')}",
                f"- Tempo total agregado: {total_time:.1f}",
                f"- Tempo ocioso / espera pelo proximo tick: {idle_time:.1f} ({idle_ratio:.1f}%)",
            ]
        )
        if idle_ratio > 40:
            lines.append("- Observacao: muito tempo da main thread parece ocioso; o servidor pode ter estado saudavel durante parte relevante do profile.")
        else:
            lines.append("- Observacao: a main thread ficou relativamente ocupada; isso combina com lag de tick/MSPT.")

        hotspots = analysis.get("main_thread_hotspots", [])[: min(top_n, 8)]
        if hotspots:
            lines.append("- Hotspots principais:")
            for item in hotspots:
                lines.append(f"  {_format_hotspot_line(item)}")
    elif analysis.get("structured"):
        lines.extend(["", "## Server thread", "- Nenhuma main thread clara foi detectada; o profile pode ser majoritariamente async ou agrupado de forma diferente."])

    lines.extend(["", "## Threads mais pesadas"])
    top_threads = analysis.get("top_threads", [])[: min(top_n, 10)]
    if top_threads:
        for item in top_threads:
            idle_ratio = min(1.0, _safe_ratio(item.get("idle_time", 0.0), item.get("total_time", 0.0))) * 100.0
            marker = " main" if item.get("main_thread") else ""
            lines.append(f"- {item['name']}{marker}: total={item.get('total_time', 0.0):.1f}, idle={idle_ratio:.1f}%")
    else:
        lines.append("- Nenhuma thread relevante foi listada.")

    lines.extend(["", "## Hotspots por total time"])
    hotspots_total = analysis.get("hotspots_total", [])[:top_n]
    if hotspots_total:
        for item in hotspots_total:
            lines.append(_format_hotspot_line(item))
    else:
        lines.append("- Sem hotspots fortes.")

    lines.extend(["", "## Hotspots por self time"])
    hotspots_self = analysis.get("hotspots_self", [])[:top_n]
    if hotspots_self:
        for item in hotspots_self:
            lines.append(_format_hotspot_line(item))
    else:
        lines.append("- Sem hotspots fortes.")

    lines.extend(["", "## Mods/plugins mais presentes"])
    source_total = analysis.get("sources_total", [])[: min(top_n, 10)]
    if source_total:
        for item in source_total:
            lines.append(f"- {item['name']}: total={item.get('inclusive_time', 0.0):.1f}, self={item.get('self_time', 0.0):.1f}")
    else:
        lines.append("- Sem mapeamento forte de sources.")

    if short:
        return "\n".join(lines)

    if analysis.get("structured"):
        lines.extend(["", "## Configs embutidas no profile"])
        embedded_server_properties = analysis.get("server_properties_embedded", {})
        if isinstance(embedded_server_properties, dict) and embedded_server_properties:
            for key in ("view-distance", "simulation-distance", "max-players", "sync-chunk-writes", "max-tick-time"):
                if key in embedded_server_properties:
                    lines.append(f"- {key}: {embedded_server_properties[key]}")
        else:
            lines.append("- server.properties embutido nao foi encontrado ou nao estava parseavel.")

        window_stats = analysis.get("window_statistics", {})
        lines.extend(["", "## Piores janelas"])
        for item in window_stats.get("worst_mspt", [])[:3]:
            lines.append(
                f"- MSPT max {item['mspt_max']:.2f}, TPS {item['tps']:.2f}, players {item['players']}, entities {item['entities']}, chunks {item['chunks']}, duracao {item['duration']} ms"
            )
        if not window_stats.get("worst_mspt"):
            lines.append("- Sem janelas estruturadas disponiveis.")

        if system_stats:
            lines.extend(["", "## Sistema/JVM"])
            lines.append(f"- CPU: {system_stats.get('cpu_model', 'desconhecido')}")
            lines.append(f"- CPU process 1m: {system_stats.get('cpu_process_1m', 0):.3f}")
            lines.append(f"- Java: {system_stats.get('java_vendor', '')} {system_stats.get('java_version', '')}".strip())
            if system_stats.get("jvm_args"):
                lines.append(f"- JVM args: {system_stats['jvm_args'][:220]}")

    lines.extend(["", "## Recomendações"])
    if analysis.get("suspected_causes"):
        used = set()
        for cause in analysis["suspected_causes"]:
            recommendation = cause.get("recommendation")
            if not recommendation or recommendation in used:
                continue
            used.add(recommendation)
            lines.append(f"- {recommendation}")
            if len(used) >= 6:
                break
    else:
        lines.append("- Cruce este profile com configs atuais, logs e recursos para aumentar a confianca do diagnostico.")

    if analysis.get("notes"):
        lines.extend(["", "## Notas"])
        for note in analysis["notes"]:
            lines.append(f"- {note}")

    return "\n".join(lines)
