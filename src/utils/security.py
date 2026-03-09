import re
from typing import List, Dict, Set, Tuple, Optional
from pathlib import Path

from src.config.settings import settings
from src.models import plugin


class SecurityError(Exception):
    pass


class ValidationError(Exception):
    pass


ALLOWED_EXTENSIONS = [".raw", ".dmp", ".mem", ".vmem", ".lime", ".img"]


_PLUGIN_INDEXES: Optional[Tuple[Set[str], Dict[str, str]]] = None
def _build_plugin_indexes() -> Tuple[Set[str], Dict[str, str]]:
    from src.mcp_server.resources.plugins import WINDOWS_PLUGINS, LINUX_PLUGINS, MAC_PLUGINS, GENERIC_PLUGINS, DEPRECATED_PLUGINS

    all_full: List[str] = []
    for d in (WINDOWS_PLUGINS, LINUX_PLUGINS, MAC_PLUGINS, GENERIC_PLUGINS):
        for v in d.values():
            for item in v:
                if isinstance(item, str):
                    all_full.append(item)
                elif isinstance(item, dict) and item.get("name"):
                    all_full.append(item["name"])

    canonical: Set[str] = set(all_full)

    short_counts: Dict[str, int] = {}
    short_to_full: Dict[str, str] = {}
    for full in canonical:
        short = ".".join(full.split(".")[:-1])
        short_counts[short] = short_counts.get(short, 0) + 1
        short_to_full[short] = full

    short_to_full_unique = {k: v for k, v in short_to_full.items() if short_counts.get(k, 0) == 1}

    deprecated_full = {k: v for k, v in DEPRECATED_PLUGINS.items()}
    canonical.update(deprecated_full.values())
    return canonical, short_to_full_unique

def _get_plugin_indexes() -> Tuple[Set[str], Dict[str, str]]:
    global _PLUGIN_INDEXES
    if _PLUGIN_INDEXES is None:
        _PLUGIN_INDEXES = _build_plugin_indexes()
    return _PLUGIN_INDEXES


def canonicalize_plugin_name(plugin: str) -> str:
    normalized = plugin.replace("-", ".").replace("_", ".")

    from src.mcp_server.resources.plugins import DEPRECATED_PLUGINS
    normalized = DEPRECATED_PLUGINS.get(normalized, normalized)

    canonical_plugins, short_to_full = _get_plugin_indexes()
    if normalized in canonical_plugins:
        return normalized

    mapped = short_to_full.get(normalized)
    if mapped:
        return mapped

    raise ValidationError(f"Invalid plugin name: {plugin}")
    canonicalize_plugin_name(plugin)
    return True


def validate_dump_path(dump_path: str) -> bool:
    try:
        path = Path(dump_path).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid path: {e}")
    
    allowed_dirs = settings.allowed_dump_dirs
    if allowed_dirs:
        is_allowed = any(
            str(path).startswith(str(Path(d).resolve()))
            for d in allowed_dirs
        ) or str(path).startswith("/app/data/dumps") or str(path).startswith("/data/dumps")
        if not is_allowed:
            raise SecurityError(f"Path outside allowed directories: {dump_path}")
    
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"Invalid file extension: {path.suffix}")
    
    if not path.exists():
        raise ValidationError(f"File not found: {dump_path}")
    
    max_size = settings.max_dump_size
    if path.stat().st_size > max_size:
        raise ValidationError(f"File exceeds maximum size: {path.stat().st_size} > {max_size}")
    
    return True

def validate_plugin_name(plugin: str) -> bool:
    canonicalize_plugin_name(plugin)
    return True