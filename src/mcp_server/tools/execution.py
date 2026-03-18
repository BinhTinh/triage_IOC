import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid
from typing import Optional

from fastmcp import FastMCP, Context

from src.core.volatility_executor import VolatilityExecutor
from src.config.settings import settings
from src.utils.security import validate_dump_path, validate_plugin_name, canonicalize_plugin_name
from src.mcp_server.resources.plugins import WINDOWS_PLUGINS, LINUX_PLUGINS
from src.mcp_server.tools.reporting import write_json_report
from src.mcp_server.tools.triage import get_cached_os_profile

executor = VolatilityExecutor()


# In-process result store for large run_plugins payloads.
# This avoids forcing huge JSON blobs across the MCP boundary.
_RESULT_STORE: dict[str, dict] = {}
_MAX_STORED_RESULTS = 50
_RESULT_STORE_PATH = Path(settings.reports_dir) / "run_results_store.json"


def _load_result_store_from_disk() -> None:
    if not _RESULT_STORE_PATH.exists():
        return
    try:
        with _RESULT_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _RESULT_STORE.clear()
            _RESULT_STORE.update(data)
    except Exception:
        # Keep in-memory empty on corruption; fresh writes will heal the file.
        pass


def _save_result_store_to_disk() -> None:
    _RESULT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _RESULT_STORE_PATH.open("w", encoding="utf-8") as f:
        json.dump(_RESULT_STORE, f, ensure_ascii=True, indent=2)


def _prune_result_store() -> None:
    if len(_RESULT_STORE) <= _MAX_STORED_RESULTS:
        return
    ordered = sorted(
        _RESULT_STORE.items(),
        key=lambda kv: kv[1].get("stored_at", ""),
    )
    to_remove = len(_RESULT_STORE) - _MAX_STORED_RESULTS
    for result_id, _ in ordered[:to_remove]:
        _RESULT_STORE.pop(result_id, None)
    _save_result_store_to_disk()


def store_plugin_results(payload: dict, dump_path: str, os_type: str) -> str:
    result_id = f"rp_{uuid.uuid4().hex[:16]}"
    _RESULT_STORE[result_id] = {
        "stored_at": datetime.now(timezone.utc).isoformat(),
        "dump_path": dump_path,
        "os_type": os_type,
        "payload": payload,
    }
    _prune_result_store()
    _save_result_store_to_disk()
    return result_id


def get_stored_plugin_results(result_id: str) -> Optional[dict]:
    record = _RESULT_STORE.get(result_id)
    if not record:
        return None
    return record.get("payload")


def get_latest_result_id() -> Optional[str]:
    if not _RESULT_STORE:
        return None
    latest_id, _ = max(
        _RESULT_STORE.items(),
        key=lambda kv: kv[1].get("stored_at", ""),
    )
    return latest_id


def get_latest_stored_plugin_results() -> Optional[tuple[str, dict]]:
    latest_id = get_latest_result_id()
    if not latest_id:
        return None
    payload = get_stored_plugin_results(latest_id)
    if payload is None:
        return None
    return latest_id, payload


def get_result_metadata(result_id: str) -> Optional[dict]:
    record = _RESULT_STORE.get(result_id)
    if not record:
        return None
    payload = record.get("payload", {})
    return {
        "result_id": result_id,
        "stored_at": record.get("stored_at"),
        "dump_path": record.get("dump_path"),
        "os_type": record.get("os_type"),
        "total": payload.get("total", 0),
        "successful": payload.get("successful", 0),
        "failed": payload.get("failed", 0),
        "network_plugins": len(payload.get("network_data", {})),
        "host_plugins": len(payload.get("host_data", {})),
    }


_load_result_store_from_disk()


async def _run_plugin(ctx: Context, dump_path: str, plugin: str, args: Optional[dict] = None) -> dict:
    validate_dump_path(dump_path)
    plugin = canonicalize_plugin_name(plugin)
    validate_plugin_name(plugin)
    await ctx.info(f"Running {plugin}...")
    result = await executor.run_plugin(dump_path, plugin, args)
    if result.success:
        await ctx.info(f"✓ {plugin}: {len(result.data or [])} rows")
    else:
        await ctx.warning(f"✗ {plugin}: {result.error}")
    return result.to_dict()


async def _run_preset(ctx: Context, dump_path: str, os_type: str, max_concurrent: int = 3) -> dict:
    if os_type == "windows":
        preset = WINDOWS_PLUGINS
    elif os_type == "linux":
        preset = LINUX_PLUGINS
    else:
        raise ValueError(f"Unsupported os_type: '{os_type}'. Must be 'windows' or 'linux'.")

    plugins = preset["network"] + preset["host"]
    total = len(plugins)
    semaphore = asyncio.Semaphore(max_concurrent)
    lock = asyncio.Lock()
    completed_count = 0
    successful = 0
    failed = 0
    network_data = {}
    host_data = {}
    results = {}

    network_names = {p["name"] for p in preset["network"]}

    async def _run_one(plugin_config: dict):
        nonlocal completed_count
        name = plugin_config["name"]
        args = plugin_config.get("args") or {}

        if args:
            import hashlib, json as _json
            args_hash = hashlib.md5(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:6]
            storage_key = f"{name}#{args_hash}"
        else:
            storage_key = name

        async with semaphore:
            async with lock:
                await ctx.report_progress(completed_count, total, f"Running {name}")
            try:
                result = await _run_plugin(ctx, dump_path, name, args)
            finally:
                async with lock:
                    completed_count += 1
        return storage_key, name, result

    items = await asyncio.gather(*[_run_one(p) for p in plugins], return_exceptions=True)

    for i, item in enumerate(items):
        if isinstance(item, Exception):
            failed += 1
            plugin_name = plugins[i]["name"] if i < len(plugins) else f"plugin_{i}"
            args = plugins[i].get("args") or {}
            if args:
                import hashlib, json as _json
                args_hash = hashlib.md5(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:6]
                storage_key = f"{plugin_name}#{args_hash}"
            else:
                storage_key = plugin_name
            results[storage_key] = {"success": False, "rows": 0, "error": str(item)}
            continue

        storage_key, name, result = item
        ok = result.get("success", False)
        results[storage_key] = {
            "success": ok,
            "rows": len(result.get("data") or []),
            "error": result.get("error"),
        }
        if ok:
            successful += 1
            if name in network_names:
                network_data[storage_key] = result.get("data", [])
            else:
                host_data[storage_key] = result.get("data", [])
        else:
            failed += 1

    await ctx.report_progress(total, total, "Complete")
    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "results": results,
        "network_data": network_data,
        "host_data": host_data,
    }


def register_execution_tools(mcp: FastMCP):

    @mcp.tool(
        name="run_plugins",
                description="Run phase 3 plugin preset for an OS and return categorized results; supports store-only mode for large payloads.",
    )
    async def run_plugins(
        ctx: Context,
        dump_path: str,
        os_type: str,
        max_concurrent: int = 3,
        store_only: bool = False,
        return_payload: bool = False,
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.
            Supported: .raw .dmp .mem .vmem .lime .img

        os_type : str
            "windows" or "linux" — must come from detect_os output.

        max_concurrent : int
            Max parallel plugin executions. Default 3.

        store_only : bool
            If true, returns compact metadata + result_id and omits raw rows.
        """
        validate_dump_path(dump_path)
        await ctx.info(f"Running {os_type} preset plugins on {dump_path}")
        payload = await _run_preset(ctx, dump_path, os_type, max_concurrent)
        payload["_meta"] = {
            "dump_path": dump_path,
            "os_type": os_type,
            "os_profile": get_cached_os_profile(dump_path) or {"os_type": os_type},
        }
        result_id = store_plugin_results(payload, dump_path, os_type)
        await ctx.info(f"Stored run_plugins output as {result_id}")

        report_path = write_json_report(
            prefix="run_plugins",
            payload={
                "result_id": result_id,
                "dump_path": dump_path,
                "os_type": os_type,
                "os_profile": payload.get("_meta", {}).get("os_profile", {}),
                "payload": payload,
            },
            result_id=result_id,
        )

        compact = {
            "result_id": result_id,
            "report_path": report_path,
            "total": payload.get("total", 0),
            "successful": payload.get("successful", 0),
            "failed": payload.get("failed", 0),
            "results": payload.get("results", {}),
            "network_plugins": len(payload.get("network_data", {})),
            "host_plugins": len(payload.get("host_data", {})),
            "next_step": "Use ioc_extract_from_store(result_id=<id>)",
        }

        # Backward-compatible escape hatch when inline raw rows are explicitly required.
        if not store_only and return_payload:
            compact["payload"] = payload

        return compact


    @mcp.tool(
        name="get_plugin_results",
        description="Load a stored run_plugins payload by result_id for replay and downstream phases.",
    )
    async def get_plugin_results(ctx: Context, result_id: str) -> dict:
        payload = get_stored_plugin_results(result_id)
        if payload is None:
            return {
                "success": False,
                "error": f"Unknown result_id: {result_id}",
            }
        return {
            "success": True,
            "result_id": result_id,
            "payload": payload,
        }

    @mcp.tool(
        name="summarize_plugin_results",
        description="Return compact per-plugin and per-category row counts from stored run results.",
    )
    async def summarize_plugin_results(ctx: Context, result_id: str) -> dict:
        meta = get_result_metadata(result_id)
        payload = get_stored_plugin_results(result_id)
        if meta is None or payload is None:
            return {
                "success": False,
                "error": f"Unknown result_id: {result_id}",
            }

        network_rows = {
            k: len(v or []) for k, v in payload.get("network_data", {}).items()
        }
        host_rows = {
            k: len(v or []) for k, v in payload.get("host_data", {}).items()
        }
        top_network = sorted(network_rows.items(), key=lambda x: x[1], reverse=True)[:5]
        top_host = sorted(host_rows.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "success": True,
            "metadata": meta,
            "network_plugins": network_rows,
            "host_plugins": host_rows,
            "top_network_by_rows": [{"plugin": k, "rows": v} for k, v in top_network],
            "top_host_by_rows": [{"plugin": k, "rows": v} for k, v in top_host],
        }

    @mcp.tool(
        name="inspect_plugin_rows",
        description="Inspect paginated rows for one stored plugin result with optional filtering and field projection.",
    )
    async def inspect_plugin_rows(
        ctx: Context,
        result_id: str,
        plugin: str,
        category: str = "auto",
        limit: int = 50,
        offset: int = 0,
        contains: Optional[str] = None,
        fields: Optional[list[str]] = None,
    ) -> dict:
        payload = get_stored_plugin_results(result_id)
        if payload is None:
            return {
                "success": False,
                "error": f"Unknown result_id: {result_id}",
            }

        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        rows = None
        resolved_category = None
        for src_category, src in (("network", payload.get("network_data", {})), ("host", payload.get("host_data", {}))):
            if category != "auto" and category != src_category:
                continue
            if plugin in src:
                rows = src.get(plugin, [])
                resolved_category = src_category
                break

        if rows is None:
            return {
                "success": False,
                "error": f"Plugin key not found in stored result: {plugin}",
            }

        if contains:
            needle = contains.lower()
            rows = [r for r in rows if needle in str(r).lower()]

        total_rows = len(rows)
        page = rows[offset: offset + limit]

        if fields:
            projected = []
            for row in page:
                if isinstance(row, dict):
                    projected.append({k: row.get(k) for k in fields})
                else:
                    projected.append(row)
            page = projected

        return {
            "success": True,
            "result_id": result_id,
            "plugin": plugin,
            "category": resolved_category,
            "total_rows": total_rows,
            "offset": offset,
            "limit": limit,
            "rows": page,
        }

    @mcp.tool(
        name="run_plugin",
                description="Run one Volatility plugin for targeted follow-up, not initial collection.",
    )
    async def run_plugin(
        ctx: Context,
        dump_path: str,
        plugin: str,
        args: Optional[dict] = None,
    ) -> dict:
        """
        Parameters
        ----------
        dump_path : str
            Absolute path to memory dump file.

        plugin : str
            Full plugin name. Example: "windows.malware.malfind.Malfind"

        args : dict | None
            Optional plugin args. Example: {"pid": 1234}
        """
        return await _run_plugin(ctx, dump_path, plugin, args)
