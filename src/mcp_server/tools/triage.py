import asyncio
from typing import List, Optional
from fastmcp import FastMCP, Context
import os
from pathlib import Path
from src.config.settings import settings

from src.core.decision_engine import DecisionEngine, get_triage_plan
from src.core.volatility_executor import VolatilityExecutor
from src.core.ioc_extractor import ExtractionPipeline
from src.core.validator import ValidationPipeline
from src.core.mitre_mapper import MITREMapper
from src.core.report_generator import ReportGenerator
from src.core.symbol_resolver import SymbolResolver
from src.models.case import Case, CaseStatus
from src.models.ioc import IOC, ValidatedIOC
from src.utils.security import validate_dump_path
from src.utils.cache import CacheManager
from src.config.settings import settings

from datetime import datetime

executor = VolatilityExecutor()
decision_engine = DecisionEngine()
symbol_resolver = SymbolResolver()
cache = CacheManager()

_cases_db = {}


async def get_case(case_id: str) -> Optional[Case]:
    return _cases_db.get(case_id)


async def save_case(case: Case) -> None:
    _cases_db[case.id] = case


async def update_case_status(case_id: str, status: str) -> None:
    if case_id in _cases_db:
        _cases_db[case_id].status = CaseStatus(status)
        _cases_db[case_id].updated_at = datetime.now()

async def _detect_os_helper(dump_path: str) -> dict:
    try:
        result = await executor.run_plugin(dump_path, "windows.info", renderer="json")
        if result.success and result.data:
            return {
                "os_type": "windows",
                "version": str(result.data[0].get("NtMajorVersion", "unknown")),
                "build": str(result.data[0].get("NtBuildNumber", "unknown")),
                "arch": "x64" if result.data[0].get("Is64Bit", True) else "x86"
            }
    except:
        pass
    
    try:
        result = await executor.run_plugin(dump_path, "banners.Banners", renderer="json")
        if result.success and result.data:
            import re
            for banner in result.data:
                match = re.search(r"Linux version (\d+\.\d+\.\d+)", banner.get("Banner", ""))
                if match:
                    return {"os_type": "linux", "version": match.group(1), "arch": "x64"}
    except:
        pass
    
    return {"os_type": "windows", "version": "unknown", "arch": "x64"}


def register_triage_tools(mcp: FastMCP):
    
    @mcp.tool()
    async def detect_os(ctx: Context, dump_path: str) -> dict:
        validate_dump_path(dump_path)
        await ctx.info(f"Detecting OS for {dump_path}")
        return await _detect_os_helper(dump_path)
    
    @mcp.tool()
    async def smart_triage(ctx: Context, dump_path: str, goal: str = "malware_detection") -> dict:
        validate_dump_path(dump_path)
        await ctx.info(f"Starting smart triage for {dump_path}")
        
        os_info = await _detect_os_helper(dump_path)
        await ctx.info(f"Detected OS: {os_info['os_type']} {os_info['version']}")
        
        plan = get_triage_plan(os_info["os_type"], goal)
        
        case = Case(
            dump_path=dump_path,
            dump_hash=await executor.get_dump_hash(dump_path),
            os_type=os_info["os_type"],
            os_version=os_info["version"],
            os_arch=os_info["arch"],
            goal=goal
        )
        await save_case(case)
        await ctx.info(f"Created case {case.id}")
        
        return {
            "case_id": case.id,
            "os": os_info,
            "plan": {
                "goal": goal,
                "plugins": [p["name"] for p in plan.plugins],
                "estimated_minutes": plan.estimated_minutes
            }
        }
    
    @mcp.tool()
    async def quick_scan(ctx: Context, dump_path: str) -> dict:
        validate_dump_path(dump_path)
        await ctx.info("Running quick scan...")
        return await smart_triage(ctx, dump_path, goal="quick_triage")
    
    @mcp.tool()
    async def deep_analysis(ctx: Context, dump_path: str) -> dict:
        validate_dump_path(dump_path)
        await ctx.info("Running deep analysis...")
        return await smart_triage(ctx, dump_path, goal="incident_response")
    
    @mcp.tool()
    async def rootkit_hunt(ctx: Context, dump_path: str) -> dict:
        validate_dump_path(dump_path)
        await ctx.info("Running rootkit hunt...")
        return await smart_triage(ctx, dump_path, goal="rootkit_hunt")
    
    @mcp.tool()
    async def full_analysis(ctx: Context, dump_path: str, goal: str = "malware_detection") -> dict:
        validate_dump_path(dump_path)
        await ctx.info(f"Starting full analysis pipeline for {dump_path}")
        
        from src.core.analysis_pipeline import AnalysisPipeline
        
        pipeline = AnalysisPipeline(
            progress_callback=lambda curr, total, msg: asyncio.create_task(ctx.report_progress(curr, total, msg)),
            log_callback=lambda msg, level: asyncio.create_task(ctx.info(msg))
        )
        
        result = await pipeline.run_analysis(dump_path=dump_path, goal=goal)
        
        await ctx.info(f"Complete: {result['threat_level']} ({result['threat_score']}/100)")
        
        return result
    
    @mcp.tool()
    async def get_analysis_status(ctx: Context, case_id: str) -> dict:
        case = await get_case(case_id)
        if not case:
            raise ValueError(f"Case not found: {case_id}")
        return case.to_dict()
    
    @mcp.tool()
    async def list_cases(ctx: Context) -> dict:
        return {
            "total": len(_cases_db),
            "cases": [c.to_dict() for c in _cases_db.values()]
        }
    
    @mcp.tool()
    async def get_symbols_status(ctx: Context, dump_path: str) -> dict:
        validate_dump_path(dump_path)
        return await symbol_resolver.check_symbols(dump_path)
    


    @mcp.tool()
    async def list_available_dumps(ctx: Context) -> dict:
        dumps_dir = Path(settings.dumps_dir)
        
        if not dumps_dir.exists():
            return {
                "dumps_directory": str(dumps_dir),
                "available": False,
                "message": "Dumps directory does not exist",
                "files": []
            }
        
        valid_extensions = [".raw", ".dmp", ".mem", ".vmem", ".lime", ".img"]
        dump_files = []
        
        for ext in valid_extensions:
            dump_files.extend(dumps_dir.glob(f"*{ext}"))
            dump_files.extend(dumps_dir.glob(f"**/*{ext}"))
        
        files_info = []
        for f in sorted(set(dump_files)):
            stat = f.stat()
            files_info.append({
                "filename": f.name,
                "path": str(f),
                "size_bytes": stat.st_size,
                "size_human": f"{stat.st_size / (1024**3):.2f} GB" if stat.st_size > 1024**3 else f"{stat.st_size / (1024**2):.2f} MB",
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        return {
            "dumps_directory": str(dumps_dir),
            "available": True,
            "total_files": len(files_info),
            "files": files_info
        }
    
    @mcp.tool()
    async def select_dump_and_triage(
        ctx: Context,
        filename: str,
        goal: str = "malware_detection"
    ) -> dict:
        dumps_dir = Path(settings.dumps_dir)
        dump_path = dumps_dir / filename
        
        if not dump_path.exists():
            for f in dumps_dir.rglob(filename):
                dump_path = f
                break
        
        if not dump_path.exists():
            available = await list_available_dumps(ctx)
            return {
                "error": f"File not found: {filename}",
                "available_dumps": available["files"]
            }
        
        return await smart_triage(ctx, str(dump_path), goal)
    
    @mcp.tool()
    async def quick_analyze(ctx: Context, filename: str) -> dict:
        dumps_dir = Path(settings.dumps_dir)
        dump_path = dumps_dir / filename
        
        if not dump_path.exists():
            for f in dumps_dir.rglob(filename):
                dump_path = f
                break
        
        if not dump_path.exists():
            return {"error": f"File not found: {filename}"}
        
        from src.core.analysis_pipeline import AnalysisPipeline
        
        pipeline = AnalysisPipeline(
            progress_callback=lambda curr, total, msg: asyncio.create_task(ctx.report_progress(curr, total, msg)),
            log_callback=lambda msg, level: asyncio.create_task(ctx.info(msg))
        )
        
        result = await pipeline.run_analysis(dump_path=str(dump_path), goal="malware_detection")
        
        return result