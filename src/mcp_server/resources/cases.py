from datetime import datetime
from typing import Optional, List, Dict, Any
from fastmcp import FastMCP

from src.models.case import Case, CaseStatus


_cases_db: Dict[str, Case] = {}


async def get_case(case_id: str) -> Optional[Case]:
    return _cases_db.get(case_id)


async def save_case(case: Case) -> None:
    _cases_db[case.id] = case


async def update_case_status(case_id: str, status: str) -> None:
    if case_id in _cases_db:
        _cases_db[case_id].status = CaseStatus(status)
        _cases_db[case_id].updated_at = datetime.now()


async def update_case_findings(case_id: str, findings_count: int = 0, iocs_count: int = 0) -> None:
    if case_id in _cases_db:
        _cases_db[case_id].findings_count = findings_count
        _cases_db[case_id].iocs_count = iocs_count
        _cases_db[case_id].updated_at = datetime.now()


async def delete_case(case_id: str) -> bool:
    if case_id in _cases_db:
        del _cases_db[case_id]
        return True
    return False


async def list_all_cases() -> List[Case]:
    return list(_cases_db.values())


async def list_cases_by_status(status: CaseStatus) -> List[Case]:
    return [c for c in _cases_db.values() if c.status == status]


async def list_cases_by_os(os_type: str) -> List[Case]:
    return [c for c in _cases_db.values() if c.os_type == os_type]


async def get_case_count() -> Dict[str, int]:
    counts = {
        "total": len(_cases_db),
        "pending": 0,
        "running": 0,
        "completed": 0,
        "failed": 0,
    }
    for case in _cases_db.values():
        counts[case.status.value] = counts.get(case.status.value, 0) + 1
    return counts


def register_case_resources(mcp: FastMCP):
    
    @mcp.resource("cases://list")
    async def resource_list_all_cases() -> dict:
        cases = await list_all_cases()
        return {
            "total": len(cases),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_type": c.os_type,
                    "os_version": c.os_version,
                    "goal": c.goal,
                    "dump_path": c.dump_path,
                    "findings_count": c.findings_count,
                    "iocs_count": c.iocs_count,
                    "created_at": c.created_at.isoformat(),
                    "updated_at": c.updated_at.isoformat(),
                }
                for c in sorted(cases, key=lambda x: x.created_at, reverse=True)
            ]
        }
    
    @mcp.resource("cases://count")
    async def resource_case_count() -> dict:
        return await get_case_count()
    
    @mcp.resource("cases://active")
    async def resource_list_active_cases() -> dict:
        pending = await list_cases_by_status(CaseStatus.PENDING)
        running = await list_cases_by_status(CaseStatus.RUNNING)
        active = pending + running
        return {
            "total": len(active),
            "pending": len(pending),
            "running": len(running),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_type": c.os_type,
                    "goal": c.goal,
                    "created_at": c.created_at.isoformat(),
                }
                for c in sorted(active, key=lambda x: x.created_at, reverse=True)
            ]
        }
    
    @mcp.resource("cases://completed")
    async def resource_list_completed_cases() -> dict:
        completed = await list_cases_by_status(CaseStatus.COMPLETED)
        return {
            "total": len(completed),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_type": c.os_type,
                    "goal": c.goal,
                    "findings_count": c.findings_count,
                    "iocs_count": c.iocs_count,
                    "created_at": c.created_at.isoformat(),
                    "updated_at": c.updated_at.isoformat(),
                }
                for c in sorted(completed, key=lambda x: x.updated_at, reverse=True)
            ]
        }
    
    @mcp.resource("cases://failed")
    async def resource_list_failed_cases() -> dict:
        failed = await list_cases_by_status(CaseStatus.FAILED)
        return {
            "total": len(failed),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_type": c.os_type,
                    "goal": c.goal,
                    "dump_path": c.dump_path,
                    "created_at": c.created_at.isoformat(),
                    "updated_at": c.updated_at.isoformat(),
                }
                for c in sorted(failed, key=lambda x: x.updated_at, reverse=True)
            ]
        }
    
    @mcp.resource("cases://windows")
    async def resource_list_windows_cases() -> dict:
        windows_cases = await list_cases_by_os("windows")
        return {
            "os_type": "windows",
            "total": len(windows_cases),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_version": c.os_version,
                    "goal": c.goal,
                    "findings_count": c.findings_count,
                    "iocs_count": c.iocs_count,
                    "created_at": c.created_at.isoformat(),
                }
                for c in sorted(windows_cases, key=lambda x: x.created_at, reverse=True)
            ]
        }
    
    @mcp.resource("cases://linux")
    async def resource_list_linux_cases() -> dict:
        linux_cases = await list_cases_by_os("linux")
        return {
            "os_type": "linux",
            "total": len(linux_cases),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_version": c.os_version,
                    "goal": c.goal,
                    "findings_count": c.findings_count,
                    "iocs_count": c.iocs_count,
                    "created_at": c.created_at.isoformat(),
                }
                for c in sorted(linux_cases, key=lambda x: x.created_at, reverse=True)
            ]
        }
    
    @mcp.resource("cases://recent")
    async def resource_list_recent_cases() -> dict:
        cases = await list_all_cases()
        recent = sorted(cases, key=lambda x: x.created_at, reverse=True)[:10]
        return {
            "total": len(recent),
            "cases": [
                {
                    "id": c.id,
                    "status": c.status.value,
                    "os_type": c.os_type,
                    "goal": c.goal,
                    "created_at": c.created_at.isoformat(),
                }
                for c in recent
            ]
        }
    
    @mcp.resource("cases://{case_id}/summary")
    async def resource_get_case_summary(case_id: str) -> dict:
        case = await get_case(case_id)
        if not case:
            return {"error": f"Case not found: {case_id}"}
        return case.to_dict()
    
    @mcp.resource("cases://{case_id}/status")
    async def resource_get_case_status(case_id: str) -> dict:
        case = await get_case(case_id)
        if not case:
            return {"error": f"Case not found: {case_id}"}
        return {
            "id": case.id,
            "status": case.status.value,
            "updated_at": case.updated_at.isoformat()
        }
    
    @mcp.resource("cases://{case_id}/details")
    async def resource_get_case_details(case_id: str) -> dict:
        case = await get_case(case_id)
        if not case:
            return {"error": f"Case not found: {case_id}"}
        return {
            "id": case.id,
            "dump_path": case.dump_path,
            "dump_hash": case.dump_hash,
            "os_type": case.os_type,
            "os_version": case.os_version,
            "os_arch": case.os_arch,
            "goal": case.goal,
            "status": case.status.value,
            "findings_count": case.findings_count,
            "iocs_count": case.iocs_count,
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
            "duration_seconds": (case.updated_at - case.created_at).total_seconds() if case.status == CaseStatus.COMPLETED else None
        }
    
    @mcp.resource("cases://{case_id}/timeline")
    async def resource_get_case_timeline(case_id: str) -> dict:
        case = await get_case(case_id)
        if not case:
            return {"error": f"Case not found: {case_id}"}
        
        events = [
            {
                "timestamp": case.created_at.isoformat(),
                "event": "Case created",
                "details": f"Goal: {case.goal}, OS: {case.os_type}"
            }
        ]
        
        if case.status in [CaseStatus.RUNNING, CaseStatus.COMPLETED, CaseStatus.FAILED]:
            events.append({
                "timestamp": case.created_at.isoformat(),
                "event": "Analysis started",
                "details": f"Processing {case.dump_path}"
            })
        
        if case.status == CaseStatus.COMPLETED:
            events.append({
                "timestamp": case.updated_at.isoformat(),
                "event": "Analysis completed",
                "details": f"Found {case.findings_count} findings, {case.iocs_count} IOCs"
            })
        elif case.status == CaseStatus.FAILED:
            events.append({
                "timestamp": case.updated_at.isoformat(),
                "event": "Analysis failed",
                "details": "Check logs for details"
            })
        
        return {
            "case_id": case_id,
            "events": events
        }