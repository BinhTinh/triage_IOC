# cases.py
from datetime import datetime
from typing import Dict, List, Optional

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


def register_case_resources(mcp: FastMCP):

    @mcp.resource(
        "cases://list",
        name="List All Cases",
        description="""
Read-only snapshot of all analysis cases in the current session.

## PURPOSE
Provides an index of every forensic case created by smart_triage or automated_pipeline.
Use this resource to discover existing case IDs without making tool calls.

## WHEN TO READ THIS RESOURCE
- At session start to check for previously completed analyses
- After batch processing to verify all cases completed successfully
- To find a case_id by OS type or goal when the ID is unknown

## CASE LIFECYCLE
  created → running → completed
                   ↘ failed

## ID FORMAT
  CASE_WIN_{YYYYMMDD}_{hex6}   — Windows dumps
  CASE_LIN_{YYYYMMDD}_{hex6}   — Linux dumps

## RESPONSE SCHEMA
{
  "total": 3,
  "by_status": {
    "pending":   0,
    "running":   1,
    "completed": 2,
    "failed":    0
  },
  "cases": [
    {
      "id":             "CASE_WIN_20260224_a1b2c3",
      "status":         "completed",    // created | running | completed | failed
      "os_type":        "windows",
      "os_version":     "10",
      "goal":           "malware_detection",
      "dump_path":      "/app/data/dumps/infected.raw",
      "findings_count": 12,
      "iocs_count":     5,
      "created_at":     "2026-02-24T10:00:00",
      "updated_at":     "2026-02-24T10:15:00"
    }
  ]
}

## NEXT STEP
→ Read cases://{case_id}/details for full timeline and metadata on a specific case
→ Use get_analysis_status(case_id) tool to check status programmatically
""",
    )
    async def resource_list_cases() -> dict:
        cases = sorted(_cases_db.values(), key=lambda c: c.created_at, reverse=True)
        return {
            "total": len(cases),
            "by_status": {
                "pending":   sum(1 for c in cases if c.status == CaseStatus.PENDING),
                "running":   sum(1 for c in cases if c.status == CaseStatus.RUNNING),
                "completed": sum(1 for c in cases if c.status == CaseStatus.COMPLETED),
                "failed":    sum(1 for c in cases if c.status == CaseStatus.FAILED),
            },
            "cases": [
                {
                    "id":             c.id,
                    "status":         c.status.value,
                    "os_type":        c.os_type,
                    "os_version":     c.os_version,
                    "goal":           c.goal,
                    "dump_path":      c.dump_path,
                    "findings_count": c.findings_count,
                    "iocs_count":     c.iocs_count,
                    "created_at":     c.created_at.isoformat(),
                    "updated_at":     c.updated_at.isoformat(),
                }
                for c in cases
            ],
        }

    @mcp.resource(
        "cases://{case_id}/details",
        name="Case Details",
        description="""
Full metadata, event timeline, and findings summary for a specific analysis case.

## PURPOSE
Provides deep inspection of a single case — more detail than cases://list.
Includes duration, dump hash for deduplication, architecture, and a chronological
event log of what happened during the analysis.

## PARAMETER
case_id : str
  Case ID from smart_triage["case_id"] or automated_pipeline["case_id"].
  Format: CASE_WIN_{YYYYMMDD}_{hex6} or CASE_LIN_{YYYYMMDD}_{hex6}

## RESPONSE SCHEMA
{
  "id":               "CASE_WIN_20260224_a1b2c3",
  "dump_path":        "/app/data/dumps/infected.raw",
  "dump_hash":        "sha256:abcdef...",   // for deduplication — same hash = same dump
  "os_type":          "windows",
  "os_version":       "10",
  "os_arch":          "x64",
  "goal":             "malware_detection",
  "status":           "completed",
  "findings_count":   12,
  "iocs_count":       5,
  "created_at":       "2026-02-24T10:00:00",
  "updated_at":       "2026-02-24T10:15:00",
  "duration_seconds": 900,                  // null if still running
  "timeline": [
    {"timestamp": "...", "event": "Case created",     "details": "Goal: malware_detection, OS: windows"},
    {"timestamp": "...", "event": "Analysis started", "details": "Processing /app/data/dumps/infected.raw"},
    {"timestamp": "...", "event": "Analysis completed","details": "Found 12 findings, 5 IOCs"}
  ]
}

## ERROR RESPONSE
{"error": "Case not found: CASE_WIN_20260224_xxxxxx"}

## NEXT STEP
→ If status=completed: read report files at /app/data/reports/{case_id}/report.json
→ If status=failed: re-run automated_pipeline(dump_path, goal) with same params
→ If status=running: wait and poll this resource again in 30s
""",
    )
    async def resource_get_case_details(case_id: str) -> dict:
        case = _cases_db.get(case_id)
        if not case:
            return {"error": f"Case not found: {case_id}"}

        created = (
            case.created_at if isinstance(case.created_at, datetime)
            else datetime.fromisoformat(str(case.created_at).split("+")[0])
        )
        updated = (
            case.updated_at if isinstance(case.updated_at, datetime)
            else datetime.fromisoformat(str(case.updated_at).split("+")[0])
        )
        duration = (updated - created).total_seconds() if case.status == CaseStatus.COMPLETED else None

        events = [
            {"timestamp": created.isoformat(), "event": "Case created",
             "details": f"Goal: {case.goal}, OS: {case.os_type}"}
        ]
        if case.status in (CaseStatus.RUNNING, CaseStatus.COMPLETED, CaseStatus.FAILED):
            events.append({"timestamp": created.isoformat(), "event": "Analysis started",
                           "details": f"Processing {case.dump_path}"})
        if case.status == CaseStatus.COMPLETED:
            events.append({"timestamp": updated.isoformat(), "event": "Analysis completed",
                           "details": f"Found {case.findings_count} findings, {case.iocs_count} IOCs"})
        elif case.status == CaseStatus.FAILED:
            events.append({"timestamp": updated.isoformat(), "event": "Analysis failed",
                           "details": "Check logs for details"})

        return {
            "id":               case.id,
            "dump_path":        case.dump_path,
            "dump_hash":        case.dump_hash,
            "os_type":          case.os_type,
            "os_version":       case.os_version,
            "os_arch":          case.os_arch,
            "goal":             case.goal,
            "status":           case.status.value,
            "findings_count":   case.findings_count,
            "iocs_count":       case.iocs_count,
            "created_at":       created.isoformat(),
            "updated_at":       updated.isoformat(),
            "duration_seconds": duration,
            "timeline":         events,
        }
