from fastmcp import FastMCP


def register_prompts(mcp: FastMCP):

    @mcp.prompt()
    async def ioc_extraction_workflow(os_hint: str = "auto") -> str:
        return (
            "# IOC Workflow (Compact)\n\n"
            "Rules:\n"
            "- Do not ask user for paths/inputs; discover automatically.\n"
            "- Use Docker paths only: dumps `/app/data/dumps`, reports `/app/data/reports`.\n"
            "- Execute phases in order.\n\n"
            "1) `list_dumps()`\n"
            "- pick most recent dump if multiple files\n\n"
            "2) `detect_os(dump_path=<dump_path>)`\n"
            "- store `os_type`\n\n"
            "3) `run_plugins(dump_path=<dump_path>, os_type=<os_type>, store_only=true)`\n"
            "- store `result_id` and `report_path`\n\n"
            "4) `ioc_extract_from_store(result_id=<result_id>, os_type=<os_type>)`\n"
            "- use returned extraction `report_path`\n\n"
            "5) `ioc_validate_from_report(report_path=<ioc_extract_report_path>, os_type=<os_type>)`\n"
            "- use returned validation `report_path`\n\n"
            "6) `forensic_report_from_validation(report_path=<ioc_validate_report_path>)`\n"
            "- produces markdown forensic report in `/app/data/reports`\n"
        )

    @mcp.prompt()
    async def ioc_reference() -> str:
        return (
            "# IOC Tools (Compact Reference)\n\n"
            "Path rule: use `/app/data/...` Docker paths only.\n\n"
            "Report-first chain:\n"
            "`list_dumps` -> `detect_os` -> `run_plugins(store_only=true)` -> "
            "`ioc_extract_from_store` -> `ioc_validate_from_report` -> "
            "`forensic_report_from_validation`\n\n"
            "Tools:\n"
            "- `list_dumps`: discover dump files\n"
            "- `detect_os`: identify `os_type`/arch\n"
            "- `run_plugins`: execute preset; returns `result_id` + run report path\n"
            "- `ioc_extract_from_store`: returns extraction summary + extraction report path\n"
            "- `ioc_validate_from_report`: returns validation summary + validation report path\n"
            "- `forensic_report_from_validation`: returns forensic markdown report path\n\n"
            "Validation policy:\n"
            "- local whitelist always runs\n"
            "- external threat intel (VT/AbuseIPDB) runs only when enabled\n"
        )
