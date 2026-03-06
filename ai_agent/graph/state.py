from typing import TypedDict, List, Optional, Dict, Any

class ForensicsState(TypedDict):
    dump_path: str
    goal: str
    case_id: Optional[str]
    os_info: Optional[Dict[str, Any]]
    plugin_list: List[Any]
    plugin_results: Dict[str, Any]
    iocs: List[Dict[str, Any]]
    validated_iocs: Dict[str, Any]
    mitre_mapping: Dict[str, Any]
    report_path: Optional[Dict[str, str]]
    error: Optional[str]
    progress: int
    reasoning_log: List[str]
    needs_deeper_scan: bool
    additional_plugins: List[str]
    interpretation: dict
    plan_review:       dict
    reasoning_content: str