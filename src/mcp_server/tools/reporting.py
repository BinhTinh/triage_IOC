import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from src.config.settings import settings


def write_json_report(prefix: str, payload: dict, result_id: Optional[str] = None) -> str:
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = result_id or uuid4().hex[:8]
    filename = f"{prefix}_{ts}_{suffix}.json"
    path = reports_dir / filename

    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=True, indent=2)

    return str(path)


def load_json_report(report_path: str) -> dict:
    path = Path(report_path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
