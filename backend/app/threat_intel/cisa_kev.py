import json
from pathlib import Path
from typing import Dict, Optional

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "cisa_kev_sample.json"


def load_kev_catalog() -> Dict[str, dict]:
    if not DATA_PATH.exists():
        return {}
    try:
        records = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {str(item.get("cve_id", "")).upper(): item for item in records if item.get("cve_id")}


def get_kev_record(cve_id: Optional[str]) -> Optional[dict]:
    if not cve_id:
        return None
    return load_kev_catalog().get(str(cve_id).upper())


def is_known_exploited(cve_id: Optional[str]) -> bool:
    return get_kev_record(cve_id) is not None
