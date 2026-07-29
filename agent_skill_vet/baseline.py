"""Baseline management."""
import json
from agent_skill_vet.types import ScanReport, Finding

def save_baseline(report: ScanReport, path: str) -> None:
    entries = [{"rule_id":f.rule_id,"location":f.location,"message":f.message} for f in report.findings]
    with open(path,"w",encoding="utf-8") as f: json.dump({"risk_score":report.risk_score,"findings":entries}, f, indent=2)

def load_baseline(path: str) -> tuple[int, list[dict]]:
    with open(path,encoding="utf-8") as f: data = json.load(f)
    return data.get("risk_score",0), data.get("findings",[])

def compare_baseline(report: ScanReport, baseline_path: str) -> tuple[list[Finding], list[str]]:
    _, bl = load_baseline(baseline_path)
    bl_ids = {f"{b['rule_id']}:{b['location']}" for b in bl}
    cur_ids = {f"{f.rule_id}:{f.location}" for f in report.findings}
    new = [f for f in report.findings if f"{f.rule_id}:{f.location}" in cur_ids - bl_ids]
    return new, sorted(bl_ids - cur_ids)
