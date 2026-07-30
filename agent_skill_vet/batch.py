"""Batch scanner — scan directories and marketplace indexes."""

import os, json
from collections import Counter
from agent_skill_vet.parser import parse_skill
from agent_skill_vet.rules import scan_skill
from agent_skill_vet.types import ScanReport


def scan_directory(dir_path: str) -> dict[str, ScanReport]:
    results: dict[str, ScanReport] = {}
    for root, _, files in os.walk(dir_path):
        for fname in files:
            if fname.endswith(".md") and ("SKILL" in fname or "skill" in fname):
                full = os.path.join(root, fname)
                with open(full, encoding="utf-8") as f:
                    skill = parse_skill(f.read())
                results[full] = scan_skill(skill)
    return results


def scan_marketplace_index(index_path: str) -> dict[str, ScanReport]:
    with open(index_path, encoding="utf-8") as f:
        entries = json.load(f)
    results: dict[str, ScanReport] = {}
    for entry in entries:
        if not isinstance(entry, dict): continue
        body = entry.get("body", entry.get("raw_body", ""))
        if not body:
            body = f"# {entry.get('name', 'unknown')}\n\n{entry.get('description', '')}"
        if "name" in entry and "body" not in entry and "raw_body" not in entry:
            fm = f"---\nname: {entry.get('name', 'unknown')}\n"
            if entry.get("description"): fm += f"description: {entry.get('description')}\n"
            if entry.get("tools"): fm += f"tools: {json.dumps(entry['tools'])}\n"
            fm += "---\n\n"
            body = fm + body
        skill = parse_skill(body)
        results[entry.get("name", f"entry-{len(results)}")] = scan_skill(skill)
    return results


def aggregate_reports(reports: dict[str, ScanReport]) -> dict:
    total = len(reports)
    if total == 0:
        return {"total": 0, "safe": 0, "suspicious": 0, "vulnerable": 0, "avg_risk": 0}
    counts = {"safe": 0, "suspicious": 0, "vulnerable": 0}
    total_risk = 0
    all_findings: list[str] = []
    for report in reports.values():
        counts[report.verdict] += 1
        total_risk += report.risk_score
        for f in report.findings: all_findings.append(f.rule_id)
    top_rules = Counter(all_findings).most_common(5)
    return {
        "total": total, "safe": counts["safe"], "suspicious": counts["suspicious"], "vulnerable": counts["vulnerable"],
        "avg_risk": round(total_risk / total, 1),
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
        "details": {name: {"risk": r.risk_score, "verdict": r.verdict} for name, r in reports.items()},
    }
