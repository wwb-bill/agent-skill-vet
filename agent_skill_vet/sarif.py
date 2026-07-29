"""SARIF 2.1.0 output."""
import json
from agent_skill_vet.types import ScanReport, Severity

def to_sarif(report: ScanReport, source: str = "SKILL.md") -> dict:
    results = []
    for f in report.findings:
        results.append({"ruleId":f.rule_id,"level":_l(f.severity),"message":{"text":f.message},"locations":[{"physicalLocation":{"artifactLocation":{"uri":source},"region":{"startLine":1}}}]})
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"agent-skill-vet","informationUri":"https://github.com/wwb-bill/agent-skill-vet","rules":[{"id":f.rule_id,"shortDescription":{"text":f.message}} for f in report.findings]}},"results":results}]}

def write_sarif(report: ScanReport, path: str, source: str = "SKILL.md") -> None:
    with open(path,"w",encoding="utf-8") as f: json.dump(to_sarif(report, source), f, indent=2)

def _l(s: Severity) -> str: return {"critical":"error","high":"error","medium":"warning","low":"note","info":"none"}.get(s,"warning")
