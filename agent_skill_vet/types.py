from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum): CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

@dataclass
class SkillDef:
    name: str = ""; description: str = ""; author: str = ""
    tools: list[str] = field(default_factory=list); prompts: list[dict] = field(default_factory=list)
    requires: list[str] = field(default_factory=list); raw_body: str = ""

@dataclass
class Finding:
    rule_id: str; severity: Severity; location: str; message: str

@dataclass
class ScanReport:
    skill: SkillDef; findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0; verdict: str = "safe"
    def summary(self) -> str:
        c = sum(1 for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
        return f"Risk: {self.risk_score}/100 ({self.verdict}) — {len(self.findings)} findings, {c} critical/high"
