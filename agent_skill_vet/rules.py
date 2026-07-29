"""Security rules for SKILL.md files."""
import re
from agent_skill_vet.types import SkillDef, Finding, Severity, ScanReport

W = {Severity.CRITICAL:35, Severity.HIGH:20, Severity.MEDIUM:10, Severity.LOW:3, Severity.INFO:0}

def check_no_description(s: SkillDef): return Finding("no-description",Severity.LOW,"frontmatter","Missing description") if not s.description else None
def check_no_author(s: SkillDef): return Finding("no-author",Severity.INFO,"frontmatter","No author") if not s.author else None
def check_suspicious_tools(s: SkillDef):
    d={"shell","exec","eval","sudo","rm","curl","wget","chmod","kill"}
    f=[t for t in s.tools if any(dd in t.lower() for dd in d)]
    return Finding("suspicious-tools",Severity.HIGH,"tools",f"Dangerous: {', '.join(f)}") if f else None
def check_prompt_injection(s: SkillDef):
    ps=[r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous\s+)?(instructions?|prompts?)",r"(?i)(you are now|act as|from now on)",r"(?i)(system\s+prompt|reveal\s+(your\s+)?instructions)"]
    for p in s.prompts:
        for pat in ps:
            if re.search(pat,p.get("text","")): return Finding("prompt-injection",Severity.CRITICAL,"prompts","Injection vector in prompts")
    return None
def check_code_execution(s: SkillDef):
    for pat in [r"\beval\s*\(",r"\bexec\s*\(",r"\bsubprocess\b",r"\bos\.system\b",r"\bchild_process\b"]:
        if re.search(pat,s.raw_body): return Finding("code-execution",Severity.CRITICAL,"body",f"Code exec: {pat}")
    return None
def check_shell_commands(s: SkillDef):
    for pat in [r"\brm\s+-rf\b",r"\bcurl\s+.*\|",r"\bsudo\s+",r"\bchmod\s+777\b"]:
        if re.search(pat,s.raw_body): return Finding("shell-command",Severity.CRITICAL,"body","Shell command")
    return None
def check_missing_requires(s: SkillDef): return Finding("missing-requires",Severity.MEDIUM,"frontmatter","No dependencies listed") if (not s.requires and s.tools) else None
def check_remote_fetch(s: SkillDef): return Finding("remote-fetch",Severity.MEDIUM,"body","Remote fetch") if re.search(r"\b(curl|wget|fetch|requests\.get|urllib)\b",s.raw_body) else None
def check_empty_body(s: SkillDef): return Finding("empty-body",Severity.LOW,"body","Short body") if len(s.raw_body.strip())<20 else None

RULES=[check_no_description,check_no_author,check_suspicious_tools,check_prompt_injection,check_code_execution,check_shell_commands,check_missing_requires,check_remote_fetch,check_empty_body]

def scan_skill(skill: SkillDef) -> ScanReport:
    fs=[]
    for r in RULES:
        f=r(skill)
        if f: fs.append(f)
    risk=min(100,sum(W[f.severity] for f in fs))
    verdict="vulnerable" if risk>=50 else ("suspicious" if risk>=25 else "safe")
    return ScanReport(skill=skill,findings=fs,risk_score=risk,verdict=verdict)
