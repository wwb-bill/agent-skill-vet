from agent_skill_vet.remediation import get_suggestion, generate_remediation
from agent_skill_vet.types import SkillDef, ScanReport, Finding, Severity
from agent_skill_vet.parser import parse_skill
from agent_skill_vet.rules import scan_skill


class TestRemediation:
    def test_get_suggestion(self):
        assert "description" in get_suggestion("no-description")
        assert "eval" in get_suggestion("code-execution").lower()
        assert "shell" in get_suggestion("shell-command").lower()

    def test_unknown_rule(self):
        assert "standard security practices" in get_suggestion("nonexistent-rule")

    def test_generate_remediation(self):
        s = SkillDef(name="test", description="x", tools=["exec"])
        r = scan_skill(s)
        rem = generate_remediation(r)
        assert len(rem) >= 1
        assert any(item["rule"] == "suspicious-tools" for item in rem)

    def test_all_9_rules_have_suggestions(self):
        from agent_skill_vet.rules import RULES
        for rule in RULES:
            rule_id = rule.__name__[6:]
            assert len(get_suggestion(rule_id)) > 10, f"Rule {rule_id} has no meaningful suggestion"


class TestEndToEnd:
    def test_full_pipeline(self):
        text = "---\nname: safe-skill\ndescription: A safe utility\nauthor: alice\ntools: [search]\nrequires: [read_access]\n---\n# Body content that is sufficiently long for audit"
        skill = parse_skill(text)
        report = scan_skill(skill)
        assert report.verdict == "safe"
        rem = generate_remediation(report)
        assert len(rem) == 0

    def test_vulnerable_pipeline(self):
        text = "---\nname: bad-skill\ndescription: x\ntools: [exec, curl]\n---\neval('hacked')\nrm -rf /tmp"
        skill = parse_skill(text)
        report = scan_skill(skill)
        assert report.verdict == "vulnerable"
        assert report.risk_score >= 50
        rem = generate_remediation(report)
        assert len(rem) >= 3
