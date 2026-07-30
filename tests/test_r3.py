from agent_skill_vet.batch import scan_directory, scan_marketplace_index, aggregate_reports
from agent_skill_vet.types import SkillDef, ScanReport, Finding, Severity
import tempfile, os, json


class TestBatch:
    def test_scan_directory(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
                f.write("---\nname: good-skill\ndescription: A safe skill\nauthor: alice\ntools: [search]\n---\n# Body content here enough long")
            with open(os.path.join(d, "SKILL-evil.md"), "w", encoding="utf-8") as f:
                f.write("---\nname: bad-skill\ndescription: x\ntools: [exec, curl]\n---\neval('hacked')")
            results = scan_directory(d)
            assert len(results) >= 2
            assert any("good-skill" in str(r.skill.name) for r in results.values())
        finally:
            for f in os.listdir(d): os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_scan_marketplace(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            entries = [
                {"name": "safe-skill", "description": "A safe utility", "body": "---\nname: safe-skill\ndescription: A safe utility\nauthor: bob\ntools: [search]\n---\n# Safe body content here"},
                {"name": "risky-skill", "description": "x", "body": "---\nname: risky-skill\ndescription: x\ntools: [exec]\n---\neval('boom')"},
            ]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f)
            results = scan_marketplace_index(path)
            assert len(results) == 2
            assert any(r.verdict == "vulnerable" for r in results.values())
        finally:
            os.unlink(path)


class TestAggregate:
    def test_aggregate(self):
        s = SkillDef(name="test")
        reports = {
            "a": ScanReport(skill=s, findings=[], risk_score=0, verdict="safe"),
            "b": ScanReport(skill=s, findings=[Finding("x", Severity.HIGH, "body", "msg")], risk_score=30, verdict="suspicious"),
        }
        agg = aggregate_reports(reports)
        assert agg["total"] == 2 and agg["safe"] == 1 and agg["avg_risk"] == 15.0

    def test_empty_aggregate(self):
        assert aggregate_reports({})["total"] == 0
