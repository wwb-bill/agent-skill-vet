from agent_skill_vet.sarif import to_sarif, write_sarif
from agent_skill_vet.baseline import save_baseline, load_baseline, compare_baseline
from agent_skill_vet.types import SkillDef, ScanReport, Finding, Severity
import tempfile, os

class TestSARIF:
    def test_to_sarif(self):
        s=SkillDef(name="test"); r=ScanReport(skill=s,findings=[Finding("test-rule",Severity.HIGH,"body","Test finding")],risk_score=20)
        assert to_sarif(r)["version"]=="2.1.0" and len(to_sarif(r)["runs"][0]["results"])==1
    def test_write_sarif(self):
        s=SkillDef(name="test"); r=ScanReport(skill=s,findings=[Finding("x",Severity.LOW,"body","msg")],risk_score=3)
        fd,path=tempfile.mkstemp(suffix=".sarif"); os.close(fd)
        try: write_sarif(r,path); assert '"version": "2.1.0"' in open(path).read()
        finally: os.unlink(path)

class TestBaseline:
    def test_save_load(self):
        s=SkillDef(name="test"); r=ScanReport(skill=s,findings=[Finding("rule",Severity.HIGH,"body","msg")],risk_score=20)
        fd,path=tempfile.mkstemp(suffix=".json"); os.close(fd)
        try: save_baseline(r,path); score,fs=load_baseline(path); assert score==20 and len(fs)==1
        finally: os.unlink(path)
    def test_compare_new(self):
        s=SkillDef(name="test")
        fd,bp=tempfile.mkstemp(suffix=".json"); os.close(fd)
        save_baseline(ScanReport(skill=s,findings=[Finding("a",Severity.HIGH,"body","old")],risk_score=20),bp)
        try:
            r=ScanReport(skill=s,findings=[Finding("a",Severity.HIGH,"body","old"),Finding("b",Severity.HIGH,"body","new!")],risk_score=40)
            nw,rm=compare_baseline(r,bp); assert len(nw)==1 and nw[0].rule_id=="b"
        finally: os.unlink(bp)
    def test_compare_removed(self):
        s=SkillDef(name="test")
        fd,bp=tempfile.mkstemp(suffix=".json"); os.close(fd)
        save_baseline(ScanReport(skill=s,findings=[Finding("a",Severity.HIGH,"body","fixed")],risk_score=20),bp)
        try:
            nw,rm=compare_baseline(ScanReport(skill=s,findings=[],risk_score=0),bp); assert len(nw)==0 and len(rm)==1
        finally: os.unlink(bp)
