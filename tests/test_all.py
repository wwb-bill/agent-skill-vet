from agent_skill_vet.parser import parse_skill
from agent_skill_vet.rules import scan_skill, RULES
from agent_skill_vet.types import SkillDef

class TestParser:
    def test_name(self): s=parse_skill("---\nname: my-skill\ndescription: Does things\n---\n# Body"); assert s.name=="my-skill"
    def test_tools(self): s=parse_skill("---\ntools: [search, read]\n---\nBody"); assert s.tools==["search","read"]
    def test_prompts(self): s=parse_skill("---\nname: test\n---\n```prompt\nHello world\n```"); assert len(s.prompts)>=1
    def test_no_frontmatter(self): s=parse_skill("# Just markdown"); assert s.name==""

class TestRules:
    def test_no_description(self): s=SkillDef(name="test"); assert any(f.rule_id=="no-description" for f in scan_skill(s).findings)
    def test_suspicious_tools(self): s=SkillDef(name="test",description="x",tools=["exec","curl"]); assert any(f.rule_id=="suspicious-tools" for f in scan_skill(s).findings)
    def test_code_exec(self): s=SkillDef(name="test",description="x",raw_body="eval('bad')"); assert any(f.rule_id=="code-execution" for f in scan_skill(s).findings)
    def test_shell(self): s=SkillDef(name="test",description="x",raw_body="rm -rf /tmp"); assert any(f.rule_id=="shell-command" for f in scan_skill(s).findings)
    def test_safe(self): s=SkillDef(name="hello",description="Greets",author="alice",tools=["search"]); assert scan_skill(s).verdict=="safe"
    def test_vulnerable(self): s=SkillDef(name="bad",description="x",tools=["exec"],raw_body="rm -rf /\neval('x')"); assert scan_skill(s).verdict=="vulnerable"
    def test_9_rules(self): assert len(RULES)==9
    def test_summary(self): s=SkillDef(name="test",description="a"); assert "Risk:" in scan_skill(s).summary()
