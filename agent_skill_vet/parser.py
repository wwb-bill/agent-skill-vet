"""Parse SKILL.md files."""
import re
from agent_skill_vet.types import SkillDef

def parse_skill(text: str) -> SkillDef:
    skill = SkillDef(raw_body=text)
    fm_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', text, re.DOTALL)
    frontmatter = ""
    if fm_match:
        frontmatter = fm_match.group(1)
        skill.raw_body = text[fm_match.end():]
    skill.name = _extract(frontmatter, "name")
    skill.description = _extract(frontmatter, "description")
    skill.author = _extract(frontmatter, "author")
    tools_str = _extract(frontmatter, "tools")
    if tools_str: skill.tools = [t.strip() for t in tools_str.replace("[","").replace("]","").split(",") if t.strip()]
    req_str = _extract(frontmatter, "requires")
    if req_str: skill.requires = [r.strip() for r in req_str.replace("[","").replace("]","").split(",") if r.strip()]
    for pm in re.findall(r'```(?:prompt|text)?\s*\n(.*?)\n```', skill.raw_body, re.DOTALL):
        skill.prompts.append({"text": pm.strip()})
    return skill

def _extract(fm: str, field: str) -> str:
    m = re.search(rf'^{field}\s*:\s*(.+?)\s*$', fm, re.MULTILINE)
    return m.group(1).strip().strip('"').strip("'") if m else ""
