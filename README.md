# agent-skill-vet

Security scanner for AI agent SKILL.md files. 9 rules, SARIF output, baseline management. 🎯 9th M project (v0.2.0, R2/4).

```bash
pip install agent-skill-vet
agent-skill-vet scan skill.md --fail-on-risk 30 --sarif report.sarif
```

Inspired by NVIDIA SkillSpector (26.1% vuln rate in agent skills).

MIT
