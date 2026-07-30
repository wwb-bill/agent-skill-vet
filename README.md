# agent-skill-vet

Security scanner for AI agent SKILL.md files — detect vulnerabilities in agent skills. Inspired by NVIDIA SkillSpector (26.1% vuln rate).

**🎯 9th M project — v1.0.0 COMPLETE (27 tests)**

```bash
pip install agent-skill-vet
agent-skill-vet scan skill.md --fail-on-risk 30 --sarif report.sarif
```

## 9 Rules

| Rule | Severity |
|------|:--:|
| prompt-injection | critical |
| code-execution | critical |
| shell-command | critical |
| suspicious-tools | high |
| missing-requires | medium |
| remote-fetch | medium |
| no-description | low |
| empty-body | low |
| no-author | info |

## Modules

- `parser.py` — SKILL.md YAML frontmatter parser
- `rules.py` — 9 security rules with risk scoring
- `sarif.py` — SARIF 2.1.0 output for GitHub Code Scanning
- `baseline.py` — Baseline management (save/load/compare)
- `batch.py` — Directory + marketplace batch scanning
- `remediation.py` — Fix suggestions for each finding

## Roadmap

| Round | Feature | Status |
|:--:|---------|:--:|
| R1 | Core scanner | ✅ |
| R2 | SARIF + baseline | ✅ |
| R3 | Batch + marketplace | ✅ |
| R4 | Remediation + v1.0 | ✅ v1.0.0 |

MIT
