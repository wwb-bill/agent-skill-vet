import sys, json, argparse
from agent_skill_vet.parser import parse_skill
from agent_skill_vet.rules import scan_skill, RULES
from agent_skill_vet.sarif import write_sarif
from agent_skill_vet.baseline import save_baseline, compare_baseline

def main(argv=None):
    if hasattr(sys.stdout,"reconfigure"): sys.stdout.reconfigure(encoding="utf-8",errors="replace")
    p = argparse.ArgumentParser(prog="agent-skill-vet")
    sp = p.add_subparsers(dest="cmd")
    p1 = sp.add_parser("scan"); p1.add_argument("file"); p1.add_argument("--json",action="store_true"); p1.add_argument("--fail-on-risk",type=int,default=0); p1.add_argument("--sarif"); p1.add_argument("--baseline"); p1.add_argument("--save-baseline")
    p2 = sp.add_parser("rules")
    args = p.parse_args(argv)
    try:
        if args.cmd == "rules":
            for r in RULES: print(r.__name__[6:])
        elif args.cmd == "scan":
            with open(args.file,encoding="utf-8") as f: skill = parse_skill(f.read())
            report = scan_skill(skill)
            if args.sarif: write_sarif(report, args.sarif, args.file); print(f"SARIF written to {args.sarif}")
            if args.save_baseline: save_baseline(report, args.save_baseline); print(f"Baseline saved to {args.save_baseline}")
            if args.baseline:
                new, removed = compare_baseline(report, args.baseline)
                print(f"New: {len(new)}, Fixed: {len(removed)}")
                for nf in new: print(f"  + [{nf.severity.value}] {nf.rule_id}: {nf.message}")
            if args.json:
                out = {"name":skill.name,"risk":report.risk_score,"verdict":report.verdict,"findings":[{"rule":f.rule_id,"severity":f.severity.value,"message":f.message} for f in report.findings]}
                print(json.dumps(out,indent=2))
            else:
                print(f"Skill: {skill.name or '(unnamed)'}\n{report.summary()}\n")
                for f in report.findings: print(f"  [{f.severity.value}] {f.rule_id}: {f.message}")
            if args.fail_on_risk>0 and report.risk_score>=args.fail_on_risk: sys.exit(1)
        else: p.print_help()
    except Exception as e: print(f"Error: {e}",file=sys.stderr); sys.exit(2)

if __name__=="__main__": main()
