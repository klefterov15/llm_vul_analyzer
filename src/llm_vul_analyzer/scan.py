import json
import argparse
from typing import List

from llm_vul_analyzer.repo_getter import GitCommitExtractor
from detectors.filter import should_skip
from detectors.heuristics import detect_regex, detect_entropy, Findings
from dataclasses import asdict
from detectors.llm_scoring import score_with_llm

def classify_severity (score: int ) -> str:
    if score == 4:
        return "critical"
    if score == 3:
        return "high"
    if score == 2:
        return "medium"
    if score == 1:
        return "low"
    return "info"



def main () :
    parser = argparse.ArgumentParser (
        prog = "scan",
        description = """ Scan a git repository for vulnerabilities. """
    )
    parser.add_argument(
        "--repo", "--r",
        required = True,
        help = "The git repository to scan.",
        type= str
    )
    parser.add_argument (
        "--n",
        type = int,
        required = False,
        default = 1,
        help = "The number of vulnerabilities to scan."
    )
    parser.add_argument (
        "--out",
        type = str,
        help = "The output file to write.",
        default = "out.json"
    )
    parser.add_argument(
        "--llm",
        help= 'Uses AI evaluation for vulnerabilities.',
        action='store_true'
    )

    args = parser.parse_args()

    print("Scanning...")
    print("Repo: {}".format(args.repo))
    print("N: {}".format(args.n))
    print("Out: {}".format(args.out))
    print("Fetching commits...")
    print()


    extractor = GitCommitExtractor(args.repo)
    extractor.extract(args.repo, args.n)
    findings : List[Findings] = []
    llm = []

    for fc in extractor.file_changes:
        if should_skip(fc.file_path, fc.diff_content):
            print("Hello there")
            continue
        findings.extend(detect_regex(fc))
        findings.extend(detect_entropy(fc))

    commit_dicts = [asdict(c) for c in extractor.commits]
    diffs_dicts  = [asdict(f) for f in extractor.file_changes]
    findings_dicts = [asdict(f) for f in findings]

    if args.llm:
        llm.extend(score_with_llm(findings, extractor.commits, extractor.file_changes))
        llm_dicts = []
        for l in llm:
            d = asdict(l)
            sev = classify_severity(l.llm_score)
            d['severity'] = sev
            d['is_likely_secret'] = l.llm_score >= 3
            llm_dicts.append(d)

        high_risk_found = [d for d in llm_dicts if d['is_likely_secret'] == True]

        report = {"commits": commit_dicts,
                  "diffs": diffs_dicts,
                  "findings": findings_dicts,
                  "llm_output": llm_dicts,
                  "high_risk_found": high_risk_found
        }
    else:
        report = {"commits": commit_dicts,
                  "diffs": diffs_dicts,
                  "findings": findings_dicts
        }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__" :
    main()