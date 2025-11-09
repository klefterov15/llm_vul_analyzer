# 🧠 LLM-Powered Git Secret Scanner

A command-line tool that scans the **last N commits** of a Git repository to detect **exposed secrets or other sensitive data** using a hybrid approach:

- **Heuristic detection** (regex + entropy analysis)  
- **LLM-based refinement** using OpenAI’s API for context-aware validation  

The tool outputs a **structured JSON report** containing all findings, commit information, and AI-scored results.

---

## 🚀 Features

- ✅ Clone or load any local / remote Git repository  
- ✅ Analyze commit diffs and messages  
- ✅ Detect high-entropy strings and credential patterns  
- ✅ Filter out irrelevant files (tests, vendors, etc.)  
- ✅ Query a hosted LLM (OpenAI) for reasoning and confidence scoring  
- ✅ Export a full JSON report with severity levels  

---

## 🧩 System Architecture

The tool follows the same three-stage architecture proposed in the reference paper:

1. **Data Collection** – Extract commit history and diffs using `GitPython`.  
2. **Heuristic Detection** – Apply regex + entropy rules to identify potential secrets.  
3. **LLM Refinement** – Evaluate each candidate using a cybersecurity-focused prompt.

---

## ⚙️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/klefterov15/llm_vul_analyzer.git
cd llm_vul_analyzer

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # (Linux/Mac)
.venv\Scripts\activate      # (Windows)

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your OpenAI API key
echo "OPENAI_API_KEY=sk-..." > .env
```

---

## 🧠 Usage

```bash
python scan.py --repo <path|url> --n <commits> --out <output.json> [--llm True]
```

## Example

```bash
python scan.py \
  --repo https://github.com/trufflesecurity/test_keys.git \
  --n 3 \
  --out report.json \
  --llm True
```

---

## 🧾 Output Structure

The generated JSON report contains the following sections:

**commits** - Metadata for each commit scanned \
**diffs** - Raw diff content of changed files   \
**findings** - Heuristic detections from regex and entropy \
**llm_output** - AI-refined evaluations for each finding \
**high_risk_findings** - Subset of high probability vulnerable diffs\

## Example Snippet 

```json
{
  "commits": [
    {
      "commit_hash": "0416560b1330d8ac42045813251d85c688717eaf",
      "message": "adding a key",
      "author": "counter"
    }
  ],
  "findings": [
    {
      "file_path": "new_key",
      "snippet": "aws_secret_access_key = 1tUm63...",
      "finding_type": "AWS Secret Access Key",
      "detector": "regex",
      "confidence": 0.9
    }
  ],
  "llm_output": [
    {
      "base_finding": {
        "commit_hash": "0416560b1330d8ac42045813251d85c688717eaf",
        "file_path": "new_key",
        "snippet": "aws_secret_access_key = 1tUm63...",
        "finding_type": "AWS Secret Access Key",
        "detector": "regex",
        "confidence": 0.9
      },
      "llm_score": 4,
      "llm_confidence": 0.92,
      "llm_rationale": "The commit introduces a real AWS credential.",
      "severity": "critical",
      "is_likely_secret": true
    }
  ]
}
```
---

## Scoring & Interpretation
**0** - definitely not a secret  
**1** - Probably not a secret \
**2** - Unclear / Needs a review\
**3** - Probably a real secret \
**4** - Definitely a secret \

***IMPORTANT*** : Findings with llm_score >= 3 are exported under high_risk_findings

---

## 🧮 Heuristic Patterns Used 

The tool currently detects: 

- AWS Access Keys
- Private Key Blocks
- JWT tokens
- Slack tokens
- Hard-coded passwords
- Google API Keys
- High-entropy Base64 / Hex strings
---

## 🧰 File Structure
```plaintext
llm_vul_analyzer/
│
├── detectors/
│   ├── heuristics.py        # Regex + entropy detectors
│   ├── filter.py            # Skips tests/vendor directories
│   ├── llm_scoring.py       # LLM reasoning module
│
├── repo_getter.py           # Commit & diff extractor
├── scan.py                  # Main CLI entry point
├── requirements.txt
├── README.md
└── .env                     # Stores your OpenAI API key
```
