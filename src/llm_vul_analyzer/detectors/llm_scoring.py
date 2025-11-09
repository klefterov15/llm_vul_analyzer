# llm_vul_analyzer/detectors/llm_scoring.py

import os
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import List
from pydantic import BaseModel
from openai import OpenAI

from llm_vul_analyzer.detectors.heuristics import Findings
from llm_vul_analyzer.repo_getter import GitCommit, FileChange

# -- Data class for the evaluated output
@dataclass(slots=True)
class LlmEvaluation:
    base_finding: Findings
    llm_score: int
    llm_confidence: float
    llm_rationale: str

# -- Schema for structured output from the model
class LlmResponse(BaseModel):
    score: int
    confidence: float
    rationale: str

# -- Load API key from .env
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("OPENAI_API_KEY environment variable is not set")

# -- Initialize the OpenAI client
client = OpenAI(api_key=api_key)

def score_with_llm(
    findings: List[Findings],
    commits: List[GitCommit],
    diffs: List[FileChange],
) -> List[LlmEvaluation]:
    """
    Given heuristic findings, evaluate each with an LLM.
    Returns a list of LlmEvaluation objects.
    """
    llm_found: List[LlmEvaluation] = []

    # Create lookups for commit message and diff content
    commit_lookup = {c.commit_hash: c for c in commits}
    diff_lookup   = {d.commit_hash: d for d in diffs}

    for f in findings:
        # Find matching commit & diff context
        commit_obj = commit_lookup.get(f.commit_hash)
        diff_obj   = diff_lookup.get(f.commit_hash)

        commit_msg = commit_obj.message if commit_obj else ""
        diff_full  = diff_obj.diff_content if diff_obj else ""

        # Truncate diff if too long
        max_lines = 200
        diff_lines = diff_full.splitlines()
        if len(diff_lines) > max_lines:
            diff_full = "\n".join(diff_lines[:max_lines]) + "\n…(truncated)…"

        # Split diff into original (removed lines) and revised (added lines)
        original_snippet = "\n".join(
            line for line in diff_full.splitlines() if line.startswith("-")
        )
        revised_snippet = "\n".join(
            line for line in diff_full.splitlines() if line.startswith("+")
        )

        # Build the prompt for the LLM
        prompt = f"""
You are a cybersecurity expert specializing in detecting exposed secrets and credentials in source-code changes.

Commit message:
{commit_msg}

Original snippet (state of the code *before* the changes in this commit):
{original_snippet}

Revised snippet (state of the code *after* the changes in this commit):
{revised_snippet}

Other changes in the same commit (context for your assessment):
{diff_full}

Heuristic finding type: {f.finding_type}
Heuristic snippet: {f.snippet}

Important:
- “Original” refers to the code as it was **before** the commit was applied.
- “Revised” refers to the code as it appears **after** the commit’s changes.

On a scale from 0 to 4, how likely is this heuristic finding to represent a **real exposed secret or sensitive credential**?
- 0 = definitely not a secret
- 1 = probably not
- 2 = unclear / needs review
- 3 = probably a real secret
- 4 = definitely a real secret and high risk

Please respond *strictly* as valid JSON with keys:
{{
    "score": <int>,
    "confidence": <float between 0 and 1>,
    "rationale": "<short explanation>"
}}
"""
        lines = prompt.splitlines()
        cleaned_prompt = "\n".join(line.lstrip() for line in lines)

        # Call the API
        response = client.responses.parse(
            model="gpt-4o-mini",
            input=cleaned_prompt,
            text_format=LlmResponse  # this tells SDK to parse into your schema
        )

        raw = response.output_text
        if raw.startswith("```"):
            print("I found this")
            raw = raw.split("```", 2)[-1]
        print(raw)

        try:
            parsed = LlmResponse.model_validate_json(raw)
        except Exception as e:
            parsed = LlmResponse(score=0, confidence=0.0, rationale=f"Parse error: {e}")

        llm_output = LlmEvaluation(
            base_finding   = f,
            llm_score      = parsed.score,
            llm_confidence = parsed.confidence,
            llm_rationale  = parsed.rationale,
        )
        llm_found.append(llm_output)

    # End for loop

    return llm_found
