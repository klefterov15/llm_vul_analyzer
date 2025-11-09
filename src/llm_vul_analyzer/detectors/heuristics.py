from dataclasses import dataclass
import re
from typing import List
from llm_vul_analyzer.repo_getter import FileChange
import math


@dataclass(slots=True)
class Findings:
    commit_hash: str
    file_path: str
    snippet: str
    finding_type: str
    detector: str
    confidence: float

PATTERNS = [
    # AWS credentials
    ("AWS Access Key ID",
        re.compile(r"(?i)[+\-\s]*aws_access_key_id\s*=\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?")),
    ("AWS Secret Access Key",
        re.compile(r"(?i)[+\-\s]*aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),

    # Private key blocks
    ("Private Key Block",
        re.compile(r"-----BEGIN (?:EC|PGP|DSA|RSA|OPENSSH)? ?PRIVATE KEY(?: BLOCK)?-----")),

    # Generic JWT (JSON Web Token)
    ("JWT Token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),

    # Slack tokens (common forms: xoxb, xoxp, xoxa, xoxr)
    ("Slack Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b")),

    # Hardcoded password assignments
    ("Hard-coded Password",
        re.compile(r"(?i)[+\-\s]*(password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\" ]{8,}['\"]")),

    # Google Cloud API key
    ("Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),

    # Generic OAuth / Bearer tokens
    ("Bearer/OAuth Token",
        re.compile(r"(?i)authorization[:=]\s*['\"]?Bearer\s+[A-Za-z0-9\-_\.]{20,}['\"]?")),

    # SSH key fingerprint (optional, often not a real secret but useful to check)
    ("SSH Key Fingerprint",
        re.compile(r"ssh-rsa\s+[A-Za-z0-9+/=]{100,}")),
]



def detect_regex (file_change: FileChange) -> List[Findings]:
    found : List[Findings] = []
    content = file_change.diff_content
    for label, pattern in PATTERNS :
        for match in pattern.finditer(content):
            #print("Regex pattern matched")
            snippet = match.group(0)
            finding = Findings(
                commit_hash = file_change.commit_hash,
                file_path = file_change.file_path,
                snippet = snippet,
                finding_type = label,
                detector = "regex",
                confidence = 0.9,
            )
            found.append(finding)

    return found

def shannon_entropy (s: str) -> float:
    if not s :
        return 0.0
    counts = {}
    for ch in s :
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in counts.values():
        p =count/length
        entropy -= p * math.log(p, 2)

    return entropy

def looks_like_base64(s: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9+/]{20,}={0,2}", s) is not None

def looks_like_hex(s: str) -> bool:
    return re.fullmatch(r"[0-9A-Fa-f]{20,}", s) is not None

def detect_entropy(file_change: FileChange, base64_thresh = 4.5, hex_thresh = 3.0) -> List[Findings]:
    found : List[Findings] = []
    tokens = re.findall(r"[A-Za-z0-9+/=]{20,}", file_change.diff_content)
    for token in tokens:
        if looks_like_base64(token):
            ent = shannon_entropy(token)
            if ent > base64_thresh:
                #print("Entropy found 1")
                found.append(Findings(
                    commit_hash=file_change.commit_hash,
                    file_path=file_change.file_path,
                    snippet=token,
                    finding_type="High-entropy base64 string",
                    detector="entropy",
                    confidence=0.6
                ))
        elif looks_like_hex(token):
            ent = shannon_entropy(token)
            if ent > hex_thresh:
                #print("Entropy found 2")
                found.append(Findings(
                    commit_hash=file_change.commit_hash,
                    file_path=file_change.file_path,
                    snippet=token,
                    finding_type="High-entropy hex string",
                    detector="entropy",
                    confidence=0.6
                ))
    return found