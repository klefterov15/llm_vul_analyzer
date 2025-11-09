import re

TEST_FILE_PATTERNS = [
    re.compile(r"(?i)(^|/)(test|tests|spec|unit|integration)(/|_).*"),
    re.compile(r"(?i).*[_\-]?test(s)?\.(py|java|js|ts)$"),
]

VENDOR_DIR_PATTERN = re.compile(r"(?i)/vendor/|/node_modules/|/third_party/")

def should_skip(file_path: str, diff_content: str) -> bool:
    # skip vendor or node_modules directories
    if VENDOR_DIR_PATTERN.search(file_path):
        print("Vendor directory detected")
        return True
    # skip obvious test files
    for p in TEST_FILE_PATTERNS:
        if p.search(file_path):
            print("Test file detected")
            return True
    # skip diffs with no additions or only whitespace changes
    if diff_content.strip() == "":
        print("Hui")
        return True

    return False
