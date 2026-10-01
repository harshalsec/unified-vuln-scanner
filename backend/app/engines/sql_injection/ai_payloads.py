from typing import List
import random

from app.engines.sql_injection.payloads import SQLI_PAYLOADS

def generate_ai_sqli_payloads(base_payloads: List[str] | None = None, count: int = 12) -> List[str]:
    """
    AI-inspired mutation of SQL Injection payloads.
    """
    if not base_payloads:
        base_payloads = SQLI_PAYLOADS

    mutations: List[str] = []

    for payload in base_payloads:
        mutations.append(payload)

        # Case variations
        mutations.append(payload.swapcase())
        mutations.append(payload.lower())
        mutations.append(payload.upper())

        # Spacing tricks
        mutations.append(payload.replace(" ", "  "))
        mutations.append(payload.replace("=", " = "))
        mutations.append(payload.replace("'", " ' "))

        # Comment variations
        if "--" in payload:
            mutations.append(payload.replace("--", "#"))
            mutations.append(payload.replace("--", "/*"))
        if "#" in payload:
            mutations.append(payload.replace("#", "--"))

        # OR / AND variations
        if "OR" in payload.upper():
            mutations.append(payload.replace("OR", "or"))
            mutations.append(payload.replace("OR", "||"))
        if "AND" in payload.upper():
            mutations.append(payload.replace("AND", "and"))
            mutations.append(payload.replace("AND", "&&"))

        # Quote variations
        mutations.append(payload.replace("'", "\""))
        mutations.append(payload.replace("\"", "'"))

        # Classic tautology expansions
        if "1=1" in payload:
            mutations.append(payload.replace("1=1", "2=2"))
            mutations.append(payload.replace("1=1", "1=1--"))
            mutations.append(payload.replace("1=1", "1=1#"))

    # Unique + shuffle
    unique = list(dict.fromkeys(m for m in mutations if m))
    random.shuffle(unique)
    return unique[:count]

def get_smart_sqli_payloads(depth: str = "normal") -> List[str]:
    if depth == "fast":
        return generate_ai_sqli_payloads(count=6)
    elif depth == "deep":
        return generate_ai_sqli_payloads(count=18)
    else:
        return generate_ai_sqli_payloads(count=12)