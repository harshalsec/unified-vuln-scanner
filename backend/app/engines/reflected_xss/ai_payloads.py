from typing import List
import random
import html

from app.engines.reflected_xss.payloads import XSS_PAYLOADS

def generate_ai_payloads(base_payloads: List[str] | None = None, count: int = 12) -> List[str]:
    """
    Improved GenXSS-inspired payload mutation engine.
    Creates higher-quality variations of XSS payloads.
    """
    if not base_payloads:
        base_payloads = XSS_PAYLOADS

    mutations: List[str] = []

    for payload in base_payloads:
        # Original
        mutations.append(payload)

        # Case variations
        mutations.append(payload.swapcase())
        mutations.append(payload.lower())
        mutations.append(payload.upper())

        # Spacing / formatting tricks
        mutations.append(payload.replace("=", " = "))
        mutations.append(payload.replace("=", "="))
        mutations.append(payload.replace("<", "< "))
        mutations.append(payload.replace(">", " >"))

        # Tag breaking techniques
        if "<script>" in payload.lower():
            mutations.append(payload.replace("<script>", "<scr<script>ipt>"))
            mutations.append(payload.replace("<script>", "<script/>"))
            mutations.append(payload.replace("<script>", "<script >"))
            mutations.append(payload.replace("</script>", "</scr</script>ipt>"))

        # Event handler obfuscation
        for event in ["onerror", "onload", "onmouseover", "onfocus", "ontoggle"]:
            if event in payload.lower():
                mutations.append(payload.replace(event, event.upper()))
                mutations.append(payload.replace(event, event.capitalize()))
                mutations.append(payload.replace(f"{event}=", f"{event}="))
                mutations.append(payload.replace(f"{event}=", f"{event} ="))

        # alert() variations
        if "alert(1)" in payload:
            mutations.append(payload.replace("alert(1)", "alert`1`"))
            mutations.append(payload.replace("alert(1)", "alert(String.fromCharCode(49))"))
            mutations.append(payload.replace("alert(1)", "prompt(1)"))
            mutations.append(payload.replace("alert(1)", "confirm(1)"))
            mutations.append(payload.replace("alert(1)", "al\\u0065rt(1)"))
            mutations.append(payload.replace("alert(1)", "top['alert'](1)"))

        # SVG / MathML style mutations
        if "<svg" in payload.lower():
            mutations.append(payload.replace("<svg", "<svg/"))
            mutations.append(payload.replace("<svg", "<svg "))
        if "<img" in payload.lower():
            mutations.append(payload.replace("<img", "<img/"))
            mutations.append(payload.replace("<img", "<img "))

        # Partial HTML encoding
        mutations.append(html.escape(payload))
        mutations.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
        mutations.append(payload.replace("\"", "&quot;"))

        # Double encoding style
        mutations.append(payload.replace("<", "%3C").replace(">", "%3E"))

    # Clean + unique
    unique = []
    seen = set()
    for m in mutations:
        if m and m not in seen:
            seen.add(m)
            unique.append(m)

    random.shuffle(unique)
    return unique[:count]

def get_smart_payloads(depth: str = "normal") -> List[str]:
    """
    Return AI-mutated payloads based on scan depth.
    """
    if depth == "fast":
        return generate_ai_payloads(count=6)
    elif depth == "deep":
        return generate_ai_payloads(count=20)
    else:
        return generate_ai_payloads(count=12)