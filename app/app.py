# rule_116_split.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re

app = FastAPI(title="Rule 116 — SPLIT Requires MODE", version="1.0")

# ---------------------------------------------------------------------------
# Models (same structure/style as your services)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    # results key is added dynamically: rule116_findings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def line_of_offset(text: str, off: int) -> int:
    """Return 1-based line number for a 0-based character offset."""
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    """Return a short context snippet with escaped newlines for JSON safety."""
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

# ---------------------------------------------------------------------------
# Detection (statement-scoped, multi-line safe)
# ---------------------------------------------------------------------------
# 1) Capture ONE ABAP statement that starts with SPLIT and ends at the period.
STMT_RE = re.compile(r"(?is)\bSPLIT\b[^.]*\.", re.DOTALL)

# 2) Inside the statement, verify the MODE addition.
MODE_RE = re.compile(r"(?i)\bIN\s+(CHARACTER|BYTE)\s+MODE\b")

def scan_unit(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    for m in STMT_RE.finditer(src):
        stmt  = m.group(0)
        start = m.start()
        end   = m.end()

        has_mode = MODE_RE.search(stmt) is not None

        if not has_mode:
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "SplitWithoutMode",
                "severity": "warning",
                "line": line_of_offset(src, start),
                "message": "SPLIT without MODE. Specify IN CHARACTER MODE (text) or IN BYTE MODE (binary).",
                "suggestion": (
                    "SPLIT <text> AT <sep> INTO <f1> <f2> ... IN CHARACTER MODE.\n"
                    "* or *\n"
                    "SPLIT <xbin> AT <xsep> INTO <x1> <x2> ... IN BYTE MODE. Specify IN CHARACTER MODE (text) or IN BYTE MODE (binary)."
                ),
                "snippet": snippet_at(src, start, end),
            })

    obj = unit.model_dump()
    obj["rule116_findings"] = findings
    return obj

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array")
async def scan_rule(units: List[Unit]):
    results = []
    for u in units:
        res = scan_unit(u)
        if res.get("rule116_findings"):
            results.append(res)
    return results

@app.get("/health")
async def health():
    return {"ok": True, "rule": 116}
