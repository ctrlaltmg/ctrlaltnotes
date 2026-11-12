# SPDX-License-Identifier: AGPL-3.0-only
"""Pentest regression (F-08, F-17): the Markdown renderer must stay fast and must not throw on
adversarial notes. Runs md.js in headless Chromium: python3 tests/md_robustness.py"""
import pathlib, sys, time
from playwright.sync_api import sync_playwright

SRC = (pathlib.Path(__file__).resolve().parent.parent / "ui" / "md.js").read_text()
CASES = {
    "heading_spaces_hash": "#" + " " * 20000 + "x" + "#" * 20000 + " ",
    "heading_hash_space_mix": "# " + "# " * 20000 + "x",
    "backtick_run": "`" * 50000,
    "backtick_odd": "`a" * 20000,
    "stars": "*a " * 30000,
    "underscores": "_a" * 30000,
    "brackets": "[a](" * 20000,
    "deep_blockquote": ">" * 20000 + " x",
    "deep_blockquote_lines": "\n".join([">" * 500] * 40),
    "table_bomb": "|" + "a|" * 5000 + "\n|" + "-|" * 5000 + "\n" + ("|x" * 5000 + "|\n") * 20,
    "hr_spaces": "- " * 20000 + "x",
    "huge_note": ("**bold** text _it_ `c`\n\n" * 40000),
    "nested_emph": "*" * 3000 + "a" + "*" * 3000,
    "list_bomb": "\n".join(["  " * i + "- x" for i in range(3000)]),
}
BUDGET_MS = 4000

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page()
    page.set_content("<body></body>")
    page.add_script_tag(content=SRC)
    bad = 0
    for name, text in CASES.items():
        t0 = time.time()
        res = page.evaluate(
            """(t) => { try { const f = window.renderMarkdown(t); return {ok: true, n: f.childNodes.length}; }
                        catch (e) { return {ok: false, err: String(e)}; } }""", text)
        ms = (time.time() - t0) * 1000
        ok = res["ok"] and ms < BUDGET_MS
        bad += not ok
        print(("PASS" if ok else "FAIL"), name, f"{ms:.0f}ms", res.get("err", ""))
    # F-17 mailto query is stripped, scripts/data urls are refused
    for u, want in [("mailto:a@b.com?bcc=evil@x.com&body=hi", "mailto:a@b.com"),
                    ("javascript:alert(1)", None), ("data:text/html,x", None),
                    ("https://example.com/a?b=c", "https://example.com/a?b=c")]:
        got = page.evaluate("(u) => window.safeHref(u)", u)
        ok = got == want
        bad += not ok
        print(("PASS" if ok else "FAIL"), "safeHref", u, "->", got)
    b.close()
sys.exit(1 if bad else 0)
