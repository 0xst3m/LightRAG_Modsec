"""
Edge case tests for the CRS .conf parser.
Focuses on tricky real-world patterns: chains, continuations,
mixed content, and malformed files.
"""
import os
import tempfile
from ingest.parser import parse_crs_file


def _parse_content(content: str) -> list:
    """Helper: write content to a temp .conf file, parse, cleanup, return chunks."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.conf', mode='w')
    tmp.write(content)
    tmp.close()
    chunks = parse_crs_file(tmp.name)
    os.remove(tmp.name)
    return chunks


def run_tests():
    all_passed = True

    def check(name, actual, expected):
        nonlocal all_passed
        if actual != expected:
            print(f"FAILED {name}: expected {expected}, got {actual}")
            all_passed = False
        else:
            print(f"PASSED {name}")

    # ── Basic cases ──────────────────────────────────────────
    check(
        "single standalone rule",
        len(_parse_content('SecRule ARGS "a" "id:1,pass"')),
        1,
    )
    check(
        "single SecAction",
        len(_parse_content('SecAction "id:900001,pass"')),
        1,
    )
    check(
        "two standalone rules",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,pass"\nSecRule ARGS "b" "id:2,pass"'
        )),
        2,
    )
    check(
        "empty file",
        len(_parse_content("")),
        0,
    )
    check(
        "comments only",
        len(_parse_content("# comment\n# another\n")),
        0,
    )

    # ── Line continuations ───────────────────────────────────
    check(
        "LF continuations",
        len(_parse_content(
            'SecRule ARGS \\\n  "@rx a" \\\n  "id:1,pass"'
        )),
        1,
    )

    # ── Chain grouping ───────────────────────────────────────
    check(
        "2-level chain = 1 chunk",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,chain"\n'
            '    SecRule ARGS "b" "pass"'
        )),
        1,
    )
    check(
        "3-level chain = 1 chunk",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,chain"\n'
            '    SecRule ARGS "b" "chain"\n'
            '    SecRule ARGS "c" "pass"'
        )),
        1,
    )
    check(
        "4-level chain with continuations = 1 chunk",
        len(_parse_content(
            'SecRule A "a" \\\n    "id:1,\\\n    chain"\n'
            '    SecRule B "b" \\\n        "chain"\n'
            '        SecRule C "c" \\\n            "chain"\n'
            '            SecRule D "d" \\\n                "pass"\n'
        )),
        1,
    )
    check(
        "chain + standalone = 2 chunks",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,chain"\n'
            '    SecRule ARGS "b" "pass"\n'
            'SecRule ARGS "c" "id:2,pass"\n'
        )),
        2,
    )
    check(
        "two chains back to back = 2 chunks",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,chain"\n'
            '    SecRule ARGS "b" "pass"\n'
            'SecRule ARGS "c" "id:2,chain"\n'
            '    SecRule ARGS "d" "deny"\n'
        )),
        2,
    )
    check(
        "malformed chain at EOF = 1 chunk (flushed)",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,chain"\n'
        )),
        1,
    )

    # ── chain keyword at end of quoted string ────────────────
    check(
        'chain" at end of action string',
        len(_parse_content(
            'SecRule ARGS "a" "id:1,severity:\'CRITICAL\',chain"\n'
            '    SecRule ARGS "b" "pass"\n'
        )),
        1,
    )

    # ── Comments between chained and non-chained rules ───────
    check(
        "comments between standalone rules = 2 chunks",
        len(_parse_content(
            '# Comment before\n'
            'SecRule ARGS "a" "id:1,pass"\n'
            '# Comment between\n'
            'SecRule ARGS "b" "id:2,pass"\n'
        )),
        2,
    )

    # ── Real-world CRS header pattern ────────────────────────
    real_world = (
        '# OWASP CRS header\n'
        '# Copyright ...\n'
        '\n'
        'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" '
        '"id:920011,phase:1,pass,nolog,skipAfter:END"\n'
        'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" '
        '"id:920012,phase:2,pass,nolog,skipAfter:END"\n'
        '\n'
        'SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \\\n'
        '    "id:920170,\\\n'
        '    phase:1,\\\n'
        '    chain"\n'
        '    SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" \\\n'
        '        "setvar:\'tx.score=+1\'"\n'
        '\n'
        'SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \\\n'
        '    "id:920171,\\\n'
        '    phase:1,\\\n'
        '    chain"\n'
        '    SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" \\\n'
        '        "setvar:\'tx.score=+1\'"\n'
    )
    check("real-world CRS pattern = 4 chunks (2 skip + 2 chains)", len(_parse_content(real_world)), 4)

    # ── Mixed SecRule and SecAction ──────────────────────────
    check(
        "SecAction between SecRules",
        len(_parse_content(
            'SecRule ARGS "a" "id:1,pass"\n'
            'SecAction "id:2,pass"\n'
            'SecRule ARGS "b" "id:3,pass"\n'
        )),
        3,
    )

    # ── Verify chain content integrity ───────────────────────
    print("\n--- Content Integrity Checks ---")
    chunks = _parse_content(
        'SecRule ARGS "parent" "id:1,chain"\n'
        '    SecRule ARGS "child" "pass"\n'
    )
    has_parent = "parent" in chunks[0]
    has_child = "child" in chunks[0]
    check("chain chunk contains parent", has_parent, True)
    check("chain chunk contains child", has_child, True)
    check("chain chunk has source prefix", chunks[0].startswith("[Source:"), True)

    # ── Summary ──────────────────────────────────────────────
    print()
    if all_passed:
        print("ALL EDGE CASE TESTS PASSED")
    else:
        print("SOME TESTS FAILED")


if __name__ == "__main__":
    run_tests()
