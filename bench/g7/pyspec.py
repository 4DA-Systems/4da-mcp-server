# SPDX-License-Identifier: Apache-2.0
"""PEP 440 helper for the G7 scorer. stdin: JSON list of {spec, versions, yanked}; stdout: JSON list of
{floor, max_sat, exact, matched_versions_count, canonical_floor} using pip's own `packaging` semantics."""
import json
import sys

from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion


def parse(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def one(q):
    spec = (q.get("spec") or "").strip()
    versions = [(v, parse(v)) for v in q["versions"]]
    versions = [(s, p) for s, p in versions if p is not None]
    yanked = set(q.get("yanked") or [])
    try:
        ss = SpecifierSet(spec)
    except InvalidSpecifier:
        return {"error": f"invalid specifier {spec!r}"}
    sat = [(s, p) for s, p in versions if p in ss]  # excludes prereleases unless the spec names one
    if not sat:
        sat = [(s, p) for s, p in versions if ss.contains(p, prereleases=True)]
    sat.sort(key=lambda x: x[1])
    sat_unyanked = [x for x in sat if x[0] not in yanked]
    exact = None
    specs = list(ss)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        exact = specs[0].version
    # the registry spelling of the exact version (2.31 == 2.31.0)
    exact_registry = None
    if exact is not None:
        pe = parse(exact)
        for s, p in versions:
            if pe is not None and p == pe:
                exact_registry = s
    lower_bounded = any(s.operator in ("==", "===", ">=", ">", "~=") for s in specs)
    return {
        "exact": exact,
        "exact_registry": exact_registry,
        "floor": (sat[0][0] if (sat and lower_bounded) else None),
        "max_sat": (sat_unyanked[-1][0] if sat_unyanked else (sat[-1][0] if sat else None)),
        "n_sat": len(sat),
        "lower_bounded": lower_bounded,
    }


def main():
    qs = json.load(sys.stdin)
    print(json.dumps([one(q) for q in qs]))


if __name__ == "__main__":
    main()
