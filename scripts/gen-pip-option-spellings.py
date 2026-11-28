# SPDX-License-Identifier: Apache-2.0
# Round 34 (B1): generates src/__tests__/fixtures/a1125-pip-spellings.json from pip's own parser
# (optparse, which reads an unambiguous prefix of a long option as that option).
# Run with the pip whose parser is the reference: `python scripts/gen-pip-option-spellings.py`.
import json
import os

import pip
from pip._internal.commands import create_command
from pip._internal.cli.main_parser import create_main_parser

out = {"pip": pip.__version__, "source": "pip's optparse parsers (main and install)", "global": [], "install": []}


def spellings(parser):
    names = set()
    for opt in parser._get_all_options():
        for long in opt._long_opts:
            for n in range(3, len(long) + 1):
                names.add(long[:n])
        for short in opt._short_opts:
            names.add(short)
    return sorted(names)


def consumed(parser, opt):
    try:
        values, rest = parser.parse_args([opt, "zz-value", "install"])
    except SystemExit:
        return None
    except Exception:
        return None
    return rest[:1] != ["zz-value"]


main = create_main_parser()
for opt in spellings(main):
    c = consumed(main, opt)
    if c is not None:
        out["global"].append({"opt": opt, "consumed": c})
install = create_command("install").parser
for opt in spellings(install):
    c = consumed(install, opt)
    if c is not None:
        out["install"].append({"opt": opt, "consumed": c})
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "..", "src", "__tests__", "fixtures", "a1125-pip-spellings.json"), "w") as f:
    json.dump(out, f)
print(len(out["global"]), "global", len(out["install"]), "install", "pip", pip.__version__)
