# SPDX-License-Identifier: Apache-2.0
# Round 35 (C2, C3): generates two fixtures from pip's own readers, for the hook's differential tests.
#   src/__tests__/fixtures/a1125-pip-clusters.json: every 2- and 3-letter cluster of pip install's
#     short letters, as pip's optparse reads it before a word (does it parse, does it take that word).
#   src/__tests__/fixtures/a1125-pip-reqfiles.json: requirements-file variants and what pip's
#     req_file reader reads from each (requirements, index, extra index, pre).
# Run with the pip whose readers are the reference: `python -I scripts/gen-pip-clusters-and-reqfiles.py`.
import itertools
import json
import optparse
import os
import tempfile

import pip
from pip._internal.commands import create_command
from pip._internal.network.session import PipSession
from pip._internal.req.req_file import parse_requirements

here = os.path.dirname(os.path.abspath(__file__))
fixtures = os.path.join(here, "..", "src", "__tests__", "fixtures")

# Clusters.
install = create_command("install").parser
letters = {}
for opt in install._get_all_options():
    for short in opt._short_opts:
        letters[short[1]] = opt.takes_value()
clusters = []
for n in (2, 3):
    for combo in itertools.product(sorted(letters), repeat=n):
        word = "-" + "".join(combo)
        try:
            values, rest = install.parse_args([word, "zz-next"])
            ok = True
            consumed = rest[:1] != ["zz-next"]
        except SystemExit:
            ok = False
            consumed = None
        clusters.append({"word": word, "ok": ok, "consumed": consumed})
with open(os.path.join(fixtures, "a1125-pip-clusters.json"), "w") as f:
    json.dump({"pip": pip.__version__, "source": "pip install's optparse parser", "letters": letters, "clusters": clusters}, f)

# Requirements files.
B = "requests==2.19.0"
A64 = "a" * 64
B64 = "b" * 64
V = []


def v(name, text):
    V.append({"name": name, "text": text})


for nl, t in (("\n", "lf"), ("\r\n", "crlf")):
    v(f"plain-{t}", f"six==1.16.0{nl}{B}{nl}")
    v(f"cont-name-{t}", f"requests\\{nl}==2.19.0{nl}")
    v(f"cont-op-{t}", f"requests==\\{nl}2.19.0{nl}")
    v(f"cont-space-{t}", f"requests \\{nl}  ==2.19.0{nl}")
    v(f"comment-bs-{t}", f"# note \\{nl}{B}{nl}")
    v(f"comment-indent-bs-{t}", f"   # note \\{nl}{B}{nl}")
    v(f"comment-tab-bs-{t}", f"\t# note \\{nl}{B}{nl}")
    v(f"comment-bs-bs-{t}", f"# note \\{nl}# more \\{nl}{B}{nl}")
    v(f"trail-comment-bs-{t}", f"six==1.16.0 # c \\{nl}{B}{nl}")
    v(f"cont-then-comment-{t}", f"six==1.16.0 \\{nl}# c{nl}{B}{nl}")
    v(f"cont-then-comment-bs-{t}", f"six==1.16.0 \\{nl}# c \\{nl}{B}{nl}")
    v(f"trail-comment-{t}", f"{B} # pinned{nl}")
    v(f"trail-comment-tab-{t}", f"{B}\t# pinned{nl}")
    v(f"glued-hash-{t}", f"six==1.16.0#x{nl}{B}{nl}")
    v(f"marker-{t}", f'{B}; python_version >= "3"{nl}')
    v(f"marker-false-{t}", f'{B} ; python_version < "3"{nl}')
    v(f"marker-space-{t}", f'requests == 2.19.0 ;python_version>"3"{nl}')
    v(f"extras-{t}", f"requests[socks]==2.19.0{nl}")
    v(f"extras-space-{t}", f"requests [socks] == 2.19.0{nl}")
    v(f"hash-{t}", f"{B} --hash=sha256:{A64}{nl}")
    v(f"hash-cont-{t}", f"{B} \\{nl}    --hash=sha256:{A64} \\{nl}    --hash=sha256:{B64}{nl}")
    v(f"envvar-{t}", f"requests==${{REQV}}{nl}")
    v(f"envvar-name-{t}", f"${{REQN}}==2.19.0{nl}")
    v(f"include-{t}", f"-r bad.txt{nl}")
    v(f"include-glued-{t}", f"-rbad.txt{nl}")
    v(f"include-long-{t}", f"--requirement bad.txt{nl}")
    v(f"include-long-eq-{t}", f"--requirement=bad.txt{nl}")
    v(f"include-comment-{t}", f"-r bad.txt # inc{nl}")
    v(f"include-cont-{t}", f"-r \\{nl}bad.txt{nl}")
    v(f"index-{t}", f"--index-url https://pypi.org/simple{nl}{B}{nl}")
    v(f"extra-{t}", f"--extra-index-url http://127.0.0.1:9/simple{nl}six==1.16.0{nl}")
    v(f"pre-{t}", f"--pre{nl}six==1.16.0{nl}")
    v(f"pre-cont-{t}", f"six==1.16.0 \\{nl}--pre{nl}")
    v(f"blank-lines-{t}", f"{nl}{nl}   {nl}{B}{nl}")
    v(f"leading-space-{t}", f"   {B}{nl}")
    v(f"tab-{t}", f"\t{B}{nl}")
    v(f"upper-{t}", f"Requests==2.19.0{nl}")
    v(f"paren-{t}", f"requests (==2.19.0){nl}")
    v(f"arbitrary-{t}", f"requests===2.19.0{nl}")
    v(f"compat-{t}", f"requests~=2.19.0{nl}")
    v(f"wild-{t}", f"requests==2.19.*{nl}")
    v(f"le-{t}", f"requests<=2.19.0{nl}")
    v(f"two-{t}", f"requests>=2.0,<=2.19.0{nl}")
    v(f"epoch-{t}", f"requests==0!2.19.0{nl}")
    v(f"zero-pad-{t}", f"requests==2.19{nl}")
    v(f"noeol-{t}", f"six==1.16.0{nl}{B}")
    v(f"trailing-bs-eof-{t}", f"{B}\\")
    v(f"trailing-bs-blank-{t}", f"{B}\\{nl}{nl}")
    v(f"double-bs-{t}", f"requests\\\\{nl}==2.19.0{nl}")
    v(f"leading-bs-{t}", f"requests==\\{nl}\\2.19.0{nl}")
    v(f"bs-space-{t}", f"requests==\\ {nl}2.19.0{nl}")
    v(f"semicolon-{t}", f"six==1.16.0;{B}{nl}")
    v(f"two-on-line-{t}", f"six==1.16.0 {B}{nl}")
    v(f"cont-three-{t}", f"req\\{nl}uests\\{nl}==2.19.0{nl}")
    v(f"comment-only-{t}", f"# requests==2.19.0{nl}six==1.16.0{nl}")
    v(f"comment-cont-{t}", f"#\\{nl}{B}{nl}")
    v(f"hash-in-name-{t}", f"requests==2.19.0#frag{nl}")
    v(f"spaces-then-hash-{t}", f"six==1.16.0    #   \\{nl}{B}{nl}")
    v(f"cont-before-blank-{t}", f"six==1.16.0 \\{nl}{nl}{B}{nl}")
    v(f"cont-into-option-{t}", f"--pre \\{nl}{B}{nl}")
    v(f"plain-proceed-{t}", f"six==1.16.0{nl}")
    v(f"cont-proceed-{t}", f"six\\{nl}==1.16.0{nl}")
v("bom8", "﻿" + B + "\n")
v("cr-only", "six==1.16.0\r" + B + "\r")
v("ff", "six==1.16.0\f" + B + "\n")
v("vt", "six==1.16.0\v" + B + "\n")
v("nel", "six==1.16.0\u0085" + B + "\n")
v("ls", "six==1.16.0 " + B + "\n")
v("coding-latin1", "# -*- coding: latin-1 -*-\n" + B + "\n")
v("coding-utf8", "# -*- coding: utf-8 -*-\n" + B + "\n")

os.environ["REQV"] = "2.19.0"
os.environ["REQN"] = "requests"
session = PipSession()
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "bad.txt"), "w") as f:
        f.write(B + "\n")
    for x in V:
        path = os.path.join(d, "r.txt")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(x["text"])
        opts = optparse.Values({"index_url": None, "extra_index_urls": [], "find_links": [], "pre": False, "format_control": None, "features_enabled": [], "require_hashes": False, "trusted_hosts": [], "prefer_binary": False})
        try:
            reqs = [pr.requirement for pr in parse_requirements(path, session=session, options=opts, constraint=False)]
            x["pip"] = {"reqs": reqs, "index": opts.index_url, "extra": opts.extra_index_urls, "pre": opts.pre}
        except BaseException as e:
            x["pip"] = {"error": type(e).__name__}
with open(os.path.join(fixtures, "a1125-pip-reqfiles.json"), "w") as f:
    json.dump({"pip": pip.__version__, "source": "pip's req_file.parse_requirements", "env": {"REQV": "2.19.0", "REQN": "requests"}, "variants": V}, f)
print(len(clusters), "clusters,", len(V), "requirements variants, pip", pip.__version__)
