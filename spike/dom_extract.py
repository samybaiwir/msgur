#!/usr/bin/env python3
"""Read a dumped DOM on stdin, print "<data-done>\t<textContent>" for an element id.
Used by spike/realpath.sh to read the headless-chromium dump-dom output."""
import sys
import re
import html

dom = sys.stdin.read()
elid = sys.argv[1]
m = re.search(r'<(\w+)\s+id="%s"([^>]*)>(.*?)</\1>' % re.escape(elid), dom, re.S)
if not m:
    print("MISSING\t")
    sys.exit(0)
attrs, inner = m.group(2), m.group(3)
done = re.search(r'data-done="([^"]*)"', attrs)
sys.stdout.write((done.group(1) if done else "NONE") + "\t" + html.unescape(inner))
