"""
Unit tests for blindsqlx's core logic.

extract_string() and build_oracle() are both pure functions of a callback
(the oracle), so they're tested without ever touching the network: a fake
oracle below answers length/substring questions against a known in-memory
string, exactly the way a real boolean-blind SQLi target would answer them
through HTTP response differences.
"""

import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import blindsqlx


def fake_oracle_for(secret: str):
    """
    Builds an oracle that understands exactly the two expression shapes
    extract_string() generates, and answers them against `secret`,
    mirroring how a real target would respond true/false.
    """

    def oracle(expr: str) -> bool:
        if expr.startswith("length(("):
            # length((<inner>))=<N>
            n = int(expr.rsplit("=", 1)[1])
            return len(secret) == n
        if expr.startswith("unicode(substr(("):
            # unicode(substr((<inner>),<pos>,1))<=<mid>
            rest = expr[len("unicode(substr(("):]
            _inner, tail = rest.rsplit("),", 1)
            pos_str, cmp = tail.split(",1))<=")
            pos = int(pos_str)
            mid = int(cmp)
            return ord(secret[pos - 1]) <= mid
        raise ValueError(f"unexpected expression shape: {expr}")

    return oracle


@pytest.mark.parametrize(
    "secret",
    ["admin", "FLAG{t3st_3xtr4ct10n}", "a", "Zz!9 space", "unicode-ish ~"],
)
def test_extract_string_recovers_known_secret(secret):
    oracle = fake_oracle_for(secret)
    result = blindsqlx.extract_string(
        oracle, select_expr="irrelevant", max_len=64, verbose=False
    )
    assert result == secret


def test_extract_string_raises_when_length_not_found():
    # max_len too small to ever find a matching length -> should raise,
    # not silently return garbage.
    oracle = fake_oracle_for("a string longer than max_len allows")
    with pytest.raises(RuntimeError):
        blindsqlx.extract_string(oracle, select_expr="x", max_len=5, verbose=False)


def _args(**overrides):
    defaults = {
        "url": "http://target.test/item?id=INJECT",
        "method": "GET",
        "data": None,
        "true_marker": "OK",
        "false_marker": None,
        "prefix": "",
        "suffix": "",
        "collapse_spaces": False,
        "timeout": 5.0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@patch("blindsqlx.requests.request")
def test_oracle_true_marker_present_means_true(mock_request):
    mock_request.return_value = MagicMock(text="status: OK")
    oracle = blindsqlx.build_oracle(_args(true_marker="OK"))
    assert oracle("1=1") is True


@patch("blindsqlx.requests.request")
def test_oracle_true_marker_absent_means_false(mock_request):
    mock_request.return_value = MagicMock(text="status: nope")
    oracle = blindsqlx.build_oracle(_args(true_marker="OK"))
    assert oracle("1=2") is False


@patch("blindsqlx.requests.request")
def test_oracle_false_marker_inverts_logic(mock_request):
    # Only --false-marker given: true means the marker is ABSENT.
    mock_request.return_value = MagicMock(text="all good here")
    oracle = blindsqlx.build_oracle(_args(true_marker=None, false_marker="ERROR"))
    assert oracle("1=1") is True

    mock_request.return_value = MagicMock(text="an ERROR occurred")
    assert oracle("1=2") is False


@patch("blindsqlx.requests.request")
def test_oracle_injects_marker_into_url(mock_request):
    mock_request.return_value = MagicMock(text="OK")
    oracle = blindsqlx.build_oracle(_args(url="http://t.test/x?id=INJECT", true_marker="OK"))
    oracle("1=1")
    called_url = mock_request.call_args.args[1]
    assert "INJECT" not in called_url
    assert "1%3D1" in called_url or "1=1" in called_url


@patch("blindsqlx.requests.request")
def test_oracle_collapse_spaces_replaces_before_injection(mock_request):
    mock_request.return_value = MagicMock(text="OK")
    oracle = blindsqlx.build_oracle(
        _args(url="http://t.test/x?id=INJECT", true_marker="OK", collapse_spaces=True)
    )
    oracle("1 AND 1=1")
    called_url = mock_request.call_args.args[1]
    # the space should have become /**/ (then URL-encoded) before injection
    assert "%2F%2A%2A%2F" in called_url


@patch("blindsqlx.requests.request")
def test_oracle_substitutes_into_form_data(mock_request):
    mock_request.return_value = MagicMock(text="Welcome back")
    oracle = blindsqlx.build_oracle(
        _args(
            url="http://t.test/login",
            method="POST",
            data="username=INJECT&password=x",
            true_marker="Welcome back",
        )
    )
    assert oracle("admin' OR '1'='1") is True
    called_kwargs = mock_request.call_args.kwargs
    assert "INJECT" not in called_kwargs["data"]["username"]
