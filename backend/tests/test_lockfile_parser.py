import json

import pytest

from app.core.exceptions import LockfileParseError, UnsupportedLockfileVersionError
from app.graph.lockfile_parser import parse_lockfile
from tests.conftest import read_fixture


def test_parses_valid_lockfile_v3():
    parsed = parse_lockfile(read_fixture("simple", "package-lock.json"))
    assert parsed.lockfile_version == 3
    assert "node_modules/express" in parsed.packages
    assert parsed.packages["node_modules/express"]["version"] == "4.18.2"


def test_unsupported_lockfile_version_raises():
    raw = json.dumps({"lockfileVersion": 1, "packages": {}}).encode("utf-8")
    with pytest.raises(UnsupportedLockfileVersionError):
        parse_lockfile(raw)


def test_malformed_json_raises_lockfile_parse_error():
    with pytest.raises(LockfileParseError):
        parse_lockfile(b"{not valid json")


def test_missing_packages_key_raises():
    raw = json.dumps({"lockfileVersion": 3}).encode("utf-8")
    with pytest.raises(LockfileParseError):
        parse_lockfile(raw)


def test_missing_lockfile_version_raises():
    raw = json.dumps({"packages": {}}).encode("utf-8")
    with pytest.raises(LockfileParseError):
        parse_lockfile(raw)
