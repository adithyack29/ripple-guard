"""Loads and validates a package-lock.json file (lockfileVersion 2 or 3).

Only responsible for turning raw bytes into a validated `packages` dict.
Graph resolution (walking node_modules paths to build edges) happens in
`app.graph.lockfile_resolver`.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict

from app.core.exceptions import LockfileParseError, UnsupportedLockfileVersionError

# lockfileVersion 2/3 both use the flat "packages" map keyed by
# node_modules install path. lockfileVersion 1 used a nested
# "dependencies" tree instead and is not supported.
SUPPORTED_LOCKFILE_VERSIONS = (2, 3)


@dataclass
class ParsedLockfile:
    lockfile_version: int
    packages: Dict[str, Dict[str, Any]]


def parse_lockfile(raw: bytes) -> ParsedLockfile:
    """Parse raw package-lock.json bytes into a ParsedLockfile.

    Raises LockfileParseError for malformed/unusable JSON, and
    UnsupportedLockfileVersionError (a LockfileParseError subclass) for a
    lockfileVersion RippleGuard does not implement.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LockfileParseError(f"package-lock.json is not valid UTF-8: {exc}") from exc

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileParseError(f"package-lock.json is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise LockfileParseError("package-lock.json must contain a JSON object at the top level")

    lockfile_version = data.get("lockfileVersion")
    if not isinstance(lockfile_version, int):
        raise LockfileParseError("package-lock.json is missing a numeric 'lockfileVersion' field")

    if lockfile_version not in SUPPORTED_LOCKFILE_VERSIONS:
        raise UnsupportedLockfileVersionError(
            f"Unsupported lockfileVersion {lockfile_version}. RippleGuard currently "
            f"supports lockfileVersion {SUPPORTED_LOCKFILE_VERSIONS} (the 'packages'-based "
            "format used by npm 7+). Older lockfileVersion 1 files are not supported."
        )

    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise LockfileParseError(
            "package-lock.json does not contain a 'packages' object "
            "(expected for lockfileVersion 2/3)"
        )

    return ParsedLockfile(lockfile_version=lockfile_version, packages=packages)
