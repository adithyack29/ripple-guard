"""Parses package.json into declared dependency information.

Only reads what Phase 1 needs: project identity and the three dependency
categories RippleGuard tracks (runtime, development, optional). Does not
resolve versions or transitive dependencies — that is the lockfile
resolver's job (`app.graph.lockfile_resolver`).
"""

import json
from typing import Any, Dict, Set, Tuple

from app.core.exceptions import ManifestParseError
from app.models.dependency import DependencyCategory
from app.models.manifest import DeclaredDependency, ManifestData

# Maps package.json keys to the DependencyCategory we assign. Order sets
# precedence: if a name is (unusually) declared in more than one list, the
# first matching category wins — "dependencies" beats "optionalDependencies"
# beats "devDependencies", since a package needed at runtime is never purely
# optional or dev-only regardless of what else declares it.
_CATEGORY_FIELDS: Tuple[Tuple[str, DependencyCategory], ...] = (
    ("dependencies", DependencyCategory.RUNTIME),
    ("optionalDependencies", DependencyCategory.OPTIONAL),
    ("devDependencies", DependencyCategory.DEVELOPMENT),
)


def parse_package_json(raw: bytes) -> ManifestData:
    """Parse raw package.json bytes into a ManifestData.

    Raises ManifestParseError if the content is not usable at all (not
    JSON, not a JSON object). Recoverable issues (missing name, non-string
    version, non-object dependency lists) are recorded as warnings instead
    of failing the request.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestParseError(f"package.json is not valid UTF-8: {exc}") from exc

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"package.json is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ManifestParseError("package.json must contain a JSON object at the top level")

    warnings = []

    project_name = data.get("name")
    if not isinstance(project_name, str) or not project_name.strip():
        warnings.append("package.json is missing a valid 'name' field; using 'unknown-project'")
        project_name = "unknown-project"

    project_version = data.get("version")
    if project_version is not None and not isinstance(project_version, str):
        warnings.append("package.json 'version' field is not a string; ignoring it")
        project_version = None

    declared = []
    seen_names: Set[str] = set()
    for field_name, category in _CATEGORY_FIELDS:
        deps = data.get(field_name)
        if deps is None:
            continue
        if not isinstance(deps, dict):
            warnings.append(f"package.json '{field_name}' is not an object; ignoring it")
            continue
        for name, version_range in deps.items():
            if name in seen_names:
                continue
            if not isinstance(version_range, str):
                warnings.append(
                    f"package.json dependency '{name}' in '{field_name}' has a non-string "
                    "version range; skipping it"
                )
                continue
            declared.append(
                DeclaredDependency(name=name, version_range=version_range, category=category)
            )
            seen_names.add(name)

    return ManifestData(
        project_name=project_name,
        project_version=project_version,
        declared_dependencies=declared,
        warnings=warnings,
    )
