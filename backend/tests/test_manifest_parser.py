import pytest

from app.core.exceptions import ManifestParseError
from app.models.dependency import DependencyCategory
from app.services.manifest_parser import parse_package_json
from tests.conftest import read_fixture


def test_parses_declared_dependencies_by_category():
    manifest = parse_package_json(read_fixture("no_lockfile", "package.json"))

    by_name = {d.name: d for d in manifest.declared_dependencies}
    assert by_name["lodash"].category == DependencyCategory.RUNTIME
    assert by_name["lodash"].version_range == "^4.17.21"
    assert by_name["eslint"].category == DependencyCategory.DEVELOPMENT
    assert by_name["fsevents"].category == DependencyCategory.OPTIONAL
    assert manifest.project_name == "no-lockfile-app"
    assert manifest.project_version == "0.1.0"


def test_direct_dependency_identification_simple_fixture():
    manifest = parse_package_json(read_fixture("simple", "package.json"))
    names = {d.name for d in manifest.declared_dependencies}
    assert names == {"express", "axios", "jest"}
    assert manifest.project_name == "my-app"


def test_malformed_json_raises_manifest_parse_error():
    with pytest.raises(ManifestParseError):
        parse_package_json(read_fixture("invalid", "package.json"))


def test_non_object_top_level_raises():
    with pytest.raises(ManifestParseError):
        parse_package_json(b"[1, 2, 3]")


def test_missing_name_falls_back_with_warning():
    manifest = parse_package_json(b'{"dependencies": {"left-pad": "^1.0.0"}}')
    assert manifest.project_name == "unknown-project"
    assert any("name" in w for w in manifest.warnings)


def test_duplicate_name_across_categories_prefers_runtime():
    raw = b"""
    {
      "name": "conflicted",
      "dependencies": {"shared-pkg": "^1.0.0"},
      "devDependencies": {"shared-pkg": "^2.0.0"}
    }
    """
    manifest = parse_package_json(raw)
    matches = [d for d in manifest.declared_dependencies if d.name == "shared-pkg"]
    assert len(matches) == 1
    assert matches[0].category == DependencyCategory.RUNTIME
    assert matches[0].version_range == "^1.0.0"
