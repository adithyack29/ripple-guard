import pytest

from app.core.exceptions import ManifestParseError, UnsupportedLockfileVersionError
from app.models.dependency import DependencyRelation, ResolutionStatus
from app.services.analysis_service import analyze_project
from tests.conftest import read_fixture


@pytest.mark.asyncio
async def test_simple_with_lockfile_is_fully_resolved():
    result = await analyze_project(
        read_fixture("simple", "package.json"),
        read_fixture("simple", "package-lock.json"),
    )

    assert result.resolution_status == ResolutionStatus.LOCKFILE_RESOLVED
    assert result.statistics.direct_dependencies == 3
    assert result.statistics.transitive_dependencies == 4
    assert result.statistics.total_dependencies == 7
    assert result.statistics.max_depth == 3
    assert result.unresolved_dependencies == []


@pytest.mark.asyncio
async def test_no_lockfile_falls_back_to_direct_only():
    result = await analyze_project(read_fixture("no_lockfile", "package.json"), None)

    assert result.resolution_status == ResolutionStatus.DIRECT_DEPENDENCIES_ONLY
    assert result.statistics.transitive_dependencies == 0
    assert result.statistics.direct_dependencies == 4  # lodash, chalk, eslint, fsevents
    relations = {n.relation for n in result.graph.nodes if n.relation != DependencyRelation.ROOT}
    assert relations == {DependencyRelation.DIRECT}
    assert any("No package-lock.json" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_invalid_manifest_raises():
    with pytest.raises(ManifestParseError):
        await analyze_project(read_fixture("invalid", "package.json"), None)


@pytest.mark.asyncio
async def test_unsupported_lockfile_version_raises():
    with pytest.raises(UnsupportedLockfileVersionError):
        await analyze_project(
            read_fixture("simple", "package.json"),
            b'{"lockfileVersion": 1, "packages": {}}',
        )


@pytest.mark.asyncio
async def test_duplicate_versions_preserved_end_to_end():
    result = await analyze_project(
        read_fixture("duplicate_versions", "package.json"),
        read_fixture("duplicate_versions", "package-lock.json"),
    )
    lodash_ids = {n.id for n in result.graph.nodes if n.name == "lodash"}
    assert lodash_ids == {"lodash@4.17.21", "lodash@4.17.20"}
    assert result.statistics.total_dependencies == 4


@pytest.mark.asyncio
async def test_category_breakdown_sums_to_total():
    result = await analyze_project(
        read_fixture("simple", "package.json"),
        read_fixture("simple", "package-lock.json"),
    )
    assert sum(result.statistics.category_breakdown.values()) == result.statistics.total_dependencies
