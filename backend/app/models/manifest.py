"""Internal representation of a parsed package.json.

Produced by `app.services.manifest_parser` and consumed by both the
lockfile resolver and the no-lockfile fallback resolver.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from app.models.dependency import DependencyCategory


@dataclass
class DeclaredDependency:
    """One dependency declared in package.json, before any resolution."""

    name: str
    version_range: str
    category: DependencyCategory


@dataclass
class ManifestData:
    project_name: str
    project_version: Optional[str]
    declared_dependencies: List[DeclaredDependency] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
