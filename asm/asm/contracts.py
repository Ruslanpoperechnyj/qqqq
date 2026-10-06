"""Typed contracts for scan orchestration and external payload boundaries.

The project still stores and exchanges legacy dictionaries. These models provide
an explicit validation/adaptation layer without dropping unknown fields or
changing the existing JSON/SQLite shapes.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Generic, TypeVar

from .settings import Settings


class ContractError(ValueError):
    """A boundary payload does not match its documented object shape."""


class StageStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_RUN = "not_run"


T = TypeVar("T")


@dataclass(frozen=True)
class StageResult(Generic[T]):
    """Outcome envelope for one pipeline stage.

    ``value`` remains in its existing legacy form during migration. ``issues``
    carries non-fatal notes; a failed result never masquerades as an empty value.
    """

    status: StageStatus
    value: T | None = None
    issues: tuple[str, ...] = ()
    error: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, StageStatus):
            raise ContractError("stage.status: неизвестный статус")
        if not isinstance(self.issues, tuple) or any(not isinstance(x, str) for x in self.issues):
            raise ContractError("stage.issues: ожидался кортеж строк")
        if not isinstance(self.error, str):
            raise ContractError("stage.error: ожидалась строка")
        if self.status is StageStatus.FAILED and not self.error:
            raise ContractError("stage.failed: нужна причина ошибки")
        if self.status is not StageStatus.FAILED and self.error:
            raise ContractError("stage.error допустим только для failed")
        if self.status is StageStatus.NOT_RUN and self.value is not None:
            raise ContractError("stage.not_run: результат не должен содержать value")

    @classmethod
    def ok(cls, value: T | None = None) -> StageResult[T]:
        return cls(StageStatus.OK, value=value)

    @classmethod
    def partial(cls, value: T | None = None, *,
                issues: tuple[str, ...] = ()) -> StageResult[T]:
        return cls(StageStatus.PARTIAL, value=value, issues=issues)

    @classmethod
    def failed(cls, error: str, *, value: T | None = None,
               issues: tuple[str, ...] = ()) -> StageResult[T]:
        return cls(StageStatus.FAILED, value=value, issues=issues, error=error)

    @classmethod
    def not_run(cls, *, reason: str = "") -> StageResult[None]:
        issues = (reason,) if reason else ()
        return cls(StageStatus.NOT_RUN, issues=issues)



def _mapping_snapshot(payload: object, name: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError(f"{name}: ожидался объект")
    if any(not isinstance(key, str) for key in payload):
        raise ContractError(f"{name}: ключи должны быть строками")
    return MappingProxyType(dict(payload))


def _optional_string(payload: Mapping[str, Any], key: str, name: str) -> str | None:
    value = payload.get(key)
    if value is not None and not isinstance(value, str):
        raise ContractError(f"{name}.{key}: ожидалась строка")
    return value


@dataclass(frozen=True)
class Asset:
    """An asset payload; unknown fields are retained for lossless adaptation."""

    kind: str
    value: str
    meta: Mapping[str, Any]
    payload: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_legacy(cls, payload: object) -> Asset:
        raw = _mapping_snapshot(payload, "asset")
        kind = raw.get("kind")
        value = raw.get("value")
        meta = raw.get("meta", {})
        if not isinstance(kind, str) or not kind:
            raise ContractError("asset.kind: ожидалась непустая строка")
        if not isinstance(value, str):
            raise ContractError("asset.value: ожидалась строка")
        if not isinstance(meta, Mapping):
            raise ContractError("asset.meta: ожидался объект")
        return cls(kind=kind, value=value, meta=MappingProxyType(dict(meta)), payload=raw)

    def to_legacy(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(frozen=True)
class Finding:
    """A finding payload with validated common scalar fields and retained extras."""

    asset: str | None
    title: str | None
    severity: str | None
    payload: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_legacy(cls, payload: object) -> Finding:
        raw = _mapping_snapshot(payload, "finding")
        asset = _optional_string(raw, "asset", "finding")
        title = _optional_string(raw, "title", "finding")
        severity = _optional_string(raw, "severity", "finding")
        port = raw.get("port")
        if port is not None and (type(port) is not int and not isinstance(port, str)):
            raise ContractError("finding.port: ожидалось целое число или строка")
        for key in ("cvss", "epss", "score"):
            number = raw.get(key)
            if number is not None and (type(number) not in (int, float)):
                raise ContractError(f"finding.{key}: ожидалось число")
        return cls(asset=asset, title=title, severity=severity, payload=raw)

    def to_legacy(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(frozen=True)
class ProbeResult:
    """HTTP/TLS probe output, including provider-specific unknown fields."""

    url: str | None
    status: int | str | None
    error: str | None
    payload: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_legacy(cls, payload: object) -> ProbeResult:
        raw = _mapping_snapshot(payload, "probe_result")
        url = _optional_string(raw, "url", "probe_result")
        error = _optional_string(raw, "error", "probe_result")
        status = raw.get("status")
        if status is not None and type(status) is not int and not isinstance(status, str):
            raise ContractError("probe_result.status: ожидалось целое число или строка")
        return cls(url=url, status=status, error=error, payload=raw)

    def to_legacy(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(frozen=True)
class Step:
    """Planner/agent step payload; supports planner and persisted-row spellings."""

    action: str | None
    title: str | None
    status: str | None
    payload: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_legacy(cls, payload: object) -> Step:
        raw = _mapping_snapshot(payload, "step")
        action_key = "action" if "action" in raw else "action_id"
        action = _optional_string(raw, action_key, "step") if action_key in raw else None
        title = _optional_string(raw, "title", "step")
        status = _optional_string(raw, "status", "step")
        params = raw.get("params")
        if params is not None and not isinstance(params, Mapping):
            raise ContractError("step.params: ожидался объект")
        return cls(action=action, title=title, status=status, payload=raw)

    def to_legacy(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass
class ScanContext:
    """Mutable state owned by one scan; its ``settings`` is an immutable snapshot."""

    scan_id: int
    target: Mapping[str, Any]
    root: str
    is_ip: bool
    settings: Settings
    assets: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    ip_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    raw_cve: list[dict[str, Any]] = field(default_factory=list)
    engine_counts: dict[str, int] = field(default_factory=dict)
    engine_findings: list[dict[str, Any]] = field(default_factory=list)
    engines_status: dict[str, Any] = field(default_factory=dict)
    stage_results: dict[str, StageResult[Any]] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.scan_id) is not int or self.scan_id < 0:
            raise ContractError("scan_context.scan_id: ожидалось неотрицательное целое")
        if not isinstance(self.target, Mapping) or any(not isinstance(k, str) for k in self.target):
            raise ContractError("scan_context.target: ожидался объект")
        object.__setattr__(self, "target", MappingProxyType(dict(self.target)))
        if not isinstance(self.root, str) or type(self.is_ip) is not bool:
            raise ContractError("scan_context.target: неверный root/is_ip")
        if not isinstance(self.settings, Settings):
            raise ContractError("scan_context.settings: ожидался Settings")
        for name in ("assets", "edges", "raw_cve", "engine_findings"):
            if not isinstance(getattr(self, name), list):
                raise ContractError(f"scan_context.{name}: ожидался список")
        for name in ("ip_meta", "engine_counts", "engines_status", "stage_results", "values"):
            if not isinstance(getattr(self, name), dict):
                raise ContractError(f"scan_context.{name}: ожидался объект")
        if any(not isinstance(k, str) or type(v) is not int
               for k, v in self.engine_counts.items()):
            raise ContractError("scan_context.engine_counts: неверный тип")
        if any(not isinstance(k, str) or not isinstance(v, StageResult)
               for k, v in self.stage_results.items()):
            raise ContractError("scan_context.stage_results: неверный тип")

    def record_stage(self, name: str, result: StageResult[Any]) -> None:
        if not isinstance(name, str) or not name:
            raise ContractError("stage.name: ожидалась непустая строка")
        if not isinstance(result, StageResult):
            raise ContractError("stage.result: ожидался StageResult")
        self.stage_results[name] = result
