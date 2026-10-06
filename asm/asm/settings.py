"""Типизированная схема и неизменяемый snapshot настроек ASM.

Схема охватывает scan- и активные non-secret runtime consumers; выбор
источников остаётся обязанностью вызывающей стороны. Модуль намеренно не
читает и не меняет ``os.environ``: при сборке snapshot передаются mappings с
явными overrides и mode preset. Учётные данные и другие исключённые secret
paths в схему не попадают и сохраняют прежний путь чтения.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field, fields
from types import MappingProxyType


class SettingsError(ValueError):
    """Настройка отсутствует в схеме или не соответствует своему контракту."""


# Scan-настройки со стабильными legacy-именами выделены в собственные поля;
# остальные активные non-secret настройки описаны в _CONFIG_SPECS ниже.
_SCAN_ENV_TO_FIELD = {
    "ASM_MAX_SUBDOMAINS": "max_subdomains",
    "ASM_MAX_IPS": "max_ips",
    "ASM_MAX_PROBES": "max_probes",
    "ASM_MAX_CPES": "max_cpes",
    "ASM_WORKERS": "workers",
    "ASM_ACTIVE_SCAN": "active_scan",
    "ASM_MAX_ACTIVE_TARGETS": "max_active_targets",
    "ASM_ESTATE": "estate",
    "ASM_ESTATE_WORDS": "estate_words",
    "ASM_ESTATE_MAX_HOSTS": "estate_max_hosts",
    "ASM_ESTATE_ASN": "estate_asn",
    "ASM_ESTATE_MAX_PREFIXES": "estate_max_prefixes",
    "ASM_ESTATE_PREFIX_IPS": "estate_prefix_ips",
    "ASM_ESTATE_MAX_EXTRA_IPS": "estate_max_extra_ips",
    "ASM_ENGINES": "engines",
    "ASM_ENGINE_CRAWL": "engine_crawl",
    "ASM_ENGINE_ARCHIVES": "engine_archives",
    "ASM_FFUF": "deep_paths",
}

_FIELD_TO_ENV = {field_name: env_name
                 for env_name, field_name in _SCAN_ENV_TO_FIELD.items()}
_SCAN_ALIASES = {
    **_SCAN_ENV_TO_FIELD,
    **{field_name: field_name for field_name in _FIELD_TO_ENV},
}
_INTEGER_FIELDS = frozenset({
    "max_subdomains", "max_ips", "max_probes", "max_cpes", "workers",
    "max_active_targets", "estate_words", "estate_max_hosts",
    "estate_max_prefixes", "estate_prefix_ips", "estate_max_extra_ips",
})
_BOOLEAN_FIELDS = frozenset({
    "active_scan", "estate", "estate_asn", "engines", "engine_crawl",
    "engine_archives", "deep_paths",
})
_TRUE_STRINGS = frozenset({"1", "true", "yes", "on"})
_FALSE_STRINGS = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class _ConfigSpec:
    domain: str
    kind: str
    default: object
    minimum: int | float | None = None
    choices: frozenset[str] = frozenset()


def _config_spec(domain: str, kind: str, default: object, *,
                 minimum: int | float | None = None,
                 choices: Iterable[str] = ()) -> _ConfigSpec:
    return _ConfigSpec(domain, kind, default, minimum, frozenset(choices))


# Static, non-secret settings registry. Secret material and the explicitly
# waived secret/code-scan paths are deliberately absent; ASM_DB remains a
# bootstrap-only input consumed by store before operation Settings exist.
_CONFIG_SPECS: dict[str, _ConfigSpec] = {
    # mode / engine policy
    "ASM_PROFILE": _config_spec("engines", "lower", "safe"),
    "ASM_PLANNER": _config_spec("planner", "lower", "rules"),
    "ASM_STEALTH": _config_spec("stealth", "lower", "off"),
    "ASM_QUEUE_IMPACT": _config_spec("planner", "bool", True),
    "ASM_ACTIVE_TIMEOUT": _config_spec("active", "int", 600, minimum=1),
    "ASM_NAABU_BIN": _config_spec("active", "str", "naabu"),
    "ASM_NUCLEI_BIN": _config_spec("active", "str", "nuclei"),
    "ASM_SUBFINDER_BIN": _config_spec("engines", "str", "subfinder"),
    "ASM_AMASS_BIN": _config_spec("engines", "str", "amass"),
    "ASM_DNSX_BIN": _config_spec("engines", "str", "dnsx"),
    "ASM_HTTPX_BIN": _config_spec("engines", "str", "httpx"),
    "ASM_TLSX_BIN": _config_spec("engines", "str", "tlsx"),
    "ASM_TESTSSL_BIN": _config_spec("engines", "str", "testssl.sh"),
    "ASM_KATANA_BIN": _config_spec("engines", "str", "katana"),
    "ASM_GAU_BIN": _config_spec("engines", "str", "gau"),
    "ASM_FFUF_BIN": _config_spec("engines", "str", "ffuf"),
    "ASM_NMAP_BIN": _config_spec("engines", "str", "nmap"),
    "ASM_NIKTO_PL_BIN": _config_spec("engines", "str", "nikto.pl"),
    "ASM_OSV_SCANNER_BIN": _config_spec("engines", "str", "osv-scanner"),
    "ASM_WAPITI_BIN": _config_spec("engines", "str", "wapiti"),
    "ASM_NUCLEI_TEMPLATES": _config_spec("active", "str", None),
    "ASM_NUCLEI_EXCLUDE_TAGS": _config_spec(
        "active", "str", "dos,fuzz,intrusive,brute-force"),
    "ASM_NUCLEI_TAGS": _config_spec("active", "str", None),
    "ASM_NUCLEI_SEVERITY": _config_spec("active", "str", None),
    "ASM_NUCLEI_RATE": _config_spec("engines", "optional_rate", None, minimum=0),
    "ASM_NAABU_TOP_PORTS": _config_spec("active", "int", 1000, minimum=0),
    "ASM_NAABU_TIMEOUT": _config_spec("active", "int", 240, minimum=1),
    "ASM_NUCLEI_TIMEOUT": _config_spec("active", "int", 900, minimum=1),
    "ASM_NAABU_RATE": _config_spec("engines", "optional_rate", None, minimum=0),
    "ASM_HTTPX_RATE": _config_spec("engines", "optional_rate", None, minimum=0),
    "ASM_KATANA_RATE": _config_spec("engines", "optional_rate", None, minimum=0),
    "ASM_NMAP_RATE": _config_spec("engines", "optional_rate", None, minimum=0),
    "ASM_FFUF_RATE": _config_spec("engines", "optional_rate", None, minimum=0),
    "ASM_RATE_SPREAD": _config_spec("engines", "float", 0.2, minimum=0),
    "ASM_NUCLEI_CONCURRENCY": _config_spec("engines", "int", 25, minimum=1),
    "ASM_NIKTO_TUNING": _config_spec("engines", "str", None),
    "ASM_WAPITI_MODULES": _config_spec("engines", "str", None),
    "ASM_TOOLS_DIR": _config_spec("engines", "str", None),
    "ASM_WORDLISTS": _config_spec("engines", "str", None),
    "ASM_REMOTE_SSH": _config_spec("engines", "str", ""),
    "ASM_STOP_POLL": _config_spec("engines", "float", 2.0, minimum=0),
    "ASM_BASH_BIN": _config_spec("engines", "str", ""),
    "ASM_PERL_BIN": _config_spec("engines", "str", ""),
    # explicitly non-secret stealth settings; proxy/SOCKS endpoints are excluded
    "ASM_COVER": _config_spec("stealth", "lower", ""),
    "ASM_STEALTH_PATCH_ENGINES": _config_spec("stealth", "bool", True),
    "ASM_UA": _config_spec("stealth", "str", ""),
    "ASM_TLS_FINGERPRINT": _config_spec("stealth", "lower", "auto"),
    "ASM_STEALTH_JITTER": _config_spec("stealth", "float", 0.0, minimum=0),
    # planner / agent policy (execution and approval gates stay in gate/agent)
    "ASM_SCOPE": _config_spec("agent", "str", ""),
    "ASM_MODEL_CMDS": _config_spec("agent", "lower", "auto"),
    "ASM_AUTO_LEARN": _config_spec("agent", "str", "1"),
    # source selection / pacing
    "ASM_SOURCES": _config_spec("sources", "str", ""),
    "ASM_SOURCES_EXTRA": _config_spec("sources", "str", ""),
    "ASM_SOURCES_OFF": _config_spec("sources", "str", ""),
    "ASM_SOURCES_PAUSE": _config_spec("sources", "float", 0.35, minimum=0),
    "ASM_SUBFINDER_LIMIT": _config_spec("sources", "int", 300, minimum=0),
    "ASM_AMASS": _config_spec("sources", "str", "0"),
    "ASM_AMASS_TIMEOUT": _config_spec("sources", "int", 240, minimum=1),
    "ASM_PTR_RECON_MAX": _config_spec("sources", "int", 5, minimum=0),
    "ASM_DNSX_LIMIT": _config_spec("sources", "int", 500, minimum=0),
    # fact verification network policy (the network allowlist remains in code)
    "ASM_FACTS_NET": _config_spec(
        "facts", "enum", "cache", choices=("off", "cache", "allow")),
    "ASM_FACTS_MAX_AGE": _config_spec("facts", "int", 7, minimum=1),
    # non-secret model/runtime selectors; credentials remain on their old path
    "ASM_LLM_BASE": _config_spec("model", "str", ""),
    "ASM_LLM_MODEL": _config_spec("model", "str", None),
    "ASM_LLM_STYLE": _config_spec("model", "lower", ""),
    "ASM_LLM_TEMPERATURE": _config_spec("model", "float", 0.2),
    "ASM_LLM_NUM_CTX": _config_spec("model", "int", 8192, minimum=1),
    "ASM_LLM_MOCK": _config_spec("model", "str", ""),
    "ASM_LLM_RETRIES": _config_spec("model", "int", 15, minimum=1),
    "ASM_LLM_RETRY_BUDGET": _config_spec("model", "float", 600.0, minimum=1),
    "ASM_LLM_RETRY_PAUSE": _config_spec("model", "float", 1.0, minimum=0),
    "ASM_LLM_TIMEOUT": _config_spec("model", "int", 60, minimum=1),
    "ASM_CLOUD_BASE": _config_spec("model", "str", ""),
    "ASM_CLOUD_EFFORT": _config_spec("model", "lower", "medium"),
    "ASM_CLOUD_MAX_TOKENS": _config_spec("model", "int", 32768, minimum=1),
    # non-secret transport controls; key/password remain on their legacy path
    "ASM_INWARD": _config_spec("transport", "lower", "on"),
    "ASM_INWARD_METHOD": _config_spec("transport", "lower", "auto"),
    "ASM_INWARD_PORT": _config_spec("transport", "str", ""),
    "ASM_INWARD_TIMEOUT": _config_spec("transport", "int", 180, minimum=1),
    "ASM_INWARD_PULL": _config_spec("transport", "bool", False),
    # runtime and local paths
    "ASM_PORT": _config_spec("runtime", "int", 8000, minimum=1),
    "ASM_VERBOSE": _config_spec("runtime", "str", ""),
    "ASM_HTTP_TIMEOUT": _config_spec("runtime", "int", 15, minimum=1),
    "ASM_MATERIALS": _config_spec("runtime", "str", None),
    "ASM_DRAFT_DIR": _config_spec("runtime", "str", ""),
    "ASM_KB_DIR": _config_spec("runtime", "str", None),
    "ASM_VECTOR_DIM": _config_spec("runtime", "int", 384, minimum=1),
    "ASM_EMBED_MODEL": _config_spec(
        "runtime", "str", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"),
    "ASM_EMBED": _config_spec("runtime", "lower", "auto"),
    "ASM_EMBED_MIN_GB": _config_spec("runtime", "float", 1.5, minimum=0),
    "ASM_PYLIBS": _config_spec("runtime", "str", None),
    "ASM_KATANA_DEPTH": _config_spec("stages", "int", 2, minimum=0),
    "ASM_KATANA_LIMIT": _config_spec("stages", "int", 200, minimum=0),
    "ASM_KATANA_TIMEOUT": _config_spec("stages", "int", 180, minimum=1),
    "ASM_KATANA_URLS": _config_spec("stages", "int", 8, minimum=0),
    "ASM_GAU_LIMIT": _config_spec("stages", "int", 300, minimum=0),
    "ASM_GAU_TIMEOUT": _config_spec("stages", "int", 120, minimum=1),
    "ASM_MAX_URLS": _config_spec("stages", "int", 400, minimum=0),
    "ASM_FFUF_TIMEOUT": _config_spec("stages", "int", 180, minimum=1),
    "ASM_TLSX_LIMIT": _config_spec("stages", "int", 80, minimum=0),
    "ASM_TLSX_TIMEOUT": _config_spec("stages", "int", 180, minimum=1),
    "ASM_NIKTO": _config_spec("stages", "str", "1"),
    "ASM_NIKTO_URLS": _config_spec("stages", "int", 2, minimum=0),
    "ASM_NIKTO_TIMEOUT": _config_spec("stages", "int", 180, minimum=1),
    "ASM_NIKTO_MAXTIME": _config_spec("stages", "str", "90s"),
    "ASM_WAPITI": _config_spec("stages", "str", "1"),
    "ASM_WAPITI_URLS": _config_spec("stages", "int", 1, minimum=0),
    "ASM_WAPITI_TIMEOUT": _config_spec("stages", "int", 300, minimum=1),
    "ASM_WAPITI_MAXTIME": _config_spec("stages", "int", 90, minimum=1),
    "ASM_TESTSSL": _config_spec("stages", "str", "1"),
    "ASM_TESTSSL_HOSTS": _config_spec("stages", "int", 2, minimum=0),
    "ASM_TESTSSL_TIMEOUT": _config_spec("stages", "int", 240, minimum=1),
    "ASM_NMAP_HOSTS": _config_spec("stages", "int", 3, minimum=0),
    "ASM_NMAP_PORTS": _config_spec("stages", "int", 40, minimum=0),
    "ASM_NMAP_TOP": _config_spec("stages", "optional_int", None, minimum=0),
    "ASM_NMAP_TIMEOUT": _config_spec("stages", "int", 240, minimum=1),
    "ASM_MAX_HTTPX": _config_spec("stages", "int", 300, minimum=0),
    "ASM_HTTPX_TIMEOUT": _config_spec("stages", "int", 420, minimum=1),
}
_CONFIG_FIELD_TO_ENV = {
    key.removeprefix("ASM_").lower(): key for key in _CONFIG_SPECS
}
_CONFIG_ENV_KEYS = frozenset(_CONFIG_SPECS)


def _parse_config_value(name: str, raw: object, source: str) -> object:
    spec = _CONFIG_SPECS[name]
    if raw is None and spec.default is None:
        return None
    if spec.kind == "str":
        if isinstance(raw, str):
            return raw
        raise SettingsError(f"{name}: ожидалась строка (источник: {source})")
    if spec.kind == "lower":
        if isinstance(raw, str):
            return raw.strip().lower()
        raise SettingsError(f"{name}: ожидалась строка (источник: {source})")
    if spec.kind == "enum":
        if not isinstance(raw, str):
            raise SettingsError(f"{name}: ожидалась строка (источник: {source})")
        value = raw.strip().lower()
        if value not in spec.choices:
            raise SettingsError(f"{name}: недопустимый вариант (источник: {source})")
        return value
    if spec.kind == "bool":
        if type(raw) is bool:
            value = raw
        elif type(raw) is int and raw in (0, 1):
            value = bool(raw)
        elif isinstance(raw, str) and raw.strip().lower() in _TRUE_STRINGS:
            value = True
        elif isinstance(raw, str) and raw.strip().lower() in _FALSE_STRINGS:
            value = False
        else:
            raise SettingsError(f"{name}: ожидалось логическое значение (источник: {source})")
        return value
    if spec.kind in ("int", "optional_int", "optional_rate"):
        if spec.kind.startswith("optional") and isinstance(raw, str) and not raw.strip():
            return None
        if type(raw) is int:
            value = raw
        elif isinstance(raw, str):
            try:
                value = (int(float(raw.strip())) if spec.kind == "optional_rate"
                         else int(raw.strip(), 10))
            except ValueError:
                raise SettingsError(f"{name}: ожидалось целое число (источник: {source})") from None
        else:
            raise SettingsError(f"{name}: ожидалось целое число (источник: {source})")
        if spec.minimum is not None and value < spec.minimum:
            raise SettingsError(f"{name}: значение вне диапазона (источник: {source})")
        return value
    if spec.kind == "float":
        if type(raw) not in (int, float, str):
            raise SettingsError(f"{name}: ожидалось число (источник: {source})")
        try:
            import math as _math
            value = float(raw)
        except (TypeError, ValueError):
            raise SettingsError(f"{name}: ожидалось число (источник: {source})") from None
        if not _math.isfinite(value):
            raise SettingsError(f"{name}: значение вне диапазона (источник: {source})")
        if spec.minimum is not None and value < spec.minimum:
            raise SettingsError(f"{name}: значение вне диапазона (источник: {source})")
        return value
    raise SettingsError(f"{name}: внутренняя ошибка схемы")


def _setting_name(field_name: str) -> str:
    return _FIELD_TO_ENV.get(field_name, field_name)


def _parse_value(field_name: str, raw: object, source: str) -> int | bool:
    """Преобразовать один явный ввод, не включая его в диагностический текст."""
    env_name = _setting_name(field_name)

    if field_name in _BOOLEAN_FIELDS:
        if type(raw) is bool:
            return raw
        if type(raw) is int and raw in (0, 1):
            return bool(raw)
        if isinstance(raw, str):
            token = raw.strip().lower()
            if token in _TRUE_STRINGS:
                return True
            if token in _FALSE_STRINGS:
                return False
        raise SettingsError(
            f"{env_name}: ожидалось логическое значение "
            f"(источник: {source}; допустимы 1/0, true/false, yes/no, on/off)"
        )

    if field_name in _INTEGER_FIELDS:
        if type(raw) is int:
            value = raw
        elif isinstance(raw, str):
            try:
                value = int(raw.strip(), 10)
            except ValueError:
                raise SettingsError(
                    f"{env_name}: ожидалось целое число (источник: {source})"
                ) from None
        else:
            raise SettingsError(
                f"{env_name}: ожидалось целое число (источник: {source})"
            )
        minimum = 1 if field_name == "workers" else 0
        if value < minimum:
            requirement = "не меньше 1" if minimum else "не меньше 0"
            raise SettingsError(
                f"{env_name}: значение должно быть {requirement} "
                f"(источник: {source})"
            )
        return value

    # Эта ветка защищает схему от рассинхронизации при добавлении нового поля.
    raise SettingsError(f"внутренняя ошибка схемы для {_setting_name(field_name)}")


def _project_scan_environment(values: Mapping[str, object] | None, source: str
                              ) -> dict[str, object]:
    """Извлечь известные scan env keys, не читая значения других доменов."""
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise SettingsError(f"источник {source}: ожидалась таблица настроек")
    return {name: values[name] for name in _SCAN_ENV_TO_FIELD if name in values}


def project_explicit_environment(
    values: Mapping[str, object] | None,
    *,
    additional_keys: Iterable[str] = (),
    source: str = "environment",
) -> dict[str, object]:
    """Project registered non-secret keys and caller-allowlisted additions.

    Composition roots call this before the legacy adapter adds mode preset
    values to ``os.environ``. Secret names are intentionally absent from the
    registry; callers must keep ``additional_keys`` to non-secret allowlists.
    Values for unrelated environment names are never copied.
    """
    projected = _project_scan_environment(values, source)
    if values is None:
        return projected
    if not isinstance(values, Mapping):
        raise SettingsError(f"источник {source}: ожидалась таблица настроек")
    try:
        keys = tuple(additional_keys)
    except TypeError:
        raise SettingsError("additional_keys: ожидалась последовательность имён") from None
    allowed = set(_CONFIG_ENV_KEYS)
    for name in keys:
        if not isinstance(name, str) or not name.startswith("ASM_"):
            raise SettingsError("additional_keys: имя должно быть разрешённым ASM_* ключом")
        allowed.add(name)
    for name in sorted(allowed):
        if name not in projected and name in values:
            projected[name] = values[name]
    return projected


def _normalise_mapping(values: Mapping[str, object] | None, source: str
                       ) -> dict[str, int | bool]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise SettingsError(f"источник {source}: ожидалась таблица настроек")

    parsed: dict[str, int | bool] = {}
    for input_name, raw in values.items():
        if not isinstance(input_name, str):
            raise SettingsError(f"источник {source}: имя настройки должно быть строкой")
        field_name = _SCAN_ALIASES.get(input_name)
        if field_name is None:
            raise SettingsError(
                f"{input_name}: неизвестная scan-настройка (источник: {source})"
            )
        if field_name in parsed:
            raise SettingsError(
                f"{_setting_name(field_name)}: настройка задана дважды "
                f"в одном источнике ({source})"
            )
        parsed[field_name] = _parse_value(field_name, raw, source)
    return parsed


@dataclass(frozen=True)
class ScanSettings:
    """Неизменяемый snapshot настроек, сейчас читаемых `asm.scan.DEFAULTS`."""

    max_subdomains: int = 200
    max_ips: int = 60
    max_probes: int = 40
    max_cpes: int = 25
    workers: int = 8
    active_scan: bool = True
    max_active_targets: int = 12
    estate: bool = True
    estate_words: int = 120
    estate_max_hosts: int = 300
    estate_asn: bool = False
    estate_max_prefixes: int = 8
    estate_prefix_ips: int = 64
    estate_max_extra_ips: int = 128
    engines: bool = True
    engine_crawl: bool = True
    engine_archives: bool = True
    deep_paths: bool = False

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            env_name = _setting_name(item.name)
            if item.name in _INTEGER_FIELDS:
                if type(value) is not int:
                    raise SettingsError(f"{env_name}: требуется целое число")
                minimum = 1 if item.name == "workers" else 0
                if value < minimum:
                    requirement = "не меньше 1" if minimum else "не меньше 0"
                    raise SettingsError(f"{env_name}: значение должно быть {requirement}")
            elif item.name in _BOOLEAN_FIELDS and type(value) is not bool:
                raise SettingsError(f"{env_name}: требуется логическое значение")

    @classmethod
    def from_mapping(cls, values: Mapping[str, object] | None = None, *,
                     source: str = "scan settings") -> ScanSettings:
        """Создать scan-настройки из mapping env-имён или Python-полей.

        Неизвестные имена отклоняются. Входной mapping не меняется.
        """
        return cls(**_normalise_mapping(values, source))

    def to_legacy_dict(self) -> dict[str, int | bool]:
        """Вернуть отдельный dict для пока не мигрированных scan stages."""
        return {item.name: getattr(self, item.name) for item in fields(self)}


def _default_config_values() -> dict[str, object]:
    return {name: spec.default for name, spec in _CONFIG_SPECS.items()}


@dataclass(frozen=True)
class ConfigGroup:
    """Typed values for one non-secret settings domain."""

    domain: str
    values: Mapping[str, object]

    def get(self, name: str, default: object = None) -> object:
        aliases = {
            "stealth": {"mode": "ASM_STEALTH"},
            "transport": {
                "mode": "ASM_INWARD", "method": "ASM_INWARD_METHOD",
                "port": "ASM_INWARD_PORT", "timeout": "ASM_INWARD_TIMEOUT",
                "pull": "ASM_INWARD_PULL",
            },
            "facts": {"mode": "ASM_FACTS_NET", "max_age_days": "ASM_FACTS_MAX_AGE"},
        }
        alias = aliases.get(self.domain, {}).get(name.lower())
        key = alias or (name if name.startswith("ASM_") else "ASM_" + name.upper())
        if key not in self.values:
            return default
        return self.values[key]

    def __getattr__(self, name: str) -> object:
        marker = object()
        value = self.get(name, marker)
        if value is marker:
            raise AttributeError(name)
        return value


@dataclass(frozen=True)
class Settings:
    """Immutable operation snapshot grouped by configuration domain."""

    scan: ScanSettings = field(default_factory=ScanSettings)
    _config: Mapping[str, object] = field(default_factory=_default_config_values,
                                         repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.scan, ScanSettings):
            raise SettingsError("scan: ожидался объект ScanSettings")
        if not isinstance(self._config, Mapping):
            raise SettingsError("settings: ожидалась таблица несекретных настроек")
        unknown = set(self._config) - _CONFIG_ENV_KEYS
        if unknown:
            # Не включаем неизвестные значения/ключи окружения в диагностику.
            raise SettingsError("settings: неизвестное поле конфигурации")
        resolved = _default_config_values()
        for key, raw in self._config.items():
            resolved[key] = _parse_config_value(key, raw, "settings")
        object.__setattr__(self, "_config", MappingProxyType(resolved))

    def get(self, name: str, default: object = None) -> object:
        """Получить typed field по ASM key либо его нижнему имени."""
        if name in _SCAN_ALIASES:
            return getattr(self.scan, _SCAN_ALIASES[name])
        key = name if name in _CONFIG_SPECS else _CONFIG_FIELD_TO_ENV.get(name.lower())
        if key is None:
            return default
        value = self._config[key]
        return default if value is None else value

    def group(self, domain: str) -> ConfigGroup:
        if domain not in {spec.domain for spec in _CONFIG_SPECS.values()}:
            raise SettingsError("settings: неизвестная группа")
        values = {key: value for key, value in self._config.items()
                  if _CONFIG_SPECS[key].domain == domain}
        return ConfigGroup(domain, MappingProxyType(values))

    @property
    def engines(self) -> ConfigGroup:
        return self.group("engines")

    @property
    def active(self) -> ConfigGroup:
        return self.group("active")

    @property
    def stealth(self) -> ConfigGroup:
        return self.group("stealth")

    @property
    def planner(self) -> ConfigGroup:
        return self.group("planner")

    @property
    def agent(self) -> ConfigGroup:
        return self.group("agent")

    @property
    def sources(self) -> ConfigGroup:
        return self.group("sources")

    @property
    def facts(self) -> ConfigGroup:
        return self.group("facts")

    @property
    def model(self) -> ConfigGroup:
        return self.group("model")

    @property
    def transport(self) -> ConfigGroup:
        return self.group("transport")

    @property
    def runtime(self) -> ConfigGroup:
        return self.group("runtime")

    @property
    def stages(self) -> ConfigGroup:
        return self.group("stages")

    @classmethod
    def from_sources(cls, *,
                     mode_values: Mapping[str, object] | None = None,
                     environment: Mapping[str, object] | None = None,
                     cli_overrides: Mapping[str, object] | None = None) -> Settings:
        """Resolve defaults < mode < explicit environment < operation override.

        Only registered scan and non-secret settings are accepted. Unknown fields
        fail closed, while full process environments are projected before entry.
        Explicit ``False``, zero, and empty strings remain distinct from absence.
        """
        scan_values: dict[str, int | bool] = {}
        config_values = _default_config_values()
        for source_name, source in (
            ("mode", mode_values),
            ("environment", environment),
            ("cli", cli_overrides),
        ):
            scan_layer, config_layer = _normalise_settings_source(source, source_name)
            scan_values.update(scan_layer)
            config_values.update(config_layer)
        return cls(scan=ScanSettings(**scan_values), _config=config_values)

    @classmethod
    def from_environment_snapshot(
        cls,
        environment: Mapping[str, object],
        *,
        mode_values: Mapping[str, object] | None = None,
        cli_overrides: Mapping[str, object] | None = None,
    ) -> Settings:
        """Build from a projected environment and a separate lower-priority preset.

        Only exact registered non-secret keys are copied; unrelated domains and
        secret values are neither traversed nor retained. Environment wins over
        mode, which wins over defaults; operation-specific overrides are last.
        """
        return cls.from_sources(
            mode_values=_project_registered_environment(mode_values, "mode"),
            environment=_project_registered_environment(environment, "environment"),
            cli_overrides=cli_overrides,
        )

    def to_legacy_config(self) -> dict[str, object]:
        """Copy registered config values for legacy adapters and tests."""
        return dict(self._config)

    def to_legacy_environment(self) -> dict[str, str]:
        """Serialize only registered non-secret settings for a legacy child.

        This adapter is transitional; it never includes secret values or
        ``ASM_DB`` bootstrap state.
        """
        values: dict[str, str] = {}
        for field_name, env_name in _FIELD_TO_ENV.items():
            value = getattr(self.scan, field_name)
            values[env_name] = "1" if value is True else "0" if value is False else str(value)
        for name, value in self._config.items():
            if value is None:
                continue
            values[name] = ("1" if value is True else "0" if value is False
                            else str(value))
        return values


def _project_registered_environment(
    values: Mapping[str, object] | None, source: str,
) -> dict[str, object]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise SettingsError(f"источник {source}: ожидалась таблица настроек")
    allowed = set(_SCAN_ENV_TO_FIELD) | set(_CONFIG_ENV_KEYS)
    return {key: values[key] for key in allowed if key in values}


def _normalise_settings_source(
    values: Mapping[str, object] | None, source: str,
) -> tuple[dict[str, int | bool], dict[str, object]]:
    if values is None:
        return {}, {}
    if not isinstance(values, Mapping):
        raise SettingsError(f"источник {source}: ожидалась таблица настроек")
    scan_raw: dict[str, object] = {}
    config_raw: dict[str, object] = {}
    for input_name, raw in values.items():
        if not isinstance(input_name, str):
            raise SettingsError(f"источник {source}: имя настройки должно быть строкой")
        if input_name in _SCAN_ALIASES:
            scan_raw[input_name] = raw
            continue
        config_name = (input_name if input_name in _CONFIG_SPECS
                       else _CONFIG_FIELD_TO_ENV.get(input_name.lower()))
        if config_name is None:
            raise SettingsError(f"{input_name}: неизвестная настройка (источник: {source})")
        if config_name in config_raw:
            raise SettingsError(f"{config_name}: настройка задана дважды (источник: {source})")
        config_raw[config_name] = raw
    scan_values = _normalise_mapping(scan_raw, source)
    config_values = {name: _parse_config_value(name, raw, source)
                     for name, raw in config_raw.items()}
    return scan_values, config_values


_CURRENT_OPERATION_SETTINGS: ContextVar[Settings | None] = ContextVar(
    "asm_operation_settings", default=None,
)


def current_settings() -> Settings | None:
    """Return the immutable snapshot bound to this operation, if any."""
    return _CURRENT_OPERATION_SETTINGS.get()


@contextmanager
def use_settings(settings: Settings):
    """Bind a typed snapshot for the current operation and restore its parent."""
    if not isinstance(settings, Settings):
        raise SettingsError("settings: ожидался объект Settings")
    token: Token = _CURRENT_OPERATION_SETTINGS.set(settings)
    try:
        yield settings
    finally:
        _CURRENT_OPERATION_SETTINGS.reset(token)
