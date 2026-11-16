"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.environ.get("MCSEC_DB", "mcsec.sqlite3"))
    admin_token: str = field(default_factory=lambda: os.environ.get("MCSEC_ADMIN_TOKEN", ""))

    # Scanner: responsible defaults. Raise deliberately, not by accident.
    scan_rate: float = field(default_factory=lambda: float(os.environ.get("MCSEC_SCAN_RATE", "50")))
    scan_rate_max: float = field(default_factory=lambda: float(os.environ.get("MCSEC_SCAN_RATE_MAX", "1000")))
    scan_concurrency: int = field(default_factory=lambda: int(os.environ.get("MCSEC_SCAN_CONCURRENCY", "200")))
    scan_timeout: float = field(default_factory=lambda: float(os.environ.get("MCSEC_SCAN_TIMEOUT", "3")))
    max_targets_per_job: int = field(default_factory=lambda: int(os.environ.get("MCSEC_MAX_TARGETS", str(1 << 20))))
    allow_private: bool = field(default_factory=lambda: _bool("MCSEC_ALLOW_PRIVATE", False))
    exclude_file: str = field(default_factory=lambda: os.environ.get("MCSEC_EXCLUDE_FILE", ""))

    # Mojang endpoints (overridable for tests / mirrors)
    mojang_name_url: str = field(default_factory=lambda: os.environ.get(
        "MCSEC_MOJANG_NAME_URL", "https://api.mojang.com/users/profiles/minecraft/{name}"))
    mojang_name_url_fallback: str = field(default_factory=lambda: os.environ.get(
        "MCSEC_MOJANG_NAME_URL_FALLBACK",
        "https://api.minecraftservices.com/minecraft/profile/lookup/name/{name}"))
    mojang_profile_url: str = field(default_factory=lambda: os.environ.get(
        "MCSEC_MOJANG_PROFILE_URL", "https://sessionserver.mojang.com/session/minecraft/profile/{uuid}"))
    mojang_cache_seconds: int = field(default_factory=lambda: int(os.environ.get("MCSEC_MOJANG_CACHE", "3600")))
    mojang_enabled: bool = field(default_factory=lambda: _bool("MCSEC_MOJANG_ENABLED", True))

    # A federation server counts as "reporting" if it sent anything within this window.
    federation_stale_seconds: int = field(default_factory=lambda: int(os.environ.get("MCSEC_FED_STALE", "900")))

    frontend_dir: str = field(default_factory=lambda: os.environ.get(
        "MCSEC_FRONTEND_DIR", str(Path(__file__).resolve().parents[2] / "frontend")))
