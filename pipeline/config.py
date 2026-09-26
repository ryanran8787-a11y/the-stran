"""環境變數 / 路徑 / 來源設定。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import env, env_float, env_int, read_json

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DAILY_DIR = DATA_DIR / "daily"
INDEX_PATH = DATA_DIR / "index.json"
SOURCES_PATH = ROOT / "config" / "sources.json"
PROMPT_PATH = ROOT / "prompts" / "daily_digest.md"
SCHEMA_PATH = ROOT / "schema" / "digest.schema.json"
CACHE_DIR = ROOT / "pipeline" / ".cache"
FIXTURE_DIR = ROOT / "pipeline" / "tests" / "fixtures"


def load_dotenv(path: Path | None = None) -> None:
    """極簡 .env 載入器。已存在的環境變數優先（CI Secrets 不會被覆蓋）。"""
    path = path or (ROOT / ".env")
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in __import__("os").environ:
            __import__("os").environ[key] = value


@dataclass
class Settings:
    data_dir: Path = DATA_DIR
    min_cvss: float = 9.0
    min_epss: float = 0.5
    kev_lookback_days: int = 3
    llm_provider: str = "gemini"
    llm_batch_size: int = 18
    llm_max_items: int = 80
    nvd_api_key: str = ""
    github_token: str = ""
    gemini_api_key: str = ""
    gemini_model: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-haiku-4-5"
    sources: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Settings":
        load_dotenv()
        raw: dict[str, Any] = {}
        if SOURCES_PATH.exists():
            raw = read_json(SOURCES_PATH)
        return cls(
            data_dir=Path(env("DATA_DIR") or DATA_DIR),
            min_cvss=env_float("FILTER_MIN_CVSS", 9.0),
            min_epss=env_float("FILTER_MIN_EPSS", 0.5),
            kev_lookback_days=env_int("KEV_LOOKBACK_DAYS", 3),
            llm_provider=(env("LLM_PROVIDER", "gemini") or "gemini").lower(),
            llm_batch_size=max(1, env_int("LLM_BATCH_SIZE", 18)),
            llm_max_items=max(0, env_int("LLM_MAX_ITEMS", 80)),
            nvd_api_key=env("NVD_API_KEY"),
            github_token=env("GITHUB_TOKEN"),
            gemini_api_key=env("GEMINI_API_KEY") or env("GOOGLE_API_KEY"),
            gemini_model=env("GEMINI_MODEL"),
            openai_api_key=env("OPENAI_API_KEY"),
            openai_model=env("OPENAI_MODEL", "gpt-4.1-mini"),
            anthropic_api_key=env("ANTHROPIC_API_KEY"),
            anthropic_model=env("ANTHROPIC_MODEL", "claude-haiku-4-5"),
            sources=raw,
        )

    def source(self, key: str) -> dict[str, Any]:
        return self.sources.get(key, {}) or {}

    def source_enabled(self, key: str) -> bool:
        return bool(self.source(key).get("enabled", False))
