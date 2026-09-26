"""HTTP / 日期 / 日誌 等共用工具。只用標準庫。"""

from __future__ import annotations

import gzip
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import date as _date
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_UA = (
    "the-stran-security-daily/0.1 "
    "(+https://github.com/ryanran8787-a11y/the-stran; security-daily aggregator)"
)

log = logging.getLogger("pipeline")


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )


def _gunzip_nested(raw: bytes, max_layers: int = 3) -> bytes:
    """解開可能被「傳輸層 gzip + 檔案本身 .gz」雙層壓縮的內容。

    NVD 的 nvdcve-2.0-modified.json.gz 就是這種情況：我們送 Accept-Encoding: gzip，
    伺服器會再包一層 Content-Encoding: gzip，只解一層只會拿到內層的二進位。
    """
    for _ in range(max_layers):
        if raw[:2] != b"\x1f\x8b":
            break
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError, zlib.error):
            break
    return raw


class HttpError(RuntimeError):
    """HTTP 請求在重試後仍失敗。"""

    def __init__(self, url: str, status: int | None, detail: str) -> None:
        self.url = url
        self.status = status
        super().__init__(f"HTTP {status} for {url}: {detail}")


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 60.0,
    retries: int = 3,
    backoff: float = 2.0,
) -> bytes:
    """取得 URL 內容並在失敗時指數退避重試。會自動解 gzip。"""
    hdrs = {
        "User-Agent": DEFAULT_UA,
        "Accept-Encoding": "gzip, identity",
        "Accept": "*/*",
    }
    if headers:
        hdrs.update(headers)

    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                enc = (resp.headers.get("Content-Encoding") or "").lower()
                if enc == "gzip" or raw[:2] == b"\x1f\x8b":
                    raw = _gunzip_nested(raw)
                return raw
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(500).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - 僅為記錄錯誤訊息
                pass
            last = HttpError(url, exc.code, detail)
            if 400 <= exc.code < 500 and exc.code != 429:
                raise last from exc  # 4xx（除 429）重試無意義
        except Exception as exc:  # noqa: BLE001 - 網路層任何錯誤都重試
            last = exc
        if attempt < retries:
            sleep_for = backoff**attempt
            log.warning("請求失敗 (%s/%s)，%.1fs 後重試：%s", attempt, retries, sleep_for, url)
            time.sleep(sleep_for)
    raise HttpError(url, None, repr(last))


def http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 60.0,
    retries: int = 3,
) -> Any:
    raw = http_get(url, headers=headers, timeout=timeout, retries=retries)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        snippet = raw[:200].decode("utf-8", "replace").replace("\n", " ")
        raise ValueError(f"回應不是 JSON（{exc.msg}）：{snippet}") from exc


def http_post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 120.0,
    retries: int = 2,
) -> Any:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    hdrs = {"User-Agent": DEFAULT_UA, "Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)

    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(1000).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            last = HttpError(url, exc.code, detail)
            if exc.code in (400, 401, 403, 404):
                raise last from exc  # 參數或金鑰問題，重試無用
        except Exception as exc:  # noqa: BLE001
            last = exc
        if attempt < retries:
            time.sleep(2.0 * attempt)
    raise HttpError(url, None, repr(last))


class RateLimiter:
    """滾動式最小間隔節流器（保護上游 API）。"""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        delta = time.monotonic() - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()


# ---------------------------------------------------------------- 日期工具

UTC = timezone.utc


def parse_iso(value: str | None) -> datetime | None:
    """寬鬆解析 ISO 8601（含 Z 結尾、無時區、純日期）。"""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%Y/%m/%d",
        ):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_date(value: str | None) -> _date | None:
    dt = parse_iso(value)
    return dt.date() if dt else None


def nvd_datetime(dt: datetime) -> str:
    """NVD API 要求的格式：2026-09-25T00:00:00.000Z"""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def taipei_today() -> _date:
    """以 UTC+8 判斷「今天」，符合日報的台灣日期直覺。"""
    return (datetime.now(UTC) + timedelta(hours=8)).date()


def report_date_from_arg(value: str | None) -> _date:
    if not value or value.strip().lower() in ("today", "now"):
        return taipei_today()
    if value.strip().lower() == "yesterday":
        return taipei_today() - timedelta(days=1)
    return _date.fromisoformat(value.strip())


def window_for(report_date: _date, hours: int = 24) -> tuple[datetime, datetime]:
    """回傳 [from, to)。

    基準點：報告日前一天 22:00 UTC（= 報告日 06:00 台北），
    對齊 GitHub Actions 的 cron 時間，且可重複執行（idempotent）。
    """
    to_dt = datetime(
        report_date.year, report_date.month, report_date.day, 22, 0, 0, tzinfo=UTC
    )
    return to_dt - timedelta(hours=hours), to_dt


# ---------------------------------------------------------------- 檔案 / 環境


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def env_float(name: str, default: float) -> float:
    try:
        return float(env(name) or default)
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    try:
        return int(float(env(name) or default))
    except ValueError:
        return default


# ---------------------------------------------------------------- 文字工具


def truncate(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def cve_tail(cve_id: str) -> str:
    """CVE-2026-87902 -> 87902"""
    parts = (cve_id or "").split("-")
    return parts[-1] if parts else ""


def pretty_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.netloc}{parsed.path}"
    except ValueError:
        return url
