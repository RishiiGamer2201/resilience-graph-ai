"""
Common event schema — the single source of truth for nextATT&CKs (PS7).

Every dataset (CIC-IDS2017, LANL, UNSW-NB15) is normalized into ONE event schema
so the rest of the pipeline (anomaly detection, correlation, ATT&CK mapping,
attack-path graph, SOAR) speaks a single language.

Import from here — do not redefine columns anywhere else.

    from src.schema import COLUMNS, empty_frame, coerce, validate, AssetCriticality
"""
from __future__ import annotations

from enum import Enum
from typing import Dict

import pandas as pd


# ---------------------------------------------------------------------------
# The schema: column -> pandas dtype. Order is canonical.
# ---------------------------------------------------------------------------
SCHEMA: Dict[str, str] = {
    "timestamp": "int64",          # seconds (or epoch) — integer, sortable
    "user": "string",             # e.g. U748@DOM1
    "source_host": "string",      # e.g. C17693
    "destination_host": "string", # e.g. DB-CITIZEN-01
    "event_type": "string",       # normalized event label (see EventType hints)
    "status": "string",           # success | failure | unknown
    "protocol": "string",         # tcp | udp | icmp | ntlm | kerberos | ...
    "port": "Int64",              # nullable integer
    "bytes_out": "int64",         # outbound byte volume (0 if n/a)
    "command": "string",          # process/command text if present, else ""
    "asset_criticality": "string",# low | medium | high | critical
    "label": "Int64",             # 1 = known-malicious (ground truth), 0 = benign, <NA> = unlabeled
}

COLUMNS = list(SCHEMA.keys())

# Common column aliases → canonical schema name. Real logs / uploads use varied
# headers (username, src, dst, proto…); we resolve them case-insensitively so a
# judge's own CSV analyses without renaming columns by hand.
ALIASES: Dict[str, list] = {
    "timestamp": ["time", "ts", "datetime", "date", "event_time", "@timestamp", "eventtime"],
    "user": ["username", "user_name", "account", "principal", "src_user", "user_id", "actor"],
    "source_host": ["src", "src_host", "source", "srchost", "src_computer", "source_computer",
                    "from_host", "src_host_name", "srchostname", "host_src"],
    "destination_host": ["dst", "dest", "dst_host", "destination", "dsthost", "dst_computer",
                         "destination_computer", "to_host", "target", "host_dst"],
    "protocol": ["proto", "auth_type", "authentication_type"],
    "status": ["result", "outcome", "auth_result", "logon_result"],
    "bytes_out": ["bytes", "out_bytes", "bytes_sent"],
    "event_type": ["type", "action", "operation"],
}


def resolve_aliases(df: pd.DataFrame) -> pd.DataFrame:
    """Rename known alias / differently-cased columns to their canonical schema
    name. Only fills a canonical column that isn't already present."""
    lower = {str(c).lower(): c for c in df.columns}
    renames = {}
    for canon, alist in ALIASES.items():
        if canon in df.columns:
            continue
        for cand in [canon, *alist]:
            src = lower.get(cand)
            if src is not None and src != canon and canon not in renames.values():
                renames[src] = canon
                break
    return df.rename(columns=renames) if renames else df


class Status(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Common normalized event_type values used across datasets + the demo.
# (Free-form is allowed, but prefer these so the ATT&CK mapper stays consistent.)
class EventType(str, Enum):
    NORMAL_LOGIN = "normal_login"
    FAILED_LOGIN_BURST = "failed_login_burst"
    UNUSUAL_SUCCESSFUL_LOGIN = "unusual_successful_login"
    DISCOVERY_COMMAND = "discovery_command"
    LATERAL_MOVEMENT = "lateral_movement"
    CRITICAL_ASSET_ACCESS = "critical_asset_access"
    LARGE_OUTBOUND_TRANSFER = "large_outbound_transfer"
    NETWORK_FLOW = "network_flow"          # generic CICIDS/UNSW flow
    AUTH = "auth"                          # generic LANL auth event
    PROCESS = "process"                    # generic LANL proc event
    DNS = "dns"                            # generic LANL dns event


VALID_CRITICALITY = {c.value for c in AssetCriticality}


def empty_frame() -> pd.DataFrame:
    """Return an empty DataFrame with the canonical columns and dtypes."""
    return pd.DataFrame({col: pd.Series(dtype=dt) for col, dt in SCHEMA.items()})


def coerce(df: pd.DataFrame) -> pd.DataFrame:
    """
    Coerce an arbitrary frame into the canonical schema:
    add any missing columns with sensible defaults, drop extras, cast dtypes,
    and return columns in canonical order. Use at the end of every normalizer.
    """
    out = resolve_aliases(df.copy())

    defaults = {
        "timestamp": 0, "user": "", "source_host": "", "destination_host": "",
        "event_type": EventType.NETWORK_FLOW.value, "status": Status.UNKNOWN.value,
        "protocol": "", "port": pd.NA, "bytes_out": 0, "command": "",
        "asset_criticality": AssetCriticality.MEDIUM.value, "label": pd.NA,
    }
    for col in COLUMNS:
        if col not in out.columns:
            out[col] = defaults[col]

    out = out[COLUMNS]  # canonical order, drop extras

    # timestamp may arrive as epoch ints OR ISO-8601 / datetime strings (real logs
    # and uploads use the latter). Normalize to epoch seconds before the int cast,
    # otherwise `int("2026-07-16T10:00:00Z")` crashes the whole analysis.
    ts_num = pd.to_numeric(out["timestamp"], errors="coerce")
    if ts_num.isna().any():                       # some values aren't plain numbers
        ts_dt = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
        epoch = (ts_dt.astype("int64") // 1_000_000_000).where(ts_dt.notna(), 0)
        out["timestamp"] = ts_num.where(ts_num.notna(), epoch)
    else:
        out["timestamp"] = ts_num
    out["timestamp"] = out["timestamp"].fillna(0)

    for col, dt in SCHEMA.items():
        try:
            out[col] = out[col].astype(dt)
        except (ValueError, TypeError):
            # fall back to nullable/string so a bad row never crashes the pipeline
            out[col] = out[col].astype("string") if dt == "string" else out[col]
    return out


def validate(df: pd.DataFrame, *, require_labels: bool = False) -> None:
    """
    Raise AssertionError if `df` violates the schema. Cheap sanity gate to call
    right after normalization / before writing parquet.
    """
    missing = [c for c in COLUMNS if c not in df.columns]
    assert not missing, f"missing schema columns: {missing}"

    bad_crit = set(df["asset_criticality"].dropna().unique()) - VALID_CRITICALITY
    assert not bad_crit, f"invalid asset_criticality values: {bad_crit}"

    if require_labels:
        assert df["label"].notna().any(), "require_labels=True but no labels present"


__all__ = [
    "SCHEMA", "COLUMNS", "Status", "AssetCriticality", "EventType",
    "empty_frame", "coerce", "validate",
]
