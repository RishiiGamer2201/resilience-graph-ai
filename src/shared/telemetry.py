"""Who acted, when the log does not name an account.

THE DEFECT. `live_analyze._prepare` refuses any batch where no row carries a
user: "events need a 'user' column (behavioral features are per-user)". That is
true of the features, and it is why network flows, DNS answers and most
endpoint telemetry cannot enter detection at all -- a NetFlow record has a
source address and no principal, so the product rejects the majority of what a
real estate produces and analyses authentication logs.

WHAT THIS DOES, AND WHAT IT DOES NOT. It fills in the ACTOR, not the account. A
flow from 10.0.0.7 with no user becomes an actor named `device:10.0.0.7`, and
its behaviour is then profiled against that device's own history rather than
against nobody's. The row is tagged `actor_kind="device"` and carries
`actor_inferred=True`, because the two must never be confused downstream:

  * "this ACCOUNT reached five new hosts" is a claim about a person;
  * "this DEVICE reached five new hosts" is a claim about a machine, and the
    account behind it is unknown -- which is a different, weaker statement, and
    the response to it is different too.

A segment key is derived when even the device is absent but an address is: the
/24 an address sits in is a coarse actor, and coarse is not nothing. It is
tagged as such.

WHY NOT JUST DROP USERLESS ROWS. That is the current behaviour and it is why
`reports/` describes an authentication-log detector. Dropping them is defensible
only while nothing claims otherwise; the product claims a multi-telemetry
engine.
"""
from __future__ import annotations

import ipaddress

import pandas as pd

ACTOR_KIND = "actor_kind"
ACTOR_INFERRED = "actor_inferred"

DEVICE_PREFIX = "device:"
SEGMENT_PREFIX = "segment:"


def _segment_of(value: str) -> str | None:
    """The /24 an address sits in, or None when it is not an address.

    A hostname has no segment. Guessing one from a name would invent structure
    the log does not carry, which is how a baseline learns something false.
    """
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if addr.version != 4:                        # pragma: no cover - v6 estates
        return None
    return str(ipaddress.ip_network(f"{addr}/24", strict=False))


def attribute_actor(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Give every row an actor, and say for each one where it came from.

    Rows that already name a user are untouched and tagged `account`. Rows that
    do not are keyed on their source device, or failing that on the segment of
    their source address. Rows with neither cannot be profiled against anything
    and keep an empty actor -- they are counted and reported rather than
    silently dropped, because "we ignored 40% of your telemetry" is a fact the
    operator needs.
    """
    out = df.copy()
    if "user" not in out.columns:
        out["user"] = ""
    user = out["user"].astype(str).str.strip()
    src = (out["source_host"].astype(str).str.strip()
           if "source_host" in out.columns else pd.Series("", index=out.index))

    has_account = user.str.len() > 0
    has_device = (~has_account) & (src.str.len() > 0) & (src.str.lower() != "nan")

    segments = pd.Series("", index=out.index, dtype=object)
    if "source_ip" in out.columns:
        candidates = out.loc[~(has_account | has_device), "source_ip"]
    else:
        candidates = pd.Series(dtype=object)
    for idx, value in candidates.items():
        seg = _segment_of(value)
        if seg:
            segments.at[idx] = f"{SEGMENT_PREFIX}{seg}"
    has_segment = segments.str.len() > 0

    out.loc[has_device, "user"] = DEVICE_PREFIX + src[has_device]
    out.loc[has_segment, "user"] = segments[has_segment]

    kind = pd.Series("unattributed", index=out.index, dtype=object)
    kind[has_account] = "account"
    kind[has_device] = "device"
    kind[has_segment] = "segment"
    out[ACTOR_KIND] = kind
    out[ACTOR_INFERRED] = ~has_account

    summary = {
        "account": int(has_account.sum()),
        "device": int(has_device.sum()),
        "segment": int(has_segment.sum()),
        "unattributed": int((kind == "unattributed").sum()),
        "total": int(len(out)),
    }
    summary["note"] = (
        f"{summary['account']} rows name an account; "
        f"{summary['device']} were keyed on their source device and "
        f"{summary['segment']} on their source segment, so they are profiled "
        f"against that device or segment's own history rather than being "
        f"refused. A device-keyed finding is a claim about a machine, not about "
        f"a person, and carries actor_kind so nothing downstream can confuse "
        f"the two."
    )
    if summary["unattributed"]:
        summary["note"] += (
            f" {summary['unattributed']} rows carry neither an account nor a "
            f"source and cannot be profiled against anything.")
    return out, summary


def has_any_actor(df: pd.DataFrame) -> bool:
    """True when at least one row can be profiled against some history."""
    if "user" not in df.columns:
        return False
    return bool((df["user"].astype(str).str.strip().str.len() > 0).any())


__all__ = ["ACTOR_KIND", "ACTOR_INFERRED", "DEVICE_PREFIX", "SEGMENT_PREFIX",
           "attribute_actor", "has_any_actor"]
