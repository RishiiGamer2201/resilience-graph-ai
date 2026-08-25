"""The detector's calibrated cut points. No imports, so anything may import it.

ALERT_SCORE was written twice -- `src/shared/correlate.py::ALERT_THRESHOLD` and
`src/shared/attack_mapper.py::ALERT_SCORE` -- with a comment on the second
saying it matches the first. A comment is not a guarantee: it stays true only
until someone edits one of them, and nothing fails when they diverge.

Both now re-export this value under the names they already published, so callers
and tests that import either keep working, and there is one number to change.
"""
from __future__ import annotations

# The 1% false-positive point measured on LANL for the shipped detector. Below
# this the detector is not claiming to have found anything, which is why it is
# also where `medium` severity begins -- see src/shared/severity.py.
ALERT_SCORE: int = 50
