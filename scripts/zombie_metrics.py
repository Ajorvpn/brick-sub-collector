"""Deterministic, non-Cloudflare 60-second zombie-trap scoring."""

from __future__ import annotations

import statistics
from typing import Any, Dict, Sequence


def _longest_stall_run(samples: Sequence[float], threshold: float = 2.0) -> int:
    """Return the longest consecutive run in stall_slice where rate < 2.0 KB/s."""
    max_run = 0
    current_run = 0
    for s in samples:
        if s < threshold:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0
    return max_run


def evaluate_stream(
    samples_kbps: Sequence[float], probe_40s_ok: bool
) -> Dict[str, Any]:
    """Score a stream against Iranian 30-second zombie-trap patterns."""
    samples = list(samples_kbps)
    n = len(samples)

    if n >= 35:
        early_slice = samples[2:15]
        late_slice = samples[29:60]
        stall_slice = samples[9:]
    else:
        early_slice = samples[1 : max(2, n // 3)]
        late_slice = samples[max(1, n // 2) :]
        stall_slice = samples[max(1, n // 5) :]

    m_early = float(statistics.median(early_slice)) if early_slice else 0.0
    m_late = float(statistics.median(late_slice)) if late_slice else 0.0
    decay = round(m_late / max(m_early, 1.0), 3)
    z_max = _longest_stall_run(stall_slice, threshold=2.0)

    if m_early < 20.0:
        passed = False
        reason = "Zombie-Slow-Start(M_early<20KB/s)"
    elif m_late < 20.0:
        passed = False
        reason = "Zombie-Died-30to60s(M_late<20KB/s)"
    elif decay < 0.45:
        passed = False
        reason = "Zombie-Throttled(D<0.45)"
    elif z_max >= 6:
        passed = False
        reason = "Zombie-Stalled(Z_max>=6s)"
    elif not probe_40s_ok:
        passed = False
        reason = "Zombie-40s-Probe-Failed"
    else:
        passed = True
        reason = "OK"

    return {
        "passed": passed,
        "reason": reason,
        "m_early": round(m_early, 1),
        "m_late": round(m_late, 1),
        "decay": decay,
        "z_max": z_max,
    }
