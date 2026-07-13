# rca: the deterministic root-cause-analysis service of Aegil

> **English** | [Русский](README.ru.md)

The Root Cause Analysis (RCA) service is the deterministic half of the Aegil product, answering the
question of what broke and why. Facts about logs and metrics are computed by deterministic code, and
the language model is connected only at the edges (for parsing the engineer's request and for
formulating a report over already-computed facts). The guarantee of the verdict is given by code,
not by a neural network.

## The deterministic core (without external dependencies)

Normalization `normalize.py` is domain-agnostic: it parses both a structured log in JSON format and
an arbitrary text line of a pod's log (a Go-language panic, a stack trace, a message from the
out-of-memory protection system, a `CrashLoopBackOff` record), extracting the severity level and
the symptoms straight from the text rather than from someone else's structural field. The former
engine read only the internal JSON envelope of the legacy platform and was blind in someone else's
cluster; the current one accepts arbitrary text.

The aggregator `aggregator.py` computes, in a single pass of O(N) complexity, eighteen blocks of
facts, including the window's time canvas and the activity by service over time, and groups lines by
a cross-cutting trace identifier over ten correlation fields. The catalog of log detectors
`detectors.py` (D1-D12) consumes the facts and the baseline and emits weights as likelihood ratios;
the detectors of a log gap, source silence and a recovery damper rely on the time canvas, and the
structural neighbor relies on the dependency graph from the facts. The catalog of metric detectors
`metric_detectors.py` (ML1-ML13) reads the window's metrics and expresses its weight in the same
likelihood-ratio format, so logs and metrics enter a single scoring.

Scoring `scoring.py` translates the triggered detectors, both log and metric, into a confidence
number by Bayesian updating in odds with the grouping of correlated detectors by maximum, a
significance gate, a ceiling of 0.999, a recovery damper, a completeness coefficient and confidence
bands. The assembly `verdict.py` produces a verdict in a five-field schema (status, confidence, root
cause, evidence, action) with an evidence registry and a "no quote, no assertion" guard: every
assertion rests on a verbatim quote from a log or a metric. The orchestration `pipeline.py` (the
`analyze` function) links everything into a single deterministic pass.

## Request routing and active learning

The cascade `cascade.py` assigns the engineer's utterance to one of six diagnostic branches with a
lightweight trained SetFit classifier (`setfit_model.py`, `router.py`). At a confidence below the
threshold, the request is escalated to a large teacher model, its decision is recorded as a new
labeled example in the store `store.py`, and a separate trainer service `rca-trainer` later further
trains the lightweight classifier. On failures, a deterministic keyword fallback operates.

## The wiring

The reader `loki.py` fetches a window of logs from Loki with a `query_range` request with reverse
pagination by time and preserves the raw line for verbatim quotes; when a Prometheus address is set,
the `metrics.py` module pulls the metrics of the same window. The application `app.py` (FastAPI)
serves `GET /health` and `POST /analyze`; the latter accepts a window of logs directly or reads it
from Loki (with a baseline shifted by a day) and returns the facts, the detectors, the scoring and
the verdict. The cache `cache.py` conserves repeated calls, and `report.py` forms a readable report.
The service itself logs in structured JSON (`service=rca`, `trace_id`).

## Tests

The core is verified by unit tests that need no network and no external dependencies:

```
cd services/rca
for t in test_*.py; do python3 "$t"; done
```

## Bounds of applicability

The detector weights and thresholds are presented as working parameters: a labeled set of incidents
for calibration does not yet exist, so the default values are set by expert judgment and neutrally.
Some detectors are honestly limited by the window input: the baseline detectors require a comparison
with the previous day, and the structural neighbor requires an observed dependency graph. Strict
calibration on historical incidents remains the necessary next step.
