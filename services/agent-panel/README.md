# agent-panel: the panel of the autonomous SRE agent Aegil

> **English** | [Русский](README.ru.md)

The agent panel is the interactive half of the Aegil product. A lightweight FastAPI service serves
a single-page chat as a mobile Progressive Web Application (PWA) through which the operator observes
the cluster and the nodes, runs the incident center and reads the audit log, while any
natural-language request is executed by a full agentic loop of the language model. The panel is
domain-agnostic: it does not know or assume the names of the owner's application, but operates on
neutral Kubernetes entities, so the same image connects to any cluster without code changes.

The panel is not published externally (a ClusterIP-type service without Ingress). Entry is closed
off by an operator token, and access goes through a closed loop: a tunnel and a port-forward.
Without at least one valid operator the panel does not come up (fail-closed).

## What it does

The operator writes a request in ordinary words, for example "how much space is on the nodes and
clean up unused images", "show the crashed pods", "restart service X", "what is happening in the
cluster". The request is executed by the agentic loop `agent_exec`: the language model conducts a
multi-step analysis, at each step observing state, reasoning, acting through tools and finishing
with a summary. The model acts as an executor of tools, not a formulator of text, and explains
every step. If the language model is not configured (no key or address is set), the agentic loop
degenerates into an executor of a single operator command without planning, and the panel remains
useful.

Besides free-form dialogue, service commands are available: `/help` (the list of commands and a
hint), `/status` (a summary of cluster state), `/health` (the health of the panel and the
log-analysis service), `/agent` (the agent's state: autonomy level, budget, guards),
`/mode observe|safe_repair|full` (changing the autonomy level) and `/report` (the agent's daily
report). The interface palette contains only the product's infrastructure commands; the domain
operations of a specific application live in the external application and are invoked by the agent
through the optional adapter `app_adapter.py`.

## Security model: a deterministic gate outside the model

The safety guarantee is given not by the language model but by deterministic code. The policy
classifier `policy.py` is a pure function that assigns every proposed command, by its actual list
of arguments, to one of three classes: read (`read`), reversible safe repair (`safe_write`) and an
irreversible action (`destructive`). The class is decided not by the tool label chosen by the
model but by the parsing of the arguments, so the model physically cannot pass off a mutation as a
read. The classifier is resistant to bypasses: the binary's name is normalized to its base name,
launcher wrappers (`env`, `sudo`, `nsenter`, `xargs`) are unwrapped down to the nested command,
paths are normalized against traversal, and an opaque shell and SQL from a file are treated as
irreversible. An unknown mutating command is by default treated as irreversible (fail-safe).

The command's class turns into an execution decision according to the autonomy level
`AEGIL_AUTONOMY`. At the `observe` level (default) the agent only observes, diagnoses and proposes,
but does not act. At the `safe_repair` level, reads and safe repairs are executed autonomously,
while irreversible actions and protected patterns (`AEGIL_PROTECTED_PATTERNS`) require operator
confirmation. At the `full` level everything is executed autonomously except irreversible actions
and protected patterns, which always require confirmation, because that is the last line of defense
of data against a model hallucination.

On top of the gate the anti-looping guards `guards.py` operate: no more than two attempts per
fingerprint, a cooldown per fingerprint and per service after a failure, an hourly action budget, a
circuit breaker after a streak of consecutive failures, and a cross-pair oscillation detector. The
guards' state survives a restart thanks to an append-only log in the JSON Lines format outside the
working tree. Untrusted text, that is logs and command output, passes through the deterministic
protection against prompt injection and tool substitution `injection.py` before and after the call
to the model. Every execution and every access to the contents of logs is written to the immutable
audit log `audit.py`.

## The autopilot and the incident center

The background autopilot loop `autopilot.py` conducts observation, diagnosis, action and
verification of the result without operator involvement. Facts about the infrastructure are
gathered by the domain-agnostic symptom catalog `alerts.py`: pod restart storms, prolonged waiting
for scheduling (`Pending` or `Unschedulable`), filling of the file system and memory pressure on a
node, the inability to pull an image (`ImagePullBackOff`, `ErrImagePull`), significant cluster
events (`FailedScheduling`, `FailedMount` and others) and the approach of a TLS certificate's
expiry. All thresholds are moved into environment variables with the `AEGIL_` prefix and have
neutral default values, suitable for an arbitrary cluster without prior calibration.

The deterministic repair `remediate.py` launches safe fixes by symptom class, without relying on a
mandatory tool call by the model. Incidents are stored in the incident center `incidents.py` with
an explicit lifecycle and deduplication by fingerprint, so identical symptoms are grouped, and
specific pod names and numeric values are not part of the fingerprint. Repair outcomes `outcomes.py`
close the active-learning loop: the result of each intervention becomes a labeled example for
further training of the request router in the log-analysis service.

## Inference observability and the SLO gate

The `llm_metrics.py` module collects metrics of calls to the language model (latencies, tokens,
error share), and the SLO gate `slo.py` ties the agent's right to act autonomously to the
fulfillment of target indicators: on a violation of the error budget, autonomy itself lowers toward
more cautious behavior. The self-update module `updater.py` applies an owner-confirmed image update
through the release channel, and the application of an update always requires an explicit
confirmation and is not executed autonomously.

## Tools through the Model Context Protocol

The panel acts as a host of the Model Context Protocol (`mcp_tools.py`): the tools of connected open
servers are added to the agent's built-in tools. Most valuable are the read-only observability
servers (Grafana, Prometheus, Loki, Tempo), which extend the diagnosis with metrics, traces and
dashboards. Since a structured tool call is not classified by the gate by arguments, a conservative
rule applies: a server explicitly marked by the operator as `read_only` is executed freely, while
any unmarked server is by default treated as mutating and requires operator confirmation. The list
of servers is set by the `AEGIL_MCP_SERVERS` variable.

Actions on the nodes themselves are performed by the privileged node agent, available strictly
inside the cluster; the client to it is closed off by the token `AEGIL_NODEAGENT_TOKEN`. The client
of the log-analysis service is separated into `rca_client.py`, the client of the language model
into `llm.py`, the cluster client into `k8s.py`.

## Voice input

Request input and the reading-aloud of responses are available through the Web Speech API (the
microphone and speaker buttons in the PWA header), with a soft disable on browsers without support.

## Running (locally)

```
pip install -r requirements.txt
AEGIL_OPERATORS="max:$(openssl rand -hex 24)" AEGIL_RCA_URL=http://127.0.0.1:9107 \
  uvicorn app:app --host 127.0.0.1 --port 9109
```

Open `http://127.0.0.1:9109` (or the tunnel address), enter an operator token and type `/help`. For
the agentic loop, set access to the language model: `AEGIL_LLM_PROVIDER` (`anthropic` by default or
an openai-compatible one), `AEGIL_LLM_MODEL`, `AEGIL_LLM_API_KEY` and, for your own model in the
cluster, `AEGIL_LLM_BASE_URL`.

## Deployment to a cluster

The panel is installed with the Helm chart `deploy/helm/aegil` (the `40-agent-panel` template) or
the raw manifest `deploy/k8s`. The panel secrets (`AEGIL_OPERATORS` and the `AEGIL_NODEAGENT_TOKEN`
shared with the node agent) are placed in the `aegil-secrets` secret. The service is not published
externally; access is through `kubectl -n aegil port-forward svc/agent-panel 9109:9109` over a
tunnel.

## Tests

All components are covered by unit tests that need no network and no external dependencies:

```
cd services/agent-panel
for t in test_*.py; do python3 "$t"; done
```

Covered are the agentic loop and the confirmation path, the deterministic policy classifier and its
resistance to bypasses, all guards with state persistence, the symptom catalog on mock data,
incident deduplication by fingerprint, audit recording, injection protection, deterministic repair,
outcomes and active learning, inference metrics and the SLO gate, the Model Context Protocol host,
the node-agent client and self-updating.

## Environment variables

The full list of product configuration with the single `AEGIL_` prefix is described in the root
`.env.example` and in `docs/CONVENTIONS.md`. The key ones for the panel: `AEGIL_OPERATORS` (the
operator allowlist, the sole entry point, mandatory), `AEGIL_AUTONOMY` (the autonomy level),
`AEGIL_RESTART_ALLOWLIST` and `AEGIL_RESTART_DENYLIST` (the lists of services that may and may not
be restarted), `AEGIL_PROTECTED_PATTERNS` (protected resources, always behind confirmation),
`AEGIL_RCA_URL`, `AEGIL_LLM_PROVIDER`, `AEGIL_LLM_MODEL`, `AEGIL_LLM_API_KEY`, `AEGIL_LLM_BASE_URL`,
`AEGIL_NODEAGENT_TOKEN`, `AEGIL_MCP_SERVERS`, the symptom-catalog thresholds
(`AEGIL_RESTART_STORM_THRESHOLD`, `AEGIL_PENDING_AGE_SECONDS`, `AEGIL_DISK_WARN`, `AEGIL_DISK_CRIT`,
`AEGIL_MEM_WARN`, `AEGIL_TLS_WARN_DAYS`, `AEGIL_TLS_HIGH_DAYS`).
