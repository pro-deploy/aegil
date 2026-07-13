# Aegil

> **English** | [Русский](README.ru.md)

An autonomous Site Reliability Engineering (SRE) and DevOps agent for Kubernetes with
deterministic log analysis. The product connects to any cluster and to logging and monitoring
systems, observes state on its own, diagnoses problems from facts and remediates infrastructure
issues, while the operator talks to it through an ordinary natural-language chat. The language
model acts through real tools (cluster commands and node commands), but operates within
deterministic bounds: a command-danger classifier, guards against looping, confirmation for
irreversible actions, and a full audit trail.

The product was carved out as a standalone offering from an audio-processing platform where it
grew (decisions ADR-0032 logging and RCA, ADR-0033 the panel, ADR-0037/0038 the autonomous agent,
ADR-0041 the command executor and node-agent, see docs/adr). The extraction boundary is described
in docs/BOUNDARY.md.

## What it does

It observes the cluster (pods, nodes, events), the nodes (disks, processor, memory, processes via
the privileged node-agent), the logs (Loki) and the traces (Tempo, optional). The deterministic
Root Cause Analysis (RCA) pipeline normalizes logs, aggregates facts in a single pass, runs a
catalog of detectors, computes confidence and assembles a verdict with an evidence registry in
which every assertion rests on a verbatim quote from a log line. A lightweight trained SetFit
classifier routes requests and is further trained on the hard cases escalated to the large model
(active learning). Incidents are stored permanently with an explicit lifecycle. The chat agent
understands an arbitrary request, inspects and repairs on its own, and explains every step.

## Components

The product is four images plus an optional observability stack.

`services/node-agent` is a privileged DaemonSet that executes commands on node hosts through
nsenter strictly as an argument list without a shell, is closed off by a token, and is not
published externally. It gives the agent root on the nodes for disk cleanup, process inspection
and memory inspection.

`services/agent-panel` is a FastAPI panel: the chat interface, the agentic tool-use loop
(agent_exec), the deterministic policy classifier (policy), the anti-looping guards (guards), the
incident center (incidents), the cluster client (k8s), the status summaries (status), and the
alert catalog and autopilot (alerts, autopilot). Clients of external systems are separated into
llm.py and rca_client.py, and the application actions of the target application into the optional
app_adapter.py.

`services/rca` is the deterministic log-analysis service: normalization, aggregator, detectors,
scoring, verdict, and the routing cascade with active learning.

`services/rca-trainer` is a CronJob that further trains the SetFit classifier on accumulated
examples and uploads the model to object storage.

The observability stack (Loki, Alloy, Tempo, OpenTelemetry Collector, Grafana) in deploy/k8s is
optional: if you already have Loki and Grafana, connect the product to them rather than deploying
your own.

## What it connects to

Kubernetes (in-cluster service account or kubeconfig), a Loki log store (query_range), a language
model over a compatible protocol (vLLM, Ollama or another proxy that returns text on
POST /completion), optionally Tempo and OpenTelemetry for traces, and object storage for the
trained model. Everything is set through environment variables, see .env.example.

## Autonomy model and safety

By default the agent runs in a dry run: it observes and escalates but does not act until
AGENT_AUTONOMOUS is enabled. In autonomous mode, reads and safe repairs (restarting services from
the allowlist, cleaning up a node, returning tasks to the queue) run immediately, while finance
and destructive actions (deleting data, dropping tables, tearing down volumes) always require
operator confirmation. The class of every command is decided by the deterministic classifier in
policy.py outside the model, so the model cannot bypass confirmation, and an unknown mutating
command is treated as dangerous. Guards limit the rate of actions, impose cooldowns, trip a
circuit breaker after a streak of failures, and an oscillation detector blocks cross pairs. Every
execution is written to the audit trail. There is a manual mode in which the agent gathers facts
and proposes options, and the operator picks one or supplies their own command.

## Deployment

Build and publish the images (set REGISTRY):

```bash
REGISTRY=registry.example.com:5000 deploy/build.sh
```

In deploy/k8s/*.yaml replace the REGISTRY_PLACEHOLDER placeholder with your registry, and check
the namespace, the storage class and the node-role label against your cluster (the manifests were
carried over from the original platform and need review). Create the panel and node-agent secrets:

```bash
kubectl -n aegil create secret generic panel-secrets \
  --from-literal=PANEL_OPERATORS="admin:$(openssl rand -hex 24)"
TOK=$(openssl rand -hex 24)
kubectl -n aegil create secret generic nodeagent-secrets --from-literal=NODEAGENT_TOKEN="$TOK"
kubectl -n aegil patch secret panel-secrets --type merge \
  -p "{\"stringData\":{\"NODEAGENT_TOKEN\":\"$TOK\"}}"
kubectl apply -f deploy/k8s/
```

The panel is not exposed externally. Access it through a tunnel:

```bash
kubectl -n aegil port-forward svc/agent-panel 9109:9109
```

and open http://127.0.0.1:9109 in a browser, logging in with an operator token.

## Tests

All components are covered by tests that need no network and no external dependencies:

```bash
cd services/agent-panel && for t in test_*.py; do python3 "$t"; done
cd ../rca && for t in test_*.py; do python3 "$t"; done
cd ../node-agent && python3 test_node_agent.py
cd ../rca-trainer && for t in test_*.py; do python3 "$t"; done
```

## Status

Version 0.1.0, extraction from the original platform. The core (observation, RCA, agent,
node-agent) works and is covered by tests. Still to be finished for a clean product: full
parameterization of detectors and alert thresholds, review of the carried-over manifests against a
specific cluster, a Helm chart, and documentation of the application-adapter contract.
