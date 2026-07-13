# aegil roadmap: what is missing and where to add it

> **English** | [Русский](ROADMAP.ru.md)

This document records the product's gaps relative to the expectations of Site Reliability
Engineering (SRE) engineers, Development and Operations (DevOps) engineers and Machine Learning
model operations (MLOps and LLMOps) engineers, as well as relative to the requirements of the
markets of the United States of America and the Russian Federation. Each item is tied to the
module of the codebase where it should be added, and is annotated with a priority estimate. The
purpose of the document is not to implement everything at once, but to ensure that nothing missing
gets lost and that the order of work is obvious.

## 1. The engineering core: a foundation common to all markets

### 1.1. A service-level-objective language (high priority)

At present, autonomous repair is triggered by the abstract confidence of the Bayesian scoring,
whereas mature operations teams think in terms of service-level objectives (SLO), service-level
indicators (SLI) and an error budget. What is missing is a layer that links a root-cause verdict
to the violation of a specific business threshold and only then raises autonomy. Add a
configuration of objectives (availability, share of successful requests, latency at a percentile)
and a calculation of the remaining error budget, and tie the danger gate in
`services/agent-panel/policy.py` and the loop in `services/agent-panel/autopilot.py` to budget
exhaustion: while the budget is intact, act conservatively; when it burns down, permit more
decisive repair. This moves the product to the language spoken by SRE-level buyers.

### 1.2. Telemetry completeness: metrics and traces (high priority)

The root-cause engine in `services/rca` reads only logs. For full analysis it also needs metrics
and distributed traces per the OpenTelemetry standard. Add to the aggregator
`services/rca/aggregator.py` and the detector catalog `services/rca/detectors.py` the intake of
metric time series (processor and memory load, error share, latencies) and correlation by trace
identifier through a separate trace receiver. This closes the class of incidents invisible in
logs: resource saturation, latency degradation, connection-pool exhaustion. Arrange the telemetry
receiver next to `services/rca/loki.py` as a parallel source, rather than rewriting the existing
one.

### 1.3. Provable safety of the agent itself (high priority)

An autonomous agent with the right to change the cluster itself becomes an attack surface. Action
auditing in `services/agent-panel/audit.py` and the guards in `services/agent-panel/guards.py`
already exist, but three things are missing. First, protection against prompt injection and tool
substitution: the contents of logs and tool output must be treated as data, not commands, and this
rule must be wired into the system prompt and into the parsing of the model's response in
`services/agent-panel/agent_exec.py`. Second, a mandatory human in the loop for irreversible
operations with a cryptographically one-time confirmation, which is partly implemented and must
become non-disableable for the destructive class. Third, the principle of least privilege at the
level of the Kubernetes role model: manifests must grant rights strictly per namespace, without
cluster roles by default.

### 1.4. Observability of the inference itself, the MLOps and LLMOps layer (medium priority)

The product uses a language model but does not observe it. What is needed is the collection of
inference metrics: response latency, the number of input and output tokens, estimated cost, the
share of model refusals and timeouts, and control of quality drift in responses through a fixed set
of check requests. Add this to the model client `services/agent-panel/llm.py` as a metrics wrapper
and surface it on a separate panel in the interface. For MLOps teams this turns aegil from a
consumer of the model into a tool that itself watches the model's health, including detection of
hallucinations through the grounding guard already built into `services/rca/verdict.py`.

### 1.5. Learning from outcomes and postmortems (medium priority)

Closing a repair outcome into a training example is partly built into `services/rca-trainer`, but
what is missing is the automatic generation of a postmortem for a completed incident: a summary of
the timeline, the root cause, the actions taken, what worked, what did not, and suggestions for
prevention. This is valued both in the blameless-review culture of the United States and in the
reporting of Russian operations services. Implement it as the formation of a report over
already-computed facts through the model in `services/agent-panel`, with saving into the incident
feed.

## 2. The United States of America market

Here the product is sold as one more auditable node in a well-tuned pipeline, so open integrations
and conformance with accepted practices decide the matter.

Missing are integrations with the existing alerting and observability ecosystem: the intake and
dispatch of events into on-call systems (PagerDuty, Opsgenie), two-way connection with Grafana and
metric systems (Prometheus, Datadog), and the publication of aegil's own metrics in the
OpenMetrics format. Arrange this as a set of channel adapters next to the existing alerting layer.

Missing is support for the everything-as-code practice and management through a repository:
integration with ArgoCD and Flux so that repair proceeds not by direct change to the cluster but
through a merge request or synchronization, and policy as code through OPA Gatekeeper or Kyverno so
that the actions permitted to the agent are described declaratively and checked outside the agent's
code.

Missing is supply-chain security: generation of a software bill of materials (SBOM) for the built
images, signing of artifacts through Sigstore, and conformance with the Supply-chain Levels for
Software Artifacts (SLSA). Add this to the build script `deploy/build.sh` and to the
continuous-integration pipeline.

Missing is confirmed conformance with audit frameworks: logging and access separation under the
requirements of SOC 2 and the ISO 27001 standard, and, for work with the public sector, the
prospect of conformance with the FedRAMP program. Technically this rests on the already-existing
immutable audit, but requires the formalization of retention and access policies.

## 3. The Russian Federation market

Here the weight shifts toward autonomy from external services and conformance with national
regulation, and this becomes not a constraint but a commercial advantage.

The key part is already partly done: operation in a closed loop without external internet and
strictly on one's own model, which is confirmed by a run on a local server with a model of the
Gemma family in vLLM. What is needed is to bring the full-autonomy-from-cloud mode to a
configuration default and to remove any mandatory outbound calls.

Missing is confirmed compatibility with domestic container-orchestration platforms (Deckhouse, the
Shturval platform) and operating systems (Astra Linux, RED OS): the manifests and images must be
tested on them too, and the base images must be built on a domestic or neutral foundation suitable
for a closed loop.

Missing is fulfillment of the requirements of the Federal Law on Personal Data (152-FZ): log
analysis may capture personal data, so anonymization and masking of sensitive fields on the input
of the aggregator `services/rca/aggregator.py` are needed, along with storage of data within the
customer's loop and recording of the facts of processing. Additionally, the requirements of the
Federal Service for Technical and Export Control for information-protection tools affect logging
and access separation.

Missing is the prospect of inclusion in the register of domestic software: this is a separate
organizational task, but it directly opens up government procurement, so it is worth keeping as a
goal and building the assembly and provenance of components in advance so that the register's
requirements can be satisfied.

## 4. The order of work

First the common foundation from section one, because it is equally needed by both markets and
raises the product's value for all three roles: the service-level-objective language, the intake
of metrics and traces, and agent safety. Then, depending on the target customer, deepening either
into the integrations and compliance of the United States market from section two, or into
autonomy from the cloud and national conformance of the Russian market from section three. The
layer of observability over the model itself and the generation of postmortems proceed in parallel
as a reinforcement valuable in both markets.
