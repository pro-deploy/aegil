# aegil product conventions

> **English** | [Русский](CONVENTIONS.ru.md)

A single contract, mandatory for all code, manifests and documentation. It was introduced during
the rewrite from the legacy administrator panel into a universal autonomous SRE agent for an
arbitrary Kubernetes cluster and an arbitrary application. Every module and every agent working on
the codebase is obliged to follow these conventions so that the result stays coherent.

## Identity

The product is called aegil. No mentions of the original platform (KROKKI, adminchat, gooseek, the
asr, diarize, worker services, tenants, billing, YooKassa, stalwart, the krokki.ru domains) must
remain anywhere: not in code, not in the model's prompts, not in manifests, not in the interface,
not in documentation, not in environment-variable names, and not in comments. The product is
domain-agnostic: it does not know the customer's service names or cluster topology in advance, but
discovers them through the Kubernetes API and through the configuration set by the owner at
installation time.

## Environment variables

A single `AEGIL_` prefix for all product configuration. Legacy names (ADMINCHAT_*, PANEL_*, as
well as the prefixless NAMESPACE, RCA_URL, LLM_SERVICE_URL, KROKKI_*) are abolished entirely, and
backward compatibility with them is not maintained. The canonical set:

The agent panel. `AEGIL_OPERATORS` (a comma-separated list of "operator:token", the sole entry
point, fail-closed), `AEGIL_NAMESPACE` (the observed and managed namespace, defaulting to the
value from the downward API or `default`), `AEGIL_NODE_ROLE_LABEL` (the node-role label for
friendly names, defaulting to `node-role.kubernetes.io/role`), `AEGIL_AUTONOMY` (the autonomy
level, see below), `AEGIL_RESTART_ALLOWLIST` and `AEGIL_RESTART_DENYLIST` (service lists),
`AEGIL_PROTECTED_PATTERNS` (resources and paths whose actions always require confirmation, set by
the owner, empty by default), `AEGIL_RCA_URL`, `AEGIL_NODEAGENT_TOKEN`, `AEGIL_NODEAGENT_TIMEOUT`.

The language model. `AEGIL_LLM_PROVIDER` (`anthropic` or `openai`, default `anthropic`),
`AEGIL_LLM_MODEL` (the model identifier), `AEGIL_LLM_API_KEY`, `AEGIL_LLM_BASE_URL` (optional, for
your own model in the cluster via vLLM, Ollama or a compatible proxy).

Observability. `AEGIL_LOKI_URL`, `AEGIL_LOKI_QUERY` (the stream selector, defaulting to
`{namespace="$AEGIL_NAMESPACE"}` without a hardcoded name), `AEGIL_GRAFANA_URL`,
`AEGIL_GRAFANA_TOKEN`.

The log-analysis service and the trainer. `AEGIL_LOKI_URL`, `AEGIL_POSTGRES_DSN`,
`AEGIL_S3_ENDPOINT`, `AEGIL_S3_ACCESS_KEY`, `AEGIL_S3_SECRET_KEY`, `AEGIL_S3_BUCKET`,
`AEGIL_MODEL_KEY_PREFIX`.

The node agent. `AEGIL_NODEAGENT_TOKEN`, `AEGIL_NODE_NAME` (from the downward API `spec.nodeName`),
`AEGIL_NODEAGENT_PORT`.

## Autonomy levels

The former boolean autonomous-repair flag is replaced by three explicit levels in the
`AEGIL_AUTONOMY` variable, chosen by the owner from the interface. The `observe` level (default) is
a dry run: the agent observes, diagnoses and proposes, but does not act. The `safe_repair` level
permits autonomous execution of commands in the read and safe_write classes, whereas destructive
and anything falling under `AEGIL_PROTECTED_PATTERNS` requires operator confirmation. The `full`
level grants full autonomy: everything is executed autonomously except the destructive class and
the protected patterns, which always remain behind confirmation, because that is the only defense
of data against a model hallucination. The decision about a command's class is made by the
deterministic classifier outside the model, so the model cannot raise its own privileges.

## Command danger classes

The classifier assigns a proposed action to one of three universal classes: `read` (read-only,
always autonomous), `safe_write` (reversible repair: restarting a service from the allowlist,
deleting a pod, scaling, clearing caches and temporary paths, freeing space), `destructive`
(irreversible: deleting data, volumes, namespaces, deployments, sets, DROP or TRUNCATE of tables,
mkfs, dd to a device, deletion of individual critical files). The legacy finance class is
abolished as domain-specific; its role (always confirm the sensitive) is taken over by the
configurable `AEGIL_PROTECTED_PATTERNS` mechanism into which the owner enters their protected
resources. The discipline is unchanged: an unknown mutating command is treated as destructive, and
the classifier always errs on the side of confirmation.

## Cluster topology

No hardcoded node, service or synonym names. The agent discovers topology through the Kubernetes
API: it enumerates nodes with a query to the cluster, takes friendly names from the
`AEGIL_NODE_ROLE_LABEL` label if it is set, and otherwise operates on node names as they are. The
model's system prompt contains no specific topology, but receives a current snapshot of the
cluster as a fact on the step's input.

## Tests

Tests are written to verify correct behavior, not to lock in the current behavior. The format is
one a standard collector can gather (functions with the `test_` prefix), so that CI is not green
on a zero collection. Negative checks are mandatory: real classifier-bypass vectors, behavior when
sources are unavailable, concurrent access, and the ordering of authentication before reading the
request body.

## Versioning

A single semantic version of the product for all images at once, each deployment under a new tag,
the tag recorded in git. No overwriting of a released tag in place. Versions in the chart, the
manifests and the registry are kept in agreement.
