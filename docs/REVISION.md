# Quality revision of version 0.1.0 and the rewrite plan (historical document)

> **English** | [Русский](REVISION.ru.md)

> **Status: historical document, the plan has been carried out.** This is a report of a full audit
> of the version 0.1.0 codebase and the rewrite plan adopted on its basis, both drawn up BEFORE
> the work. All defects and all the legacy of the original audio platform (KROKKI, adminchat,
> gooseek, asr, diarize, tenants, billing, YooKassa) described below in the present tense refer to
> the state BEFORE the rewrite and are, as of now, RESOLVED: the product has been rewritten and
> renamed to Aegil, the legacy has been cleaned out, the configuration has been moved under the
> single `AEGIL_` prefix, the deterministic danger gate and the guards have been reinforced, the
> node agent has been closed off, and log and metric analysis has been made universal. The present
> tenses in the text below should be read as "as of the audit of version 0.1.0", not as facts
> about the current product. The document is preserved as an audit record and a justification of
> the adopted architecture; its descriptions should NOT be taken as current.

This document summarizes the result of a full audit of the version 0.1.0 codebase, conducted
before the complete rewrite of the product. The audit was performed as five independent passes by
zone (the panel's security core, the panel's web and application layer, the root-cause-analysis
service RCA, the privileged node agent node-agent, and infrastructure and deployment) and was
backed by the deterministic quality scanner ailc. Every file was read in full, and the
command-classifier bypass vectors were checked by mentally tracing the code.

## Overall conclusion

The product in its current form is unfit for release for two independent reasons. First, it does
not run in someone else's cluster at all, even before questions of quality: the manifests
reference secrets and config maps the product does not create, are pinned to the node labels of the
original two-node cluster, are fixed to legacy image tags, and the log-analysis service by default
analyzes the namespace of the original platform. Second, where it would run, its main protective
function, that is the deterministic command-danger classifier, is flawed at its very foundation,
and the privileged node agent is published onto the local network as an unencrypted root backdoor.
The deterministic scanner ailc, independently of human judgment, gave a score of zero out of a
hundred with thirty-one blocking decisions.

Separately, a systemic fact was established: the configuration module's claim of domain neutrality
is refuted by the model's system prompts, the detector catalog, the node-name synonyms, the
application adapter, the entire user interface and the documentation. The legacy of the original
platform (the names KROKKI, gooseek, adminchat, the asr and diarize services, billing, tenants)
pervades the code, the manifests and the documents, and the architectural decisions and
specifications describe the audio platform in full without a single mark of historicity.

## Registry of critical defects

### Command-execution security

The policy classifier is built on the incorrect model "only the first element of argv decides." The
"read-only" list includes universal process launchers, so commands of the form
`env rm -rf /var/lib/postgresql/data` and `find /var/lib/postgresql -delete` are classified as
harmless reads and executed immediately, without guards, without confirmation and without a record
in the audit. Path matching is done by raw string prefixes without normalization, so the traversal
`/tmp/../var/lib/postgresql/data` passes as a cache cleanup. SQL risk is assessed only by the text
in argv, so `psql -f wipe.sql` with a DROP operator inside the file passes as a read. The read path
in the agentic loop is not atomic with the guards at all (a race between the check and the
recording of the attempt), is not counted against the budget and is not audited, and deferred
confirmations are held in the process's memory without a binding to the initiator and are lost with
multiple workers. The audit log physically lies inside the working tree and is itself classified as
safe to delete, meaning the agent is capable of erasing its own traces.

### The privileged node agent

The execution code itself is written carefully (constant-time token comparison, honest protection
against injection through the argument list and the nsenter option separator), but the access model
is critically flawed. The manifest publishes a privileged god-mode endpoint through hostPort on all
network interfaces of every node, including the local network and the control node, which directly
contradicts the promise of in-cluster availability. There are no network policies at all, there is
no transport encryption, the token is a single static one for everything, travels in plaintext and
is sniffed on the local network. An unauthenticated slow stream of connections brings the pod down
because of the absence of a socket timeout and an unbounded thread pool. The full list of the
command's arguments is written to the log and leaks into the log store together with the passwords
and tokens that exploitation not infrequently passes as arguments.

### The autopilot's autonomous loop

When observation sources are unavailable, empty facts are treated as the absence of problems, and
all pending checks are marked as successfully resolved by the agent: the system's blindness is
counted as a repair. A single network exception at the moment of a restart freezes the incident
forever in the repairing state without escalation and without a trace. The confirmation card in the
interface reads non-existent fields of the server's response, so the operator sees an empty card
with no operation text, the control word is never requested, and the confirm button is active
immediately: an irreversible command is confirmed with a single blind click.

### Root-cause analysis

The reading of logs counts as a record only the internal JSON envelope of the original platform, so
ordinary text logs of Kubernetes pods (stack traces, panics, OOM-killer messages) are invisible to
all detectors, and in someone else's cluster the engine is blind on its main function. Scoring is
arranged so that a real spike of errors with a single triggered group yields a confidence below the
threshold and is declared health, whereas detectors correlated from a single wave of errors are
multiplied as independent evidence and produce a confidence of ninety-eight percent from two log
lines. The weights are declared calibratable, but neither the calibration nor the data for it
exists. The stuck-job analysis module is entirely a legacy of the audio pipeline and is subject to
removal. The tests are written so that the standard collector finds zero tests with a green CI.

### Deployment in someone else's cluster

The log-analysis and trainer pods reference a config map and a secret the product does not create
and crash at startup. The names and keys of the secrets in the instructions and in the panel
manifest diverge, and literal execution of the instructions yields a pod that does not come up.
Seven workloads are pinned to the node label of the original cluster and remain in eternal pending,
and the trainer is additionally pinned to a non-existent node with a foreign scheduling constraint.
The build script assembles everything under a single version, while the manifests are fixed to four
different legacy tags, so the built images are not pulled. The mandatory Postgres and object storage
are not mentioned in the documentation. There is not a single network policy, log collection runs
without a namespace filter and takes the logs of all namespaces of someone else's cluster.

## Per-verdict map of files

To be rewritten from scratch: the policy classifier and the agentic executor of the panel (an
incorrect foundation for the classification and execution of privileged commands), the autopilot
(blindness as success, freeze on exception, binding to someone else's domain), the alert-detector
catalogs and the panel's status summaries (they model a specific audio platform rather than the
universal symptoms of Kubernetes), the user interface (a broken confirmation contract, pervasive
foreign branding), the log reading and the RCA detector catalog with scoring (calibrated to
someone else's logging canon), and the README and access model of the node agent together with its
manifest. To be removed entirely: the stuck-job analysis module as an alien organ.

To be preserved and reinforced with targeted edits: the Kubernetes API access layer, the incident
lifecycle model, the panel's route skeleton, the anti-looping guards, the audit primitive, the RCA
fact aggregator and verdict module, the normalization, the routing cascade, the cache, and the node
agent at the level of the execution code. These modules are designed more sensibly than one might
have expected and do not require a rewrite.

## The adopted rewrite architecture

Under the mandate of a full carte blanche, the following guiding decisions were adopted. The
language-model layer is made universal with support for a full tool-call protocol (Anthropic and
the OpenAI-compatible API), with a cloud frontier model as the default for the sake of the quality
of agentic behavior, with the ability for the owner to specify their own model in the cluster. The
tooling is moved to the open Model Context Protocol ecosystem: the panel becomes a host, tools are
connected as ready-made open servers (Kubernetes, Grafana, Loki and others), and the node agent and
the RCA service are wrapped as their own tools of the same protocol. The deterministic danger gate
is preserved and turned into a configurable autonomy level, because it is precisely what
distinguishes the product from an arbitrary agent in the cluster and remains the only defense
against the destruction of data by a model hallucination. Turnkey operation is achieved through a
Helm chart, a first-run setup wizard in the interface, and storage of configuration in the cluster
with hot reload.

## The order of work

First comes the cleanup of the product's identity and the extraction of all configuration into a
single parameterizable contour, because without a clean foundation any rewrite would drag the
legacy further. Then the security core (the classifier and the executor) is rewritten for the new
tool-call model with the preservation and reinforcement of the guards and the audit. Next the node
agent and its access model are reinforced, and network policies and transport encryption are
introduced. Then the log analysis is rewritten for the universal intake of arbitrary Kubernetes
logs and correct scoring. After that the turnkey package is assembled (the Helm chart, the setup
wizard, the hot configuration) and the loop of self-learning and self-updating is closed. Each unit
of work is accompanied by rewritten tests that verify correct behavior rather than lock in the
current one.
