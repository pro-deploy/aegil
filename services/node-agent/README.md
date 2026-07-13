# node-agent

> **English** | [Русский](README.ru.md)

The privileged node agent of the aegil product. It is a tiny HTTP server built on the Python
standard library without external dependencies, which is deployed as a DaemonSet object with one pod
per cluster node and gives the agent panel the ability to execute operations commands directly on
the node's host.

## Purpose

The aegil panel is an autonomous operations agent that manages not only the application through the
Kubernetes API but also the nodes themselves. A significant part of operations lives past the
Kubernetes API: disk cleanup, prune of docker and containerd images and layers, observation through
df, du, top, free, uptime, per-core processor load, killing a hung process, restarting system
services through systemctl. All of this is performed on the host itself. node-agent executes the
passed list of arguments in the host's namespaces through `nsenter -t 1 -m -u -i -n -- <argv>` and
returns the return code, the output and the duration.

## Why privileged

The pod enters the namespaces of the process with identifier PID 1 (the host itself) and therefore
has superuser rights on the node. This is a deliberate price for the ability to actually repair the
node (free the disk, kill processes, restart services). The full `privileged: true` flag is
deliberately not used: for entry through nsenter into the mount, uts, ipc and net namespaces of the
PID 1 process, `hostPID: true` together with the `SYS_ADMIN` capability (the setns operation over
these namespaces) and `SYS_PTRACE` (operations over host processes) is sufficient. The container's
file system is mounted read-only, privilege escalation is forbidden, and all other capabilities are
dropped. Because of its privileged nature, the surface is closed off by several security frames at
once.

## The network access model

The service listens on the port `AEGIL_NODEAGENT_PORT` (default 9110) on the pod's address. The
node port is NOT published: there is neither hostPort nor hostNetwork in the manifest, so the
god-mode endpoint is not surfaced onto the node's interfaces and is unreachable from the local
network and from the control node. The panel calls the agent strictly in-cluster, at the pod's
address through an internal Service (ClusterIP, without external publication). Additionally, a
NetworkPolicy operates that admits incoming traffic to the agent's port only from the panel pod (by
its label) and drops everything else.

## API

The `GET /health` endpoint returns JSON of the form `{"status":"ok","node":"<node>"}` and serves the
readiness probe; a token is not required.

The `POST /run` endpoint executes a command. Authentication is performed BEFORE reading the request
body: the header must contain `X-NodeAgent-Token`, which is compared against the secret
`AEGIL_NODEAGENT_TOKEN` in constant time (`hmac.compare_digest`, both values cast to bytes). Without
a match, 401 is returned, the request body is not read at that point and nothing is executed
(fail-closed). The request body is JSON of the form `{"argv":["df","-h","/"],"timeout":30}`. The
`argv` field must be a non-empty list of strings with a limit on the number of elements and on the
total length, and `timeout` a number in the range from 1 to 600 seconds; a malformed body leads to a
400 response, a too-large body to a 413 response. The response has the form
`{"exit_code":int,"stdout":str,"stderr":str,"duration_ms":int,"node":str}`. The output on each of
the stdout and stderr streams is limited to 256 kilobytes, and on truncation the mark
`...[truncated]` is added. On a timeout overrun an `exit_code` of 124 is returned, along with the
corresponding mark in stderr, and the whole process group of the command is killed, not only the
direct descendant, so no orphan processes remain on the host.

## Environment variables

All product configuration lives under the single `AEGIL_` prefix. The `AEGIL_NODE_NAME` variable
sets the node name and arrives through the downward API from `spec.nodeName`; it is returned in
responses and lands in the logs. The `AEGIL_NODEAGENT_TOKEN` variable is the shared access secret,
the same one that is placed in the panel secret under the same key. The `AEGIL_NODEAGENT_PORT`
variable sets the listening port and defaults to 9110.

## Security

Access is closed off by a shared secret: without a valid `X-NodeAgent-Token` header the `/run`
endpoint responds 401 and executes nothing, and the service behaves fail-closed in exactly the same
way if the server-side secret is not set at all. Authentication is performed before reading the
body, so an unauthenticated request leads to no reading and execution. The service is reachable only
in-cluster (no Ingress, no publication of the node port) and is additionally fenced off by a network
policy. The key guarantee against shell injection is that the command is always passed as a list of
arguments (argv), and execution goes through subprocess without `shell=True` and without `sh -c`.
Shell metacharacters inside argv remain literal arguments and are not interpreted. The `--` separator
in the nsenter prefix cuts off an attempt to slip flags of nsenter itself into argv: everything
after `--` is treated as the program to execute and its arguments, not as options of nsenter. The
child process is passed a cleaned environment without the agent's secrets, so a command executed on
the node cannot read the token through `/proc/self/environ`. Against an unauthenticated slow stream
of connections (slowloris), a timeout is set on the socket, and the size of the request body is
bounded from above so that a huge `Content-Length` does not drive the pod into OOM.

## Logs

Logs are emitted to stdout in structured JSON: the fields `ts`, `level`, `service` equal to
`node-agent`, and `msg`, plus the execution context. Only the name of the executed program
(`argv[0]`) and the number of arguments are written to the log, but NOT the argument values, so
secrets passed as command-line arguments (passwords, tokens) do not leak into the log store. The
access token itself never lands in the log.

## Tests

The tests are in `test_node_agent.py` and are collected by the standard pytest collector; they need
no network. To run: `cd services/node-agent && python3 -m pytest -q`. They verify body validation,
size limits, the correct assembly of the nsenter command without turning argv into a shell string,
the cutting off by the `--` separator of an attempt to slip in nsenter flags, output truncation,
the masking of secrets in logs, the cleaning of the environment, the fail-closed refusal without a
token, and, at the HTTP level, the "authentication before reading the body" ordering: a request
without a token and with an incorrect token returns 401 and executes nothing. subprocess is mocked
in the process, and the real nsenter is not called.
