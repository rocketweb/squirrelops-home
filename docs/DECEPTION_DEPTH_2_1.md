# Deception Depth 2.1

## Product outcome

SquirrelOps Home 2.1 adds one coherent synthetic Mac environment whose SSH,
SMB, Bonjour, web, and agent-facing surfaces describe the same machine and
the same recent work. The flagship identity is a forgotten build Mac named
`studio-mini.local` used by a small mobile engineering team.

The deep decoy is not a collection of independent banners. Real OpenSSH and
Samba processes run inside a disposable Linux guest. The sensor and the host
runtime only relay opaque bytes and record bounded connection metadata. The
guest has no network device, host mount, shared clipboard, Keychain access,
or path to the operator's files.

## Release boundary

The 2.1 release requires all three artifacts to be present and verified together:

1. The sensor policy and narrative engine.
2. The signed macOS guest runtime built with Virtualization.framework.
3. The hash-pinned `studio-mini` guest bundle containing a Linux kernel and
   memory-only root filesystem with OpenSSH, Samba, and the guest relay.

Artifact presence is one requirement. Independent review, CI, live PF failure
cases, signed-installer acceptance, and publication are separate gates described
in [publication readiness](testing/2026-10-01-publication-readiness.md).

If the runtime or guest bundle is missing, malformed, writable by an
untrusted user, symlinked, or fails its digest check, the deep decoy is unavailable
or degraded. Ports 22 and 445 must not silently fall back to banner replay or the
legacy HTTP file-share presentation while the operator is shown a real
protocol decoy.

## Containment contract

The guest runtime is an unprivileged, separately signed process. Its virtual
machine configuration has:

- no virtual network device;
- no directory, file-system, clipboard, USB, camera, microphone, or graphics
  sharing;
- a Virtio socket device as its only application data channel;
- fixed CPU and memory ceilings;
- a fresh memory-only guest on every start;
- fixed host listeners that relay only to allowlisted guest socket ports;
- bounded connection concurrency and an operator kill switch;
- an anonymous, one-use pipe carrying the bounded persona archive from the
  dedicated sensor account.

The guest cannot initiate a LAN or internet connection because it has no
network adapter. Agent instructions, model output, planted credentials, and
visitor-created files remain inside the synthetic environment.

## Flagship synthetic world

| Surface | Presentation |
| --- | --- |
| Bonjour | `studio-mini.local`, SSH and SMB service records |
| SSH/SFTP | OpenSSH login for `buildbot`, recent shell and build activity |
| SMB | `Builds`, `Engineering`, and `Time Machine Backups` shares |
| Web | Internal build status, artifact index, and deployment notes |
| OpenAI-style API | Synthetic `/v1/models` and `/v1/chat/completions` responses; no inference |
| Ollama-style API | Synthetic `/api/tags`, `/api/show`, and `/api/chat` responses; no inference |
| MCP | Synthetic results for `list_projects`, `read_runbook`, `get_deployment`, and `search_secrets`; no real tool execution |
| Agent files | Synthetic `.codex`, `.claude`, `.cursor`, tool logs, and runbooks |

The Time Machine share advertises Samba's Apple extensions. A complete macOS
backup and restore has not been verified.

Every hostname, username, project, build number, timestamp, credential,
share, and deployment name must come from one persona document. The API and
guest seed tests reject cross-surface drift.

## Adaptive narrative

A campaign is keyed by decoy host and source address and survives a sensor
restart. Its world does not randomly change on each request. Evidence can
advance the campaign through these monotonic stages:

1. discovery;
2. browsing;
3. credential access;
4. agent tool use;
5. write activity.

The intent label is evidence-based and sticky. Simple service discovery stays
boring. Credential searches reveal synthetic rotation notes and planted
tokens. Developer and agent behavior discovers projects, MCP tools, model
configuration, and build runbooks. HTTP/MCP write-like requests can advance
the narrative. SSH/SMB telemetry records connection and relay outcomes only;
it does not inspect authentication, shell commands, or SMB file operations.
Guest file changes remain in memory and do not advance the host's campaign
from observed SMB writes. A visitor sees Finder-friendly names and familiar
Mac development artifacts on an underlying Linux guest.

No response instructs a visitor to contact real infrastructure. Any hostnames,
repositories, users, credentials, tickets, customer names, and deployments in
the world are synthetic.

## Deception review gates

Attacker-visible behavior requires an explicit deception review. The review
must include:

- byte-exact snapshots for the agent APIs and every fallback response;
- real `ssh` client negotiation and authenticated shell/SFTP acceptance;
- Finder and `smbutil` discovery, authentication, listing, read, and bounded
  write acceptance;
- Bonjour discovery from another LAN device;
- agreement checks across the guest files, SMB shares, shell history, model
  APIs, MCP results, HTTP pages, and alerts;
- guest attempts to read host files, open outbound connections, and create new
  host listeners, all of which must fail;
- stop, crash, restart, overload, upgrade, and uninstall behavior;
- proof that a missing or invalid guest artifact is reported as unavailable,
  never as an active real-protocol decoy.

Full VNC is outside the 2.1 release boundary. It remains a later guest surface
after SSH and SMB pass the isolation and realism gates above.
