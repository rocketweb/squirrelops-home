# Security model

SquirrelOps Home separates the desktop app, unprivileged sensor, and root
network helper. The app and sensor communicate with mutual TLS after a
one-time pairing flow. The helper's network-operation socket accepts only root
and the dedicated sensor UID. A separate signed-app XPC service is limited to
local certificate enrollment.

## macOS sandbox boundary

The app and helper are intentionally not App Sandbox processes. The desktop
app inspects the system LaunchDaemon state, invokes `launchctl`, and supports a
source-development Unix pairing socket. The helper must own Unix sockets and
state under `/var`, execute fixed system networking tools, and update packet
filter and interface state. Those operations are incompatible with the App
Sandbox entitlement model used by Mac App Store apps.

Signed builds use Hardened Runtime for both executables. Library-validation
disabling entitlements are forbidden. The helper remains a narrowly
authorized service rather than moving root privileges into the app or sensor.

## LAN API exposure

The production sensor listens on all IPv4 interfaces so a paired app elsewhere
on the LAN can reach it. Every protected HTTP route requires a verified client
certificate, the WebSocket authenticates the same certificate, proxy headers
are ignored, and plaintext development authentication is restricted to a
literal loopback peer. mDNS is discovery only and is not an authorization
boundary.

Control WebSocket frames must be JSON objects. Malformed authentication is
rejected; malformed messages after authentication close the connection with a
protocol error. Replay cursors must be nonnegative signed-64-bit integers, not
booleans or coerced strings. These checks apply to the management API, not to
decoy protocols.

Remote pairing and local enrollment use the same nonempty, trimmed client name
with a 128-character maximum and no ASCII control characters. The app aborts
remote pairing if secure nonce generation fails, before sending a proof or
storing credentials.

## Automatic local enrollment

The signed macOS package installs the app, unprivileged sensor, and root helper
together, but they remain separate processes. Bundling does not remove a trust
boundary or place the sensor's LAN API in the root helper.

The app generates a P-256 private key in macOS Keychain and sends only a
certificate signing request to the helper. The helper's enrollment Mach
service requires the `com.squirrelops.home` signing identifier, the release
Team ID, an Apple generic code-signing anchor, and the current console UID. It
does not expose the helper's network RPC methods to the app.

The app also pins the privileged helper before resuming its outbound XPC
connection. Developer ID releases require the `com.squirrelops.helper`
identifier, release Team ID, and Apple signing anchor. Explicit local-test
packages instead require the exact designated `cdhash` of the root-owned,
non-writable helper installed at the fixed privileged-helper path.

The helper forwards a bounded JSON enrollment request to
`/Library/SquirrelOps/sensor/run/enrollment.sock`. The socket is mode `0600`,
is made private before it begins listening, and the sensor verifies that the
connecting peer UID is root. A stale non-directory entry at that exact path is
removed without following symlinks so an interrupted launch cannot block the
sensor from restarting. There is no local enrollment HTTP endpoint and no
enrollment listener on the LAN.

The sensor issues a short-lived pending client certificate. The app must then
connect to the protected API with that certificate and confirm the matching
fingerprint before the pairing becomes active. Pending enrollments expire
after five minutes, are capped, and use idempotent request identifiers so a
response-loss retry cannot create another certificate or substitute another
CSR. Authentication lookups ignore all pending rows.

Developer ID releases keep one stable Keychain service and code requirement
across upgrades. Explicit ad-hoc local-test packages instead carry a unique
build UUID and store their credentials in an isolated Keychain service. A test
build therefore never broadens an existing item's access list or reads private
keys protected for a different ad-hoc CDHash. The UUID is isolation metadata,
not an authorization secret. Production packages do not contain it.

For an explicit local-test package, the helper copies the exact `cdhash`
designated requirement from the root-owned app installed in `/Applications`
and applies it to the enrollment Mach service. It refuses local enrollment if
the app, marker, or containing bundle directories are not root-owned or are
writable by another user. A generic ad-hoc bundle identifier is never enough.
Developer ID releases do not use this exception and continue to require the
fixed app identifier, Team ID, and Apple signing anchor.

Package scripts run inside the single administrator-approved Installer
transaction. The sensor script verifies helper compatibility, launchd job
ownership, and a stable daemon handoff. Long persisted-decoy restoration stays
inside the unprivileged sensor supervised by launchd. Installer does not gain
or retain root authority on behalf of the app after the transaction finishes.
If post-move validation rejects a newly installed helper or launchd plist, the
app package removes that unverified privileged artifact before failing.

## Development setup-key socket

The cross-user Unix pairing socket is disabled in packaged production
configuration. Source development can explicitly enable it with
`pairing.allow_unsigned_local`. Its permissive filesystem mode only permits a
console-user connection; peer UID and macOS audit-token validation remain the
authorization boundary. The parent directory is not writable by the console
user, and the server refuses to replace a non-socket path.

## Untrusted LAN device probes

SSDP and Scout probes may connect to self-signed HTTPS services. Certificate
verification is intentionally disabled only for these credential-free
fingerprinting requests. Targets are restricted to private LAN addresses,
SSDP description requests are pinned to the UDP responder address, redirects
and environment proxies are disabled, and response sizes and deadlines are
bounded. Probe results are untrusted observations, never authentication input.

## Deep-decoy guest boundary

### macOS virtual-IP forwarding

The helper renders redirects without an unconditional `rdr pass`. Each redirect
sets a private PF tag. A separate TCP filter rule requires that tag, the exact
destination, the selected ingress interface, and the kernel-observed socket
owner UID. The helper resolves `_squirrelops` itself; an RPC caller cannot
choose the allowed UID. Missing, root, or unknown UIDs cannot authorize TCP
publication. Untagged backend-port probes and other traffic still reach the
virtual IP's default-deny rule. ICMP echo behavior is unchanged.

The pre-load and post-load exact listener checks remain. The kernel rule adds
a UID boundary, not process-ID pinning. If a post-load check fails, the helper
attempts block-only quarantine and connection-state cleanup independently.
Failure on one endpoint does not skip cleanup of later endpoints. Incomplete
recovery returns an error, retains cleanup work for retry, and cannot authorize
a new alias publication from the cached state.

Existing PF states can bypass new filter evaluation. Endpoint and allowed-UID
changes therefore require state cleanup; a guarded rule is not proof that all
old states are gone. Rule-generation tests, injected recovery failures, and the
macOS syntax parser cover the source change. Live listener replacement, state
reuse, upgrade from older rules, and second-machine LAN acceptance remain
release gates. See the [PF safety development record](testing/2026-09-26-pf-safety-development.md).

### Disposable guest

The 2.1 Studio Build Mac runs real OpenSSH and Samba inside a disposable
Virtualization.framework guest, not inside the sensor or privileged helper.
The separately signed guest runtime is unprivileged. Its virtual machine has
no network device, persistent disk, shared directory, clipboard, USB, camera,
microphone, audio, graphics, or input device. A fixed Virtio socket device is
its only application data path.

The sensor generates one bounded persona archive in memory and writes it to
the runtime's anonymous standard-input pipe. The runtime transfers it once to
the guest. The guest cannot read the sensor's filesystem or initiate a LAN or
internet connection. SSH and SMB listeners are opaque byte relays to two fixed
guest socket ports, under the same connection ceiling as the VM. Neither the
sensor nor runtime parses attacker-controlled SSH or SMB messages.

The shared host ceiling remains 16 connections. A guest socket must connect
within 10 seconds; a missed callback invalidates that VM's connector and stops
the runtime rather than accumulating uncancellable Virtio requests. Late
callbacks close their sockets. Active relays expire after five minutes without
byte progress, or 30 seconds without progress after either direction reaches
EOF. Progress renews the applicable deadline; active transfers have no absolute
session-duration limit. Cancellation interrupts I/O but retains descriptor
ownership and admission until both workers finish. Nonblocking I/O and bounded
polls let workers observe cancellation even if socket shutdown misses a wakeup.

Guest sshd exempts `127.0.0.1/32` from per-source penalties because every Virtio
relay appears at that address. Its `MaxStartups 16` matches the host ceiling.
This prevents one visitor's scan from penalizing all later SSH visitors.
Connection evidence distinguishes guest-connected, capacity-rejected,
guest-connect-failed, and guest-connect-timeout outcomes. Rejected attempts
remain decoy hits; a connected guest channel is not proof of authentication.

The guest kernel, initramfs, containment declaration, resources, services, and
SHA-256 digests are validated before packaging and again before launch. Release
artifacts must be root-owned and non-writable by other accounts. A linked,
writable, oversized, wrong-architecture, missing, or malformed artifact leaves
the host degraded with packet-filter deny rules in place.

Ollama, OpenAI-compatible, and MCP presentations run as bounded unprivileged
sensor listeners on private backend ports. They accept limited request sizes
and deadlines, return only synthetic data, and persist only source address,
classified intent, narrative stage, and decoy evidence. They do not invoke a
model, tool, repository, command, or external service.

## Secrets and executable integrity

### AI setup diagnostics

The paired-client-only `POST /config/ai/models` and `POST /config/ai/test` routes
use a snapshot of the sensor's saved AI configuration and credentials. They
accept no caller-supplied prompt, device data, or destination. Cloud provider
origins stay fixed; custom destinations must be explicitly configured. Redirects
and environment proxies are disabled, TLS verification stays enabled, and URLs
with embedded credentials, query strings, or fragments are rejected.

Discovery is bounded to five catalog pages, 1,000 models, and 2 MiB per response.
Generation tests use synthetic fixtures, two requests of at most 512 output
tokens each, and the production prompts/parsers. Each diagnostic has a
50-second overall deadline. One diagnostic can run at a time, with at most six
starts per minute per sensor. These limits apply only to the management API.
No decoy protocol is changed. Upstream error bodies and exception strings are
not returned to the app. Configuration changes during a request invalidate its
result; the UI separately rejects completions from an older settings revision.

### Stored secrets

TLS keys and configuration credentials are stored in the encrypted secret
store. Runtime YAML contains non-secret configuration only. Legacy plaintext
configuration credentials are migrated and scrubbed at startup.

Python components resolve operating-system tools through an absolute path
allowlist, never the service `PATH`. An allow-listed path is accepted only if
the resolved binary is a root-owned, non-group/other-writable regular
executable, and every directory along both the literal and resolved paths is
root-owned and not group/other writable. Symlink chains are followed rather
than rejected, because the packaged Linux layout routes these tools through
`/etc/alternatives`; directory write permission, not link ownership, is what
governs whether a name can be swapped.

A tool that is simply absent resolves to an absolute path so the caller fails
with `FileNotFoundError` and never falls back to `PATH`. A tool that is present
but fails the trust check raises `UntrustedExecutableError`, which is never
reported as an ordinary operational failure:

- Paths that execute as root (`iptables-restore`, `iptables-save`, `ip addr`,
  `nmap`) log at CRITICAL and re-raise. Refusing to run an untrusted binary as
  root is not a degraded mode.
- Best-effort probes (mDNS and decoy interface enumeration) still degrade to an
  empty result, because a bind-address lookup should not take the sensor down,
  but they log the refusal at ERROR rather than folding it into a DEBUG line.

Dynamic Python plugins are accepted only from a non-writable directory and
regular files owned by an explicitly trusted UID. Packaged operation does not
currently load third-party plugins.
