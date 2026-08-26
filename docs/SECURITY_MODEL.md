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

## Automatic local enrollment

The signed macOS package installs the app, unprivileged sensor, and root helper
together, but they remain separate processes. Bundling does not remove a trust
boundary or place the sensor's LAN API in the root helper.

The app generates a P-256 private key in macOS Keychain and sends only a
certificate signing request to the helper. The helper's enrollment Mach
service requires the `com.squirrelops.home` signing identifier, the release
Team ID, an Apple generic code-signing anchor, and the current console UID. It
does not expose the helper's network RPC methods to the app.

The helper forwards a bounded JSON enrollment request to
`/Library/SquirrelOps/sensor/run/enrollment.sock`. The socket is mode `0600`,
and the sensor verifies that the connecting peer UID is root. There is no
local enrollment HTTP endpoint and no enrollment listener on the LAN.

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

## Secrets and executable integrity

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
