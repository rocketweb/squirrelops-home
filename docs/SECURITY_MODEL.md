# Security model

SquirrelOps Home separates the desktop app, unprivileged sensor, and root
network helper. The app and sensor communicate with mutual TLS after a
one-time pairing flow. The helper accepts only root and the dedicated sensor
UID over a permission-restricted Unix socket.

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

## Local pairing socket

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
