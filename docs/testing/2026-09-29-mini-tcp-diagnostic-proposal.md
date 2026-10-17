# Mini TCP account-control diagnostic proposal

Date: 2026-09-29. Status: approved by Matt in this chat. Execution results are
recorded separately in the account-control diagnostic report. Matt subsequently
authorized one repeat with a changed Python script, after the successful v2 run.
This is diagnosis, not installed-package acceptance or closure of the A5 gate.

## Question

Does ordinary inbound TCP to the mini reach Python `accept()` and return a
fixed response when running as the sensor account, compared with the login
account? Previous virtual-IP flows completed TCP handshakes but were not
accepted by either Python or the Swift guest. Little Snitch's supplied history
contains no corresponding inbound TCP records.

## Approved bounds

- Server: Matt's mini, Tailscale management `100.108.203.27`, concrete Ethernet
  address `192.168.1.115` on `en0`.
- Client: authorized laptop `192.168.1.7`, through `wlp0s20f3`.
- At most two temporary TCP listeners. Each binds only `192.168.1.115`, using
  an OS-selected unused port in 49152 through 65535; no wildcard bind or port
  takeover. Verify allocated ports before client traffic.
- Both use the same installed, root-owned sensor Python executable and fixed
  standalone probe code. One process drops privileges to `_squirrelops`
  UID/GID 309; the other to `matt` UID 501, primary GID 20. Neither serves files,
  authenticates users, starts a shell or executes client-supplied content.
- Only the authorized laptop receives a fixed diagnostic response. Other peers
  are closed without a response. No real or synthetic credential is required.
- Per separately authorized run, maximum three connection/banner-read attempts
  per listener, six total. No
  scanning, authentication or file operations.
- Maximum observation window: 180 seconds, with an independent child deadline
  and bounded parent cleanup. A single attended administrator command starts
  both privilege-dropped processes and the read-only observations.

## Preconditions and preservation

Revalidate mini identity, route/address, account IDs and trusted executable
ownership/hash. Stop if the sensor/helper jobs or app have restarted, test VIPs
are assigned, selected ports are unavailable, or current PF state differs from
the stopped baseline. Do not adjust the host to make a precondition pass.

Create a uniquely named root-private diagnostic directory. Preserve the script,
scope, executable digest, baseline listener/process inventory and read-only
PF/interface snapshots there. Keep raw unrelated inventory private. Expose
only the probe ports, phase and scoped results needed to coordinate the client.

## Observations and inverse

Record client TCP-connect and banner-read outcomes separately. While a client
waits, capture the selected listeners' pending queues and matching socket rows,
process identities and content-filter counts. If packet tracing is needed,
limit it to the laptop, mini Ethernet address and the two allocated ports;
retain header-only text, not raw payload captures. Note any visible filter
prompt without accepting it or changing rules during the baseline.

On normal completion, failure, interrupt or deadline, terminate and reap only
the diagnostic's own child processes, close both sockets and stop its scoped
observer. Verify the ports are no longer listening and pre-existing services
remain present. Retain diagnostic files for review; do not delete product data.

There is no installer invocation, app/helper/sensor launch, VM, virtual IP,
proxy ARP, PF enable/reference/rule/state mutation, route change, filter disable,
VPN change, permission reset or persistent service. Native SSH, SMB, Screen
Sharing, Ollama, Tailscale and unrelated workloads remain untouched.

## Interpretation limits

- Both listeners work: ordinary inbound TCP for both UIDs works on the concrete
  host address. The virtual-IP/PF/filter interaction still needs reproduction.
- Only one works: focus on account/process policy differences; this alone does
  not identify a particular filter or prove launchd behaves the same way.
- Neither works: inspect wire delivery, pending queues and filter observations
  before choosing a narrower follow-up. Do not infer a product defect from a
  standalone listener failure.

The control intentionally excludes virtual-IP translation, launchd context,
ASGI, the guest runtime and virtualization. It cannot replace release testing.
No filter change is authorized by this proposal. Any later per-application
allow rule or comparison with a filter disabled requires a separate decision.

## Execution choices within the approved bounds

The first pass records socket queues and scoped socket rows without packet
capture. Both listener children clear supplementary groups and use isolated
Python with site initialization disabled. That makes the primary UID/GID
comparison explicit, but does not reproduce the normal login or launchd context.

The parent uses Apple's system Python. The installed sensor Python is used only
after dropping privileges. Each child has an independent absolute deadline and
an anonymous stdin lifeline: parent exit closes the lifeline and ends the child.
Cleanup can terminate only these directly spawned diagnostic children. No PID
discovered in the host inventory is signaled.

The laptop client makes exactly three interleaved attempts per allocated port,
separates connect success from banner timeout, and uses an exclusive result file
to refuse a second run from the same staging directory. Do not rerun either
attended command without reviewing the prior result. Root-private evidence and
sanitized diagnostic observations are retained; nothing is deleted.

## Authorized changed-script repeat (v3)

The only behavioral change for this run is the fixed response marker:
`SquirrelOps TCP diagnostic v3\r\n` (31 bytes). The laptop client must match that
new marker. Both listeners still use the identical installed Python executable
and the same isolated inline `-c` launch mechanism. The executable is not edited,
copied or re-signed. No filter setting or rule may be reset to force an alert.
All addresses, accounts, duration, six-attempt limit and cleanup bounds above
remain in force. A new prompt is an observation, not an assumed outcome.
