import Foundation
import Testing
@testable import SquirrelOpsDeceptionGuest

/// Guest `sshd`/`smbd` only ever see the relay at 127.0.0.1, so the LAN peer
/// has to be recovered from the host-chosen source port. These pin both halves:
/// the log-line parser and the port-to-peer table.
/// A settable clock the table can read from a `@Sendable` closure.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: TimeInterval
    init(_ value: TimeInterval) { self.value = value }
    var now: TimeInterval {
        get { lock.lock(); defer { lock.unlock() }; return value }
        set { lock.lock(); value = newValue; lock.unlock() }
    }
}

@Suite("Guest authentication attribution")
struct GuestAuthenticationTests {

    // MARK: Parser

    @Test("sshd accepted password login is parsed with its relay port")
    func parsesAcceptedSSH() {
        let line = "Oct 17 19:14:14 studio-mini auth.info sshd-session[25]: Accepted password for buildbot from 127.0.0.1 port 23456 ssh2"
        #expect(GuestAuthenticationParser.parse(line) == GuestAuthenticationEvent(
            service: .ssh, accepted: true, username: "buildbot", method: "password", localPort: 23456
        ))
    }

    @Test("sshd failed login, including an invalid user, is parsed")
    func parsesFailedSSH() {
        let known = "Oct 17 19:14:14 studio-mini auth.info sshd-session[32]: Failed password for buildbot from 127.0.0.1 port 23457 ssh2"
        let invalid = "Oct 17 19:14:14 studio-mini auth.info sshd-session[37]: Failed password for invalid user root from 127.0.0.1 port 23458 ssh2"
        #expect(GuestAuthenticationParser.parse(known)?.accepted == false)
        #expect(GuestAuthenticationParser.parse(known)?.username == "buildbot")
        #expect(GuestAuthenticationParser.parse(invalid) == GuestAuthenticationEvent(
            service: .ssh, accepted: false, username: "root", method: "password", localPort: 23458
        ))
    }

    @Test("Samba auth_audit success and failure lines are parsed")
    func parsesSamba() {
        let ok = #"Oct 17 16:12:19 studio-mini daemon.notice smbd[28]:   Auth: [SMB2,(null)] user [HAWTHORN]\[buildbot] at [Sat, 17 Oct 2026 16:12:19.163147 UTC] with [NTLMv2] status [NT_STATUS_OK] workstation [MACBOOK] remote host [ipv4:127.0.0.1:24000] became [MACBOOK]\[buildbot] [S-1-5-21-1]. local host [ipv4:127.0.0.1:445] "#
        let bad = #"Oct 17 16:12:19 studio-mini daemon.notice smbd[28]:   Auth: [SMB2,(null)] user [HAWTHORN]\[buildbot] at [Sat, 17 Oct 2026 16:12:19.198895 UTC] with [NTLMv2] status [NT_STATUS_WRONG_PASSWORD] workstation [MACBOOK] remote host [ipv4:127.0.0.1:24001] mapped to [HAWTHORN]\[buildbot]. local host [ipv4:127.0.0.1:445] "#
        #expect(GuestAuthenticationParser.parse(ok) == GuestAuthenticationEvent(
            service: .smb, accepted: true, username: "buildbot", method: "NTLMv2", localPort: 24000
        ))
        #expect(GuestAuthenticationParser.parse(bad) == GuestAuthenticationEvent(
            service: .smb, accepted: false, username: "buildbot", method: "NTLMv2", localPort: 24001
        ))
    }

    @Test("Legacy single-process sshd tag is still accepted")
    func acceptsLegacySSHTag() {
        let line = "Oct 17 16:12:21 studio-mini auth.info sshd[123]: Accepted password for buildbot from 127.0.0.1 port 23456 ssh2"
        #expect(GuestAuthenticationParser.parse(line)?.accepted == true)
    }

    @Test("Unrelated, oversized, and non-loopback lines are ignored")
    func ignoresNoise() {
        // Real neighbours of the auth lines in the guest ring, captured live.
        #expect(GuestAuthenticationParser.parse("Oct 17 19:14:14 studio-mini auth.info sshd-session[27]: Disconnected from user buildbot 127.0.0.1 port 60488") == nil)
        #expect(GuestAuthenticationParser.parse("Oct 17 19:14:14 studio-mini auth.info sshd-session[32]: Connection closed by authenticating user buildbot 127.0.0.1 port 60500 [preauth]") == nil)
        #expect(GuestAuthenticationParser.parse("Oct 17 16:12:19 studio-mini daemon.notice smbd[28]: [2026/10/17 16:12:19.160151,  3] ../../auth/gensec/gensec_start.c:1052(gensec_register)") == nil)
        #expect(GuestAuthenticationParser.parse(#"{"timestamp": "2026-10-17T16:12:19+0000", "type": "Authentication", "Authentication": {"status": "NT_STATUS_OK"}}"#) == nil)
        // Only the relay address is a valid origin; anything else is not ours.
        #expect(GuestAuthenticationParser.parse("sshd[1]: Accepted password for buildbot from 10.0.0.9 port 23456 ssh2") == nil)
        // A username is attacker-chosen input; control characters and brackets never leave the guest.
        #expect(GuestAuthenticationParser.parse("sshd[1]: Accepted password for bad\u{1b}[0m from 127.0.0.1 port 23456 ssh2") == nil)
        #expect(GuestAuthenticationParser.parse("sshd[1]: Accepted password for " + String(repeating: "a", count: 65) + " from 127.0.0.1 port 23456 ssh2") == nil)
        #expect(GuestAuthenticationParser.parse(String(repeating: "x", count: GuestAuthenticationParser.maximumLineLength + 1)) == nil)
        #expect(GuestAuthenticationParser.parse("sshd[1]: Accepted password for buildbot from 127.0.0.1 port 70000 ssh2") == nil)
    }

    // MARK: Attribution table

    @Test("Each relay gets a distinct source port that resolves to its peer while open")
    func allocatesDistinctPortsAndResolves() {
        let clock = TestClock(1_000)
        let table = RelayAttributionTable(range: 20_000...20_003, grace: 120, now: { clock.now })
        let a = RelayPeer(address: "192.168.1.50", port: 51_000)
        let b = RelayPeer(address: "192.168.1.51", port: 51_001)
        let portA = table.allocate(peer: a, service: .ssh)
        let portB = table.allocate(peer: b, service: .smb)
        #expect(portA != nil && portB != nil && portA != portB)
        #expect(table.resolve(localPort: portA!, service: .ssh) == a)
        #expect(table.resolve(localPort: portB!, service: .smb) == b)
        // Same port, wrong service: sshd and smbd ports are independent namespaces.
        #expect(table.resolve(localPort: portA!, service: .smb) == nil)
        clock.now += 1
        #expect(table.resolve(localPort: 20_003, service: .ssh) == nil)
    }

    @Test("A closed relay stays attributable for the grace window, then expires")
    func gracePeriodAfterClose() {
        let clock = TestClock(0)
        let table = RelayAttributionTable(range: 20_000...20_010, grace: 120, now: { clock.now })
        let peer = RelayPeer(address: "192.168.1.50", port: 51_000)
        let port = table.allocate(peer: peer, service: .ssh)!
        table.release(port)
        clock.now = 119
        #expect(table.resolve(localPort: port, service: .ssh) == peer)
        clock.now = 121
        #expect(table.resolve(localPort: port, service: .ssh) == nil)
    }

    @Test("Released ports are reused least recently first, never while in grace")
    func reuseIsLeastRecentAndOutsideGrace() {
        let clock = TestClock(0)
        let table = RelayAttributionTable(range: 20_000...20_001, grace: 120, now: { clock.now })
        let a = RelayPeer(address: "192.168.1.50", port: 1)
        let b = RelayPeer(address: "192.168.1.51", port: 2)
        let pa = table.allocate(peer: a, service: .ssh)!
        let pb = table.allocate(peer: b, service: .ssh)!
        #expect(table.allocate(peer: a, service: .ssh) == nil, "pool exhausted while both open")
        table.release(pa)
        clock.now = 10
        table.release(pb)
        // Both are inside grace: an auth line for either could still arrive, so
        // neither port may be handed to a new peer yet.
        #expect(table.allocate(peer: b, service: .ssh) == nil)
        clock.now = 125
        // pa left grace first; it is the one reused.
        #expect(table.allocate(peer: b, service: .ssh) == pa)
        #expect(table.resolve(localPort: pa, service: .ssh) == b)
        // pb was released at t=10 and stays inside grace until t=130. A late line for it must still attribute to b.
        #expect(table.resolve(localPort: pb, service: .ssh) == b)
        clock.now = 131
        #expect(table.resolve(localPort: pb, service: .ssh) == nil)
    }

    @Test("Telemetry payload carries the peer when resolved and says so when it cannot")
    func telemetryPayloadShape() {
        let event = GuestAuthenticationEvent(service: .ssh, accepted: true, username: "buildbot", method: "password", localPort: 23456)
        let resolved = GuestAuthenticationTelemetry.payload(for: event, peer: RelayPeer(address: "192.168.1.50", port: 51000), timestamp: "2026-10-17T16:12:21Z")
        #expect(resolved["event"] as? String == "authentication")
        #expect(resolved["service"] as? String == "ssh")
        #expect(resolved["outcome"] as? String == "accepted")
        #expect(resolved["username"] as? String == "buildbot")
        #expect(resolved["method"] as? String == "password")
        #expect(resolved["source_ip"] as? String == "192.168.1.50")
        #expect(resolved["source_port"] as? Int == 51000)
        #expect(resolved["dest_port"] as? Int == 22)
        #expect(resolved["attribution"] as? String == "exact")
        #expect(JSONSerialization.isValidJSONObject(resolved))

        let unresolved = GuestAuthenticationTelemetry.payload(for: event, peer: nil, timestamp: "2026-10-17T16:12:21Z")
        #expect(unresolved["attribution"] as? String == "unresolved")
        #expect(unresolved["source_ip"] is NSNull)
        #expect(unresolved["source_port"] is NSNull)
        #expect(JSONSerialization.isValidJSONObject(unresolved))
    }
}
