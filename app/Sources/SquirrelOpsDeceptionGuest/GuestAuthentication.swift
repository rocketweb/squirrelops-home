import Foundation

/// One authentication attempt the guest's own daemons logged.
struct GuestAuthenticationEvent: Equatable, Sendable {
    let service: RelayService
    let accepted: Bool
    let username: String
    let method: String
    /// The 127.0.0.1 source port the daemon saw: the host-chosen relay port.
    let localPort: UInt16
}

/// Recognizes the two auth log lines the guest emits and nothing else.
///
/// This reads the guest's own syslog records; it does not parse SSH or SMB.
/// The relay contract in `DECEPTION_DEPTH_2_1.md` is unchanged: protocol bytes
/// stay opaque, and only `sshd` and `smbd` ever interpret them.
///
/// Formats were captured from OpenSSH 10.3 and Samba 4.23.8 in the pinned
/// Alpine image (`guest/studio-mini/packages.lock`), not written from memory:
///
///     sshd-session[25]: Accepted password for buildbot from 127.0.0.1 port 60488 ssh2
///     sshd-session[37]: Failed password for invalid user root from 127.0.0.1 port 60512 ssh2
///
/// OpenSSH 9.8 and later run each connection in `sshd-session`, so that is the
/// tag the live guest actually emits; a bare `sshd` tag is accepted for older
/// builds. The first live run against the rebuilt guest caught exactly this:
/// SMB logins attributed, SSH logins silently unmatched.
///     smbd[28]:   Auth: [SMB2,(null)] user [HAWTHORN]\[buildbot] at [...] with [NTLMv2]
///                 status [NT_STATUS_OK] workstation [X] remote host [ipv4:127.0.0.1:24000] ...
enum GuestAuthenticationParser {
    /// Longer than any legitimate line from either daemon. The guest syslog
    /// ring is attacker-influenced (usernames, workstation names), so the
    /// bound is enforced before any pattern runs.
    static let maximumLineLength = 2048

    private static let maximumUsernameLength = 64

    static func parse(_ line: String) -> GuestAuthenticationEvent? {
        guard line.utf8.count <= maximumLineLength else { return nil }
        // Regex values are not Sendable, so they live here rather than in
        // static storage. Only the relay address is a legitimate origin: a
        // line naming any other address did not come through the host.
        let ssh = /sshd(?:-session)?\[\d{1,10}\]: (Accepted|Failed) (password|publickey|keyboard-interactive(?:\/pam)?|none) for (?:invalid user )?(\S{1,64}) from 127\.0\.0\.1 port (\d{1,5}) ssh2\b/
        let smb = /\ Auth: \[SMB2,[^\]]{0,64}\] user \[[^\]]{0,64}\]\\\[([^\]]{1,64})\] at \[[^\]]{0,96}\] with \[([^\]]{1,32})\] status \[([A-Z0-9_]{1,64})\] workstation \[[^\]]{0,64}\] remote host \[ipv4:127\.0\.0\.1:(\d{1,5})\]/

        if let match = line.firstMatch(of: ssh) {
            guard let username = cleanUsername(String(match.3)),
                  let port = localPort(match.4)
            else { return nil }
            return GuestAuthenticationEvent(
                service: .ssh,
                accepted: match.1 == "Accepted",
                username: username,
                method: String(match.2),
                localPort: port
            )
        }
        if let match = line.firstMatch(of: smb) {
            guard let username = cleanUsername(String(match.1)),
                  let port = localPort(match.4)
            else { return nil }
            return GuestAuthenticationEvent(
                service: .smb,
                accepted: match.3 == "NT_STATUS_OK",
                username: username,
                method: String(match.2),
                localPort: port
            )
        }
        return nil
    }

    /// Usernames are attacker-chosen. Keep them as evidence, but only printable
    /// ASCII without whitespace or brackets, bounded, so a crafted login name
    /// cannot carry terminal escapes or forge log structure downstream.
    private static func cleanUsername(_ raw: String) -> String? {
        guard !raw.isEmpty, raw.utf8.count <= maximumUsernameLength else { return nil }
        for scalar in raw.unicodeScalars {
            guard scalar.value >= 0x21, scalar.value <= 0x7e,
                  scalar != "[", scalar != "]", scalar != "\\"
            else { return nil }
        }
        return raw
    }

    private static func localPort(_ raw: Substring) -> UInt16? {
        guard let value = Int(raw), (1...65535).contains(value) else { return nil }
        return UInt16(value)
    }
}

/// The stdout telemetry record for one authentication event.
enum GuestAuthenticationTelemetry {
    static func payload(
        for event: GuestAuthenticationEvent,
        peer: RelayPeer?,
        timestamp: String
    ) -> [String: Any] {
        [
            "event": "authentication",
            "service": event.service.rawValue,
            "outcome": event.accepted ? "accepted" : "failed",
            "username": event.username,
            "method": event.method,
            "source_ip": peer.map { $0.address as Any } ?? NSNull(),
            "source_port": peer.map { Int($0.port) as Any } ?? NSNull(),
            "dest_port": event.service.advertisedPort,
            "attribution": peer == nil ? "unresolved" : "exact",
            "timestamp": timestamp,
        ]
    }
}
