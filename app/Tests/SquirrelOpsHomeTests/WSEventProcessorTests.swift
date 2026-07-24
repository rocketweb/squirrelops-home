import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("WSEventProcessor")
@MainActor
struct WSEventProcessorTests {

    @Test("device.new event adds device to AppState")
    func deviceNewAddsDevice() {
        let state = AppState()
        let payload: [String: AnyCodableValue] = [
            "id": .int(1),
            "ip_address": .string("192.168.1.10"),
            "mac_address": .string("AA:BB:CC:DD:EE:FF"),
            "hostname": .string("test-device"),
            "vendor": .null,
            "device_type": .string("computer"),
            "custom_name": .null,
            "trust_status": .string("unknown"),
            "is_online": .bool(true),
            "first_seen": .string("2026-01-01T00:00:00Z"),
            "last_seen": .string("2026-01-01T00:00:00Z"),
        ]
        let frame = WSFrame.event(seq: 1, eventType: "device.new", payload: payload)

        WSEventProcessor.process(frame, into: state)
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.devices.count == 1)
        #expect(state.devices[0].ipAddress == "192.168.1.10")
    }

    @Test("device.online event updates device status")
    func deviceOnlineUpdates() {
        let state = AppState()
        state.devices = [DeviceSummary(
            id: 1, ipAddress: "192.168.1.10", macAddress: nil, hostname: nil,
            vendor: nil, deviceType: "computer", customName: nil,
            trustStatus: "unknown", isOnline: false, firstSeen: "2026-01-01", lastSeen: "2026-01-01"
        )]

        let frame = WSFrame.event(seq: 2, eventType: "device.online", payload: ["device_id": .int(1)])
        WSEventProcessor.process(frame, into: state)
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.devices[0].isOnline == true)
    }

    @Test("decoy.status_changed removes matching device")
    func decoyStatusChangedRemovesMatchingDevice() {
        let state = AppState()
        state.devices = [DeviceSummary(
            id: 1, ipAddress: "192.168.1.118", macAddress: nil, hostname: "files.local",
            vendor: nil, deviceType: "server", customName: nil,
            trustStatus: "unknown", isOnline: true,
            firstSeen: "2026-01-01", lastSeen: "2026-01-01"
        )]
        let payload: [String: AnyCodableValue] = [
            "id": .int(10),
            "name": .string("files.local"),
            "decoy_type": .string("mimic"),
            "bind_address": .string("192.168.1.118"),
            "port": .int(80),
            "status": .string("active"),
            "connection_count": .int(0),
            "credential_trip_count": .int(0),
            "created_at": .string("2026-01-01T00:00:00Z"),
            "updated_at": .string("2026-01-01T00:00:00Z"),
        ]

        WSEventProcessor.process(
            .event(seq: 4, eventType: "decoy.status_changed", payload: payload),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.devices.isEmpty)
        #expect(state.decoys.count == 1)
    }

    @Test("Minimal removed decoy event removes the existing decoy")
    func minimalRemovedDecoyEventRemovesExistingDecoy() {
        let state = AppState()
        state.decoys = [
            DecoySummary(
                id: 10,
                name: "files.local",
                decoyType: "mimic",
                bindAddress: "192.168.1.118",
                port: 80,
                status: "active",
                connectionCount: 0,
                credentialTripCount: 0,
                createdAt: "2026-01-01T00:00:00Z",
                updatedAt: "2026-01-01T00:00:00Z"
            ),
        ]
        let payload: [String: AnyCodableValue] = [
            "id": .int(10),
            "status": .string("removed"),
        ]

        WSEventProcessor.process(
            .event(seq: 5, eventType: "decoy.status_changed", payload: payload),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.decoys.isEmpty)
    }

    @Test("Connection count event replaces service counters with absolute values")
    func connectionCountEventUsesAbsoluteValues() {
        let state = AppState()
        state.decoys = [
            makeMimicDecoy(
                id: 10,
                hostId: 4,
                address: "192.168.1.203",
                port: 80,
                connectionCount: 8
            ),
            makeMimicDecoy(
                id: 11,
                hostId: 4,
                address: "192.168.1.203",
                port: 443,
                connectionCount: 3
            ),
        ]

        WSEventProcessor.process(
            .event(
                seq: 6,
                eventType: "decoy.connection_count_changed",
                payload: [
                    "id": .int(10),
                    "decoy_id": .int(10),
                    "host_id": .int(4),
                    "bind_address": .string("192.168.1.203"),
                    "port": .int(80),
                    "connection_count": .int(9),
                    "credential_trip_count": .int(2),
                    "updated_at": .string("2026-07-24T12:00:00Z"),
                ]
            ),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.decoys[0].connectionCount == 9)
        #expect(state.decoys[0].credentialTripCount == 2)
        #expect(state.decoys[0].updatedAt == "2026-07-24T12:00:00Z")
        #expect(state.decoys[1].connectionCount == 3)
    }

    @Test("Hostname event updates every service in the virtual host")
    func hostnameEventUpdatesHostGroup() {
        let state = AppState()
        state.decoys = [
            makeMimicDecoy(
                id: 10,
                hostId: 4,
                address: "192.168.1.203",
                port: 80
            ),
            makeMimicDecoy(
                id: 11,
                hostId: 4,
                address: "192.168.1.203",
                port: 443
            ),
            makeMimicDecoy(
                id: 12,
                hostId: 5,
                address: "192.168.1.204",
                port: 80
            ),
        ]

        WSEventProcessor.process(
            .event(
                seq: 7,
                eventType: "decoy.hostname_changed",
                payload: [
                    "host_id": .int(4),
                    "hostname": .string("printer-232.local"),
                    "bind_address": .string("192.168.1.203"),
                    "decoy_ids": .array([.int(10), .int(11)]),
                    "updated_at": .string("2026-07-24T12:01:00Z"),
                ]
            ),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.decoys[0].hostname == "printer-232.local")
        #expect(state.decoys[1].hostname == "printer-232.local")
        #expect(state.decoys[2].hostname == "old.local")
    }

    @Test("device.offline event updates device status")
    func deviceOfflineUpdates() {
        let state = AppState()
        state.devices = [DeviceSummary(
            id: 1, ipAddress: "192.168.1.10", macAddress: nil, hostname: nil,
            vendor: nil, deviceType: "computer", customName: nil,
            trustStatus: "unknown", isOnline: true, firstSeen: "2026-01-01", lastSeen: "2026-01-01"
        )]

        let frame = WSFrame.event(seq: 3, eventType: "device.offline", payload: ["device_id": .int(1)])
        WSEventProcessor.process(frame, into: state)
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.devices[0].isOnline == false)
    }

    @Test("alert.new event prepends alert")
    func alertNewPrepends() {
        let state = AppState()
        let payload: [String: AnyCodableValue] = [
            "id": .int(1),
            "alert_type": .string("device.new"),
            "severity": .string("medium"),
            "title": .string("New device detected"),
            "created_at": .string("2026-01-01T00:00:00Z"),
        ]
        let frame = WSFrame.event(seq: 4, eventType: "alert.new", payload: payload)

        WSEventProcessor.process(frame, into: state)
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.alerts.count == 1)
        #expect(state.alerts[0].title == "New device detected")
    }

    @Test("History clear drops queued alerts before they can flush")
    func historyClearDropsQueuedAlerts() {
        let state = AppState()
        let payload: [String: AnyCodableValue] = [
            "id": .int(1),
            "alert_type": .string("device.new"),
            "severity": .string("medium"),
            "title": .string("Queued old alert"),
            "created_at": .string("2026-01-01T00:00:00Z"),
        ]
        WSEventProcessor.process(
            .event(seq: 4, eventType: "alert.new", payload: payload),
            into: state
        )
        WSEventProcessor.process(
            .event(
                seq: 5,
                eventType: "alerts.history_cleared",
                payload: ["alerts_deleted": .int(1)]
            ),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.alerts.isEmpty)
    }

    @Test("Replay clear preserves a queued newer live alert")
    func replayClearPreservesQueuedNewerLiveAlert() {
        let state = AppState()
        let payload: [String: AnyCodableValue] = [
            "id": .int(2),
            "alert_type": .string("decoy.trip"),
            "severity": .string("high"),
            "title": .string("Post-clear live alert"),
            "created_at": .string("2026-01-01T00:00:01Z"),
        ]

        // A live event can arrive while the server is still replaying older
        // frames. The later-delivered marker is older than this alert.
        WSEventProcessor.process(
            .event(seq: 6, eventType: "alert.new", payload: payload),
            into: state
        )
        WSEventProcessor.process(
            .event(
                seq: 5,
                eventType: "alerts.history_cleared",
                payload: ["alerts_deleted": .int(1)]
            ),
            into: state
        )
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.alerts.map(\.id) == [2])
    }

    @Test("system.status_changed event updates system status")
    func systemStatusChanged() {
        let state = AppState()
        let payload: [String: AnyCodableValue] = [
            "profile": .string("full"),
            "learning_mode": .bool(true),
            "device_count": .int(10),
            "decoy_count": .int(5),
            "alert_count": .int(3),
        ]
        let frame = WSFrame.event(seq: 5, eventType: "system.status_changed", payload: payload)

        WSEventProcessor.process(frame, into: state)
        WSEventProcessor.flushPendingUpdates(into: state)

        #expect(state.systemStatus?.profile == "full")
        #expect(state.systemStatus?.learningMode == true)
    }

    @Test("Unknown event type is silently ignored")
    func unknownEventIgnored() {
        let state = AppState()
        let frame = WSFrame.event(seq: 99, eventType: "unknown.event", payload: [:])
        WSEventProcessor.process(frame, into: state)
        #expect(state.devices.isEmpty)
        #expect(state.alerts.isEmpty)
    }

    @Test("Non-event frames are ignored")
    func nonEventFrameIgnored() {
        let state = AppState()
        WSEventProcessor.process(.authOk, into: state)
        WSEventProcessor.process(.ping, into: state)
        WSEventProcessor.process(.replayComplete(lastSeq: 10), into: state)
        #expect(state.devices.isEmpty)
    }

    private func makeMimicDecoy(
        id: Int,
        hostId: Int,
        address: String,
        port: Int,
        connectionCount: Int = 0
    ) -> DecoySummary {
        DecoySummary(
            id: id,
            name: "Mimic \(id)",
            decoyType: "mimic",
            bindAddress: address,
            port: port,
            status: "active",
            connectionCount: connectionCount,
            credentialTripCount: 0,
            createdAt: "2026-07-24T00:00:00Z",
            updatedAt: "2026-07-24T00:00:00Z",
            hostId: hostId,
            hostname: "old.local",
            serviceProtocol: port == 443 ? "https" : "http",
            serviceName: "Web"
        )
    }
}
