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
}
