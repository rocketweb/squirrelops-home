import Testing
@testable import SquirrelOpsHome

@MainActor
@Suite("Network map device coverage")
struct NetworkMapTests {
    @Test("Current device types remain visible in their display groups", arguments: [
        ("network_equipment", "infrastructure"), ("computer", "computer"),
        ("sbc", "computer"), ("nas", "server"), ("smartphone", "phone"),
        ("smart_tv", "media"), ("speaker", "media"), ("smart_speaker", "media"),
        ("streaming", "media"), ("gaming_console", "media"), ("game_console", "media"),
        ("camera", "iot"), ("thermostat", "iot"), ("smart_home", "iot"),
        ("smart_lighting", "iot"), ("iot_device", "iot"), ("unknown", "unknown"),
    ])
    func currentTypes(type: String, category: String) {
        let original = device(id: 1, type: type)
        let groups = NetworkMapView(devices: [original]).groupedDevices
        #expect(groups.map(\.category) == [category])
        #expect(groups.flatMap(\.devices) == [original])
    }

    @Test("Legacy groups retain their order and every device appears exactly once")
    func stableGroups() {
        let types = ["unknown", "iot", "media", "phone", "server", "computer", "infrastructure"]
        let devices = types.enumerated().map { device(id: $0.offset, type: $0.element) }
        let groups = NetworkMapView(devices: devices).groupedDevices
        #expect(groups.map(\.category) == types.reversed())
        #expect(groups.flatMap(\.devices).map(\.id).sorted() == devices.map(\.id))
    }

    @Test("New and empty types fall back to unknown without changing their data or order")
    func futureTypes() {
        let devices = [device(id: 1, type: "future_device"), device(id: 2, type: ""),
                       device(id: 3, type: "unknown"), device(id: 4, type: "future_device")]
        let groups = NetworkMapView(devices: devices).groupedDevices
        #expect(groups.map(\.category) == ["unknown"])
        #expect(groups.flatMap(\.devices) == devices)
    }

    @Test("Empty inventory does not produce empty sections")
    func emptyInventory() {
        #expect(NetworkMapView(devices: []).groupedDevices.isEmpty)
    }

    private func device(id: Int, type: String) -> DeviceSummary {
        DeviceSummary(id: id, ipAddress: "192.0.2.\(id)", macAddress: nil,
                      hostname: nil, vendor: nil, deviceType: type, customName: nil,
                      trustStatus: "unknown", isOnline: true,
                      firstSeen: "2026-10-02T00:00:00Z", lastSeen: "2026-10-02T00:00:00Z")
    }
}
