import Testing

@testable import SquirrelOpsHome

@Suite("Connection State")
struct ConnectionStateTests {

    @Test("Connection states have stable raw values")
    func allStatesExist() {
        #expect(ConnectionState.disconnected.rawValue == "disconnected")
        #expect(ConnectionState.connecting.rawValue == "connecting")
        #expect(ConnectionState.connected.rawValue == "connected")
        #expect(ConnectionState.syncing.rawValue == "syncing")
        #expect(ConnectionState.live.rawValue == "live")
        #expect(ConnectionState.authFailed.rawValue == "authFailed")
        #expect(ConnectionState.incompatible.rawValue == "incompatible")
    }

    @Test("isUsable returns true for connected, syncing, and live")
    func isUsableTrueForConnectedStates() {
        #expect(ConnectionState.connected.isUsable == true)
        #expect(ConnectionState.syncing.isUsable == true)
        #expect(ConnectionState.live.isUsable == true)
    }

    @Test("isUsable returns false for disconnected and connecting")
    func isUsableFalseForDisconnectedStates() {
        #expect(ConnectionState.disconnected.isUsable == false)
        #expect(ConnectionState.connecting.isUsable == false)
        #expect(ConnectionState.authFailed.isUsable == false)
        #expect(ConnectionState.incompatible.isUsable == false)
    }
}
