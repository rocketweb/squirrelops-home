import Testing
import SwiftUI
@testable import SquirrelOpsHome

@Suite("Appearance")
struct AppearanceTests {

    @Test("resolvedColorScheme returns nil for system")
    func systemReturnsNil() {
        let result = AppearanceMode.resolvedColorScheme(for: "system")
        #expect(result == nil)
    }

    @Test("resolvedColorScheme returns .light for light")
    func lightReturnsLight() {
        let result = AppearanceMode.resolvedColorScheme(for: "light")
        #expect(result == .light)
    }

    @Test("resolvedColorScheme returns .dark for dark")
    func darkReturnsDark() {
        let result = AppearanceMode.resolvedColorScheme(for: "dark")
        #expect(result == .dark)
    }

    @Test("resolvedColorScheme returns nil for unknown value")
    func unknownReturnsNil() {
        let result = AppearanceMode.resolvedColorScheme(for: "banana")
        #expect(result == nil)
    }
}
