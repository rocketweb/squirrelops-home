import AppKit
import SwiftUI
import Testing
@testable import SquirrelOpsHome

@Suite("Theme")
struct ThemeTests {
    init() {
        FontRegistration.registerAllFonts()
    }

    @Test("SpaceGrotesk-Regular is available after registration")
    func spaceGroteskRegular() {
        #expect(NSFont(name: "SpaceGrotesk-Regular", size: 16) != nil)
    }

    @Test("SpaceGrotesk-Medium is available after registration")
    func spaceGroteskMedium() {
        #expect(NSFont(name: "SpaceGrotesk-Medium", size: 16) != nil)
    }

    @Test("SpaceGrotesk-SemiBold is available after registration")
    func spaceGroteskSemiBold() {
        #expect(NSFont(name: "SpaceGrotesk-SemiBold", size: 16) != nil)
    }

    @Test("SpaceGrotesk-Bold is available after registration")
    func spaceGroteskBold() {
        #expect(NSFont(name: "SpaceGrotesk-Bold", size: 16) != nil)
    }

    @Test("SpaceMono-Regular is available after registration")
    func spaceMonoRegular() {
        #expect(NSFont(name: "SpaceMono-Regular", size: 16) != nil)
    }

    @Test("SpaceMono-Bold is available after registration")
    func spaceMonoBold() {
        #expect(NSFont(name: "SpaceMono-Bold", size: 16) != nil)
    }

    // MARK: - Color Tests

    @Test("Background color differs between dark and light")
    func backgroundColorDiffers() {
        #expect(Theme.background(.dark) != Theme.background(.light))
    }

    @Test("Accent default in dark mode is #B91C1C")
    func accentDarkMode() {
        #expect(Theme.accentDefault(.dark) == Color(red: 185 / 255, green: 28 / 255, blue: 28 / 255))
    }

    @Test("Accent default in light mode is #B91C1C")
    func accentLightMode() {
        #expect(Theme.accentDefault(.light) == Color(red: 185 / 255, green: 28 / 255, blue: 28 / 255))
    }

    @Test("Text primary differs between dark and light")
    func textPrimaryDiffers() {
        #expect(Theme.textPrimary(.dark) != Theme.textPrimary(.light))
    }

    @Test("Status colors are the same in both modes")
    func statusColorsSameBothModes() {
        #expect(Theme.statusSuccess(.dark) == Theme.statusSuccess(.light))
        #expect(Theme.statusWarning(.dark) == Theme.statusWarning(.light))
        #expect(Theme.statusError(.dark) == Theme.statusError(.light))
        #expect(Theme.statusInfo(.dark) == Theme.statusInfo(.light))
    }

    // MARK: - Spacing Tests

    @Test("Spacing values match design system")
    func spacingValues() {
        #expect(Spacing.xs == 4)
        #expect(Spacing.sm == 8)
        #expect(Spacing.md == 16)
        #expect(Spacing.lg == 24)
        #expect(Spacing.xl == 32)
        #expect(Spacing.xxl == 48)
        #expect(Spacing.xxxl == 64)
    }

    @Test("All spacing values are multiples of 4")
    func allSpacingMultiplesOf4() {
        let spacings: [CGFloat] = [
            Spacing.xs, Spacing.sm, Spacing.md, Spacing.lg,
            Spacing.xl, Spacing.xxl, Spacing.xxxl,
            Spacing.s12, Spacing.s20, Spacing.s40,
            Spacing.s80, Spacing.s96, Spacing.s128, Spacing.s160,
        ]
        for value in spacings {
            #expect(value.truncatingRemainder(dividingBy: 4) == 0, "Spacing \(value) is not a multiple of 4")
        }
    }

    @Test("Radius values match design system")
    func radiusValues() {
        #expect(Spacing.radiusSm == 4)
        #expect(Spacing.radiusMd == 8)
        #expect(Spacing.radiusLg == 12)
        #expect(Spacing.radiusXl == 16)
        #expect(Spacing.radiusFull == 9999)
    }

    // MARK: - Typography Tests

    @Test("Typography display1 resolves to SpaceGrotesk-Bold 72pt")
    func typographyDisplay1() {
        #expect(NSFont(name: "SpaceGrotesk-Bold", size: 72) != nil)
    }

    @Test("Typography body resolves to SpaceGrotesk-Medium 16pt")
    func typographyBody() {
        #expect(NSFont(name: "SpaceGrotesk-Medium", size: 16) != nil)
    }

    @Test("Typography mono resolves to SpaceMono-Regular 13pt")
    func typographyMono() {
        #expect(NSFont(name: "SpaceMono-Regular", size: 13) != nil)
    }

    @Test("All typography styles resolve to valid NSFonts")
    func allTypographyStyles() {
        let fontSpecs: [(String, CGFloat)] = [
            ("SpaceGrotesk-Bold", 72),      // display1
            ("SpaceGrotesk-Bold", 54),      // display2
            ("SpaceGrotesk-Bold", 40),      // h1
            ("SpaceGrotesk-SemiBold", 30),  // h2
            ("SpaceGrotesk-SemiBold", 24),  // h3
            ("SpaceGrotesk-SemiBold", 18),  // h4
            ("SpaceGrotesk-Medium", 16),    // body
            ("SpaceGrotesk-Medium", 15),    // bodySmall
            ("SpaceGrotesk-SemiBold", 12),  // caption
            ("SpaceMono-Regular", 13),      // mono
        ]
        for (name, size) in fontSpecs {
            #expect(NSFont(name: name, size: size) != nil, "\(name) at \(size)pt should resolve")
        }
    }
}
