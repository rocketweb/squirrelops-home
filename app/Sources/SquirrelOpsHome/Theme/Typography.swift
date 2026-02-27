import SwiftUI

public enum Typography {
    /// Display1: SpaceGrotesk-Bold 72pt, tracking -0.04em, leading 1.0
    public static let display1: Font = Font.custom("SpaceGrotesk-Bold", size: 72)
        .leading(.tight)

    public static let display1Tracking: CGFloat = -0.04 * 72

    /// Display2: SpaceGrotesk-Bold 54pt
    public static let display2: Font = Font.custom("SpaceGrotesk-Bold", size: 54)
        .leading(.tight)

    public static let display2Tracking: CGFloat = -0.035 * 54

    /// H1: SpaceGrotesk-Bold 40pt
    public static let h1: Font = Font.custom("SpaceGrotesk-Bold", size: 40)

    public static let h1Tracking: CGFloat = -0.03 * 40

    /// H2: SpaceGrotesk-SemiBold 30pt
    public static let h2: Font = Font.custom("SpaceGrotesk-SemiBold", size: 30)

    public static let h2Tracking: CGFloat = -0.025 * 30

    /// H3: SpaceGrotesk-SemiBold 24pt
    public static let h3: Font = Font.custom("SpaceGrotesk-SemiBold", size: 24)

    public static let h3Tracking: CGFloat = -0.02 * 24

    /// H4: SpaceGrotesk-SemiBold 18pt
    public static let h4: Font = Font.custom("SpaceGrotesk-SemiBold", size: 18)

    public static let h4Tracking: CGFloat = -0.01 * 18

    /// Body: SpaceGrotesk-Medium 16pt
    public static let body: Font = Font.custom("SpaceGrotesk-Medium", size: 16)

    public static let bodyTracking: CGFloat = 0

    /// BodySmall: SpaceGrotesk-Medium 15pt
    public static let bodySmall: Font = Font.custom("SpaceGrotesk-Medium", size: 15)

    public static let bodySmallTracking: CGFloat = 0.005 * 15

    /// Caption: SpaceGrotesk-SemiBold 12pt, tracking 0.04em
    public static let caption: Font = Font.custom("SpaceGrotesk-SemiBold", size: 12)

    public static let captionTracking: CGFloat = 0.04 * 12

    /// Mono: SpaceMono-Regular 13pt, tracking 0.02em
    public static let mono: Font = Font.custom("SpaceMono-Regular", size: 13)

    public static let monoTracking: CGFloat = 0.02 * 13
}
