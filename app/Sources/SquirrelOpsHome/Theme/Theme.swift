import SwiftUI

public enum Theme {
    // MARK: - Backgrounds

    public static func background(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 10 / 255, green: 10 / 255, blue: 10 / 255)       // #0A0A0A
            : Color(red: 255 / 255, green: 255 / 255, blue: 255 / 255)    // #FFFFFF
    }

    public static func backgroundSecondary(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 19 / 255, green: 19 / 255, blue: 19 / 255)       // #131313
            : Color(red: 250 / 255, green: 250 / 255, blue: 250 / 255)    // #FAFAFA
    }

    public static func backgroundTertiary(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 23 / 255, green: 23 / 255, blue: 23 / 255)       // #171717
            : Color(red: 245 / 255, green: 245 / 255, blue: 245 / 255)    // #F5F5F5
    }

    public static func backgroundElevated(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 28 / 255, green: 28 / 255, blue: 28 / 255)       // #1C1C1C
            : Color(red: 255 / 255, green: 255 / 255, blue: 255 / 255)    // #FFFFFF
    }

    // MARK: - Text

    public static func textPrimary(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 255 / 255, green: 255 / 255, blue: 255 / 255)    // #FFFFFF
            : Color(red: 23 / 255, green: 23 / 255, blue: 23 / 255)       // #171717
    }

    public static func textSecondary(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 181 / 255, green: 181 / 255, blue: 181 / 255)    // #B5B5B5
            : Color(red: 82 / 255, green: 82 / 255, blue: 82 / 255)       // #525252
    }

    public static func textTertiary(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 163 / 255, green: 163 / 255, blue: 163 / 255)  // #A3A3A3
            : Color(red: 102 / 255, green: 102 / 255, blue: 102 / 255)  // #666666
    }

    // MARK: - Borders

    public static func borderSubtle(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 28 / 255, green: 28 / 255, blue: 28 / 255)       // #1C1C1C
            : Color(red: 245 / 255, green: 245 / 255, blue: 245 / 255)    // #F5F5F5
    }

    public static func borderDefault(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 38 / 255, green: 38 / 255, blue: 38 / 255)       // #262626
            : Color(red: 229 / 255, green: 229 / 255, blue: 229 / 255)    // #E5E5E5
    }

    public static func borderStrong(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 64 / 255, green: 64 / 255, blue: 64 / 255)       // #404040
            : Color(red: 212 / 255, green: 212 / 255, blue: 212 / 255)    // #D4D4D4
    }

    // MARK: - Accent

    public static func accentDefault(_ colorScheme: ColorScheme) -> Color {
        Color(red: 185 / 255, green: 28 / 255, blue: 28 / 255)            // #B91C1C
    }

    public static func accentHover(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 220 / 255, green: 38 / 255, blue: 38 / 255)      // #DC2626
            : Color(red: 153 / 255, green: 27 / 255, blue: 27 / 255)      // #991B1B
    }

    public static func accentMuted(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 69 / 255, green: 10 / 255, blue: 10 / 255)       // #450A0A
            : Color(red: 254 / 255, green: 242 / 255, blue: 242 / 255)    // #FEF2F2
    }

    public static func accentText(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 231 / 255, green: 76 / 255, blue: 76 / 255)      // #E74C4C
            : Color(red: 153 / 255, green: 27 / 255, blue: 27 / 255)      // #991B1B
    }

    // MARK: - Status

    public static func statusSuccess(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 74 / 255, green: 222 / 255, blue: 128 / 255)
            : Color(red: 22 / 255, green: 101 / 255, blue: 52 / 255)
    }

    public static func statusWarning(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 250 / 255, green: 204 / 255, blue: 21 / 255)
            : Color(red: 133 / 255, green: 77 / 255, blue: 14 / 255)
    }

    public static func statusError(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 248 / 255, green: 113 / 255, blue: 113 / 255)
            : Color(red: 185 / 255, green: 28 / 255, blue: 28 / 255)
    }

    public static func statusInfo(_ colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 96 / 255, green: 165 / 255, blue: 250 / 255)
            : Color(red: 29 / 255, green: 78 / 255, blue: 216 / 255)
    }
}
