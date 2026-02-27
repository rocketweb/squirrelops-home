import CoreText
import Foundation
import os

public enum FontRegistration {
    private static let fontFileNames: [String] = [
        "SpaceGrotesk-Regular",
        "SpaceGrotesk-Medium",
        "SpaceGrotesk-SemiBold",
        "SpaceGrotesk-Bold",
        "SpaceMono-Regular",
        "SpaceMono-Bold",
    ]

    private static let registrationLock = OSAllocatedUnfairLock(initialState: false)

    public static func registerAllFonts() {
        registrationLock.withLock { isRegistered in
            guard !isRegistered else { return }
            isRegistered = true

            for fontName in fontFileNames {
                guard let fontURL = fontBundleURL(for: fontName) else {
                    print("[FontRegistration] WARNING: Could not locate \(fontName).ttf in bundle")
                    continue
                }

                var errorRef: Unmanaged<CFError>?
                let registered = CTFontManagerRegisterFontsForURL(
                    fontURL as CFURL,
                    .process,
                    &errorRef
                )

                if !registered {
                    if let error = errorRef?.takeRetainedValue() {
                        let nsError = error as Error as NSError
                        if nsError.code == 105 { continue }
                        print("[FontRegistration] ERROR: Failed to register \(fontName): \(nsError)")
                    }
                }
            }
        }
    }

    private static func fontBundleURL(for fontName: String) -> URL? {
        #if SWIFT_PACKAGE
        let bundle = Bundle.module
        #else
        let bundle = Bundle.main
        #endif
        return bundle.url(forResource: fontName, withExtension: "ttf", subdirectory: "Fonts")
    }
}
