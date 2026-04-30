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
        for bundle in resourceBundles() {
            if let url = bundle.url(forResource: fontName, withExtension: "ttf", subdirectory: "Fonts") {
                return url
            }
        }

        return nil
    }

    private static func resourceBundles() -> [Bundle] {
        var bundles: [Bundle] = []

        if let appResourceBundleURL = Bundle.main.url(
            forResource: "SquirrelOpsHome_SquirrelOpsHome",
            withExtension: "bundle"
        ),
           let appResourceBundle = Bundle(url: appResourceBundleURL) {
            bundles.append(appResourceBundle)
        }

        #if SWIFT_PACKAGE
        bundles.append(Bundle.module)
        #endif

        bundles.append(Bundle.main)
        return bundles
    }
}
