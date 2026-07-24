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
        var seenPaths: Set<String> = []
        let resourceBundleName = "SquirrelOpsHome_SquirrelOpsHome.bundle"

        if let appResourceBundleURL = Bundle.main.url(
            forResource: "SquirrelOpsHome_SquirrelOpsHome",
            withExtension: "bundle"
        ),
           let appResourceBundle = Bundle(url: appResourceBundleURL) {
            bundles.append(appResourceBundle)
            seenPaths.insert(appResourceBundle.bundlePath)
        }

        // SwiftPM's generated accessor compiles its absolute build directory
        // into the executable. Walk up from the current executable instead,
        // which finds the sibling resource bundle in tests while the lookup
        // above handles the installed application.
        var searchRoots = Bundle.allBundles.map(\.bundleURL)
        searchRoots.append(Bundle.main.bundleURL)
        if let executableURL = Bundle.main.executableURL {
            searchRoots.append(executableURL)
        }
        searchRoots.append(
            contentsOf: CommandLine.arguments
                .filter { $0.hasPrefix("/") }
                .map { URL(fileURLWithPath: $0) }
        )

        for searchRoot in searchRoots {
            var directory = searchRoot
            for _ in 0 ..< 8 {
                let candidates = [
                    directory.appendingPathComponent(resourceBundleName),
                    directory
                        .appendingPathComponent("Resources")
                        .appendingPathComponent(resourceBundleName),
                ]
                for candidate in candidates {
                    if let bundle = Bundle(url: candidate),
                       seenPaths.insert(bundle.bundlePath).inserted {
                        bundles.append(bundle)
                    }
                }
                directory.deleteLastPathComponent()
            }
        }

        if seenPaths.insert(Bundle.main.bundlePath).inserted {
            bundles.append(Bundle.main)
        }
        return bundles
    }
}
