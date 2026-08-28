import Foundation
import Security
import SquirrelOpsLocalEnrollment
#if canImport(Darwin)
import Darwin
#endif

enum LocalEnrollmentCodeRequirementError: Error, Equatable {
    case insecureInstalledApp
    case invalidInstalledAppRequirement
    case unreadableInstalledApp
}

enum LocalEnrollmentCodeRequirementPolicy {
    static func select(
        isLocalTestBuild: Bool,
        installedAppIsRootSecured: Bool,
        installedAppDesignatedRequirement: String?
    ) throws -> String {
        guard isLocalTestBuild else {
            return LocalEnrollmentXPC.appCodeRequirement
        }
        guard installedAppIsRootSecured else {
            throw LocalEnrollmentCodeRequirementError.insecureInstalledApp
        }
        guard let installedAppDesignatedRequirement,
              installedAppDesignatedRequirement.range(
                of: #"^cdhash H"[0-9a-fA-F]{40,64}"$"#,
                options: .regularExpression
              ) != nil else {
            throw LocalEnrollmentCodeRequirementError.invalidInstalledAppRequirement
        }
        return installedAppDesignatedRequirement
    }
}

struct LocalEnrollmentCodeRequirementResolver {
    static let installedAppURL = URL(
        fileURLWithPath: "/Applications/SquirrelOps Home.app",
        isDirectory: true
    )

    let installedAppURL: URL

    init(installedAppURL: URL = Self.installedAppURL) {
        self.installedAppURL = installedAppURL
    }

    func resolve() throws -> String {
        let markerURL = installedAppURL
            .appendingPathComponent("Contents/Resources/com.squirrelops.local-test-build")
        guard pathExistsWithoutFollowingLinks(markerURL.path) else {
            return LocalEnrollmentXPC.appCodeRequirement
        }

        let securedPaths: [(url: URL, isDirectory: Bool)] = [
            (installedAppURL, true),
            (installedAppURL.appendingPathComponent("Contents", isDirectory: true), true),
            (installedAppURL.appendingPathComponent("Contents/Resources", isDirectory: true), true),
            (markerURL, false),
        ]
        let installedAppIsRootSecured = securedPaths.allSatisfy { path in
            isRootOwnedAndNotWritableByOthers(
                path.url.path,
                isDirectory: path.isDirectory
            )
        }
        let designatedRequirement = try copyDesignatedRequirement(
            for: installedAppURL
        )

        return try LocalEnrollmentCodeRequirementPolicy.select(
            isLocalTestBuild: true,
            installedAppIsRootSecured: installedAppIsRootSecured,
            installedAppDesignatedRequirement: designatedRequirement
        )
    }

    private func pathExistsWithoutFollowingLinks(_ path: String) -> Bool {
        var metadata = stat()
        return lstat(path, &metadata) == 0
    }

    private func isRootOwnedAndNotWritableByOthers(
        _ path: String,
        isDirectory: Bool
    ) -> Bool {
        var metadata = stat()
        guard lstat(path, &metadata) == 0,
              metadata.st_uid == 0,
              metadata.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0 else {
            return false
        }
        let fileType = metadata.st_mode & mode_t(S_IFMT)
        if isDirectory {
            return fileType == mode_t(S_IFDIR)
        }
        return fileType == mode_t(S_IFREG) && metadata.st_nlink == 1
    }

    private func copyDesignatedRequirement(for appURL: URL) throws -> String {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            appURL as CFURL,
            SecCSFlags(),
            &staticCode
        ) == errSecSuccess, let staticCode else {
            throw LocalEnrollmentCodeRequirementError.unreadableInstalledApp
        }
        guard SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(
                rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures
            ),
            nil
        ) == errSecSuccess else {
            throw LocalEnrollmentCodeRequirementError.unreadableInstalledApp
        }

        var requirement: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(
            staticCode,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess, let requirement else {
            throw LocalEnrollmentCodeRequirementError.unreadableInstalledApp
        }

        var requirementText: CFString?
        guard SecRequirementCopyString(
            requirement,
            SecCSFlags(),
            &requirementText
        ) == errSecSuccess, let requirementText else {
            throw LocalEnrollmentCodeRequirementError.unreadableInstalledApp
        }
        return requirementText as String
    }
}
