import Foundation
import Security
import SquirrelOpsLocalEnrollment
#if canImport(Darwin)
import Darwin
#endif

enum LocalEnrollmentHelperCodeRequirementError: Error, Equatable {
    case insecureInstalledHelper
    case invalidInstalledHelperRequirement
    case unreadableInstalledHelper
}

enum LocalEnrollmentHelperCodeRequirementPolicy {
    static func select(
        isLocalTestBuild: Bool,
        installedHelperIsRootSecured: Bool,
        installedHelperDesignatedRequirement: String?
    ) throws -> String {
        guard isLocalTestBuild else {
            return LocalEnrollmentXPC.helperCodeRequirement
        }
        guard installedHelperIsRootSecured else {
            throw LocalEnrollmentHelperCodeRequirementError.insecureInstalledHelper
        }
        guard let installedHelperDesignatedRequirement,
              installedHelperDesignatedRequirement.range(
                of: #"^cdhash H"[0-9a-fA-F]{40,64}"$"#,
                options: .regularExpression
              ) != nil else {
            throw LocalEnrollmentHelperCodeRequirementError
                .invalidInstalledHelperRequirement
        }
        return installedHelperDesignatedRequirement
    }
}

struct LocalEnrollmentHelperCodeRequirementResolver {
    static let installedHelperURL = URL(
        fileURLWithPath: "/Library/PrivilegedHelperTools/com.squirrelops.helper"
    )

    let installedHelperURL: URL
    let appBundle: Bundle

    init(
        installedHelperURL: URL = Self.installedHelperURL,
        appBundle: Bundle = .main
    ) {
        self.installedHelperURL = installedHelperURL
        self.appBundle = appBundle
    }

    func resolve() throws -> String {
        guard appBundle.url(
            forResource: "com.squirrelops.local-test-build",
            withExtension: nil
        ) != nil else {
            return LocalEnrollmentXPC.helperCodeRequirement
        }

        let helperIsRootSecured = isRootOwnedAndNotWritableByOthers(
            installedHelperURL.path
        )
        let designatedRequirement = try copyDesignatedRequirement(
            for: installedHelperURL
        )
        return try LocalEnrollmentHelperCodeRequirementPolicy.select(
            isLocalTestBuild: true,
            installedHelperIsRootSecured: helperIsRootSecured,
            installedHelperDesignatedRequirement: designatedRequirement
        )
    }

    private func isRootOwnedAndNotWritableByOthers(_ path: String) -> Bool {
        var metadata = stat()
        guard lstat(path, &metadata) == 0,
              metadata.st_uid == 0,
              metadata.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0 else {
            return false
        }
        return metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG)
            && metadata.st_nlink == 1
    }

    private func copyDesignatedRequirement(for helperURL: URL) throws -> String {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            helperURL as CFURL,
            SecCSFlags(),
            &staticCode
        ) == errSecSuccess, let staticCode else {
            throw LocalEnrollmentHelperCodeRequirementError.unreadableInstalledHelper
        }
        guard SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(
                rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures
            ),
            nil
        ) == errSecSuccess else {
            throw LocalEnrollmentHelperCodeRequirementError.unreadableInstalledHelper
        }

        var requirement: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(
            staticCode,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess, let requirement else {
            throw LocalEnrollmentHelperCodeRequirementError.unreadableInstalledHelper
        }

        var requirementText: CFString?
        guard SecRequirementCopyString(
            requirement,
            SecCSFlags(),
            &requirementText
        ) == errSecSuccess, let requirementText else {
            throw LocalEnrollmentHelperCodeRequirementError.unreadableInstalledHelper
        }
        return requirementText as String
    }
}
