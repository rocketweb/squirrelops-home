@preconcurrency import Foundation

import SquirrelOpsLocalEnrollment

public enum LocalEnrollmentClientError: Error, Equatable, LocalizedError, Sendable {
    case serviceUnavailable
    case rejected
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .serviceUnavailable:
            return "The local sensor setup service is not available yet."
        case .rejected:
            return "This copy of the app is not authorized for automatic local setup."
        case .invalidResponse:
            return "The local sensor returned an invalid setup response."
        }
    }
}

public protocol LocalEnrollmentProviding: Sendable {
    func enroll(request: LocalEnrollmentRequest) async throws -> LocalEnrollmentResponse
}

private final class LocalEnrollmentContinuation: @unchecked Sendable {
    // NSLock protects every read and mutation of the single continuation.
    // The unchecked conformance is limited to this lock-backed handoff object.
    private let lock = NSLock()
    private var continuation: CheckedContinuation<LocalEnrollmentResponse, any Error>?

    init(_ continuation: CheckedContinuation<LocalEnrollmentResponse, any Error>) {
        self.continuation = continuation
    }

    func resume(with result: Result<LocalEnrollmentResponse, any Error>) {
        let pending = lock.withLock {
            let pending = continuation
            continuation = nil
            return pending
        }
        pending?.resume(with: result)
    }
}

public struct PrivilegedLocalEnrollmentProvider: LocalEnrollmentProviding {
    public init() {}

    public func enroll(
        request: LocalEnrollmentRequest
    ) async throws -> LocalEnrollmentResponse {
        do {
            return try await enrollOnce(request: request)
        } catch LocalEnrollmentClientError.serviceUnavailable {
            try await Task.sleep(for: .milliseconds(200))
            return try await enrollOnce(request: request)
        }
    }

    private func enrollOnce(
        request: LocalEnrollmentRequest
    ) async throws -> LocalEnrollmentResponse {
        let requestData = try JSONEncoder().encode(request)
        let helperCodeRequirement: String
        do {
            helperCodeRequirement = try LocalEnrollmentHelperCodeRequirementResolver()
                .resolve()
        } catch {
            throw LocalEnrollmentClientError.rejected
        }
        return try await withCheckedThrowingContinuation { continuation in
            let pending = LocalEnrollmentContinuation(continuation)
            let connection = NSXPCConnection(
                machServiceName: LocalEnrollmentXPC.machServiceName,
                options: .privileged
            )
            connection.remoteObjectInterface = NSXPCInterface(
                with: LocalEnrollmentXPCProtocol.self
            )
            connection.interruptionHandler = {
                pending.resume(with: .failure(LocalEnrollmentClientError.serviceUnavailable))
            }
            connection.invalidationHandler = {
                pending.resume(with: .failure(LocalEnrollmentClientError.serviceUnavailable))
            }
            connection.setCodeSigningRequirement(helperCodeRequirement)
            connection.resume()

            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                pending.resume(with: .failure(LocalEnrollmentClientError.rejected))
                connection.invalidate()
            }) as? LocalEnrollmentXPCProtocol else {
                pending.resume(with: .failure(LocalEnrollmentClientError.serviceUnavailable))
                connection.invalidate()
                return
            }

            proxy.enrollLocalApp(request: requestData) { responseData, error in
                defer { connection.invalidate() }
                if error != nil {
                    pending.resume(with: .failure(LocalEnrollmentClientError.serviceUnavailable))
                    return
                }
                guard let responseData,
                      let response = try? JSONDecoder().decode(
                        LocalEnrollmentResponse.self,
                        from: responseData
                      ),
                      response.requestID.lowercased() == request.requestID.lowercased() else {
                    pending.resume(with: .failure(LocalEnrollmentClientError.invalidResponse))
                    return
                }
                pending.resume(with: .success(response))
            }
        }
    }
}
