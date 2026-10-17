import Foundation
import Observation

struct AIModelOption: Decodable, Identifiable, Equatable, Sendable {
    let id: String
    let name: String
}

struct AIProbeResponse: Decodable, Sendable {
    let status: String
    let message: String
    let models: [AIModelOption]
    let elapsedMs: Int
    let checks: [String: Bool]

    enum CodingKeys: String, CodingKey {
        case status, message, models, checks
        case elapsedMs = "elapsed_ms"
    }
}

/// A completion belongs to one configuration revision, never to the next edit.
@Observable @MainActor
final class AIConnectionState {
    private(set) var revision = UUID()
    private(set) var isBusy = false
    private(set) var models: [AIModelOption] = []
    private(set) var discoveryResult: AIProbeResponse?
    private(set) var testResult: AIProbeResponse?
    private(set) var error: String?

    func invalidate(clearModels: Bool) {
        revision = UUID()
        isBusy = false
        testResult = nil
        error = nil
        if clearModels {
            models = []
            discoveryResult = nil
        }
    }

    func begin() -> UUID? {
        guard !isBusy else { return nil }
        isBusy = true
        error = nil
        testResult = nil
        return revision
    }

    func finish(_ result: AIProbeResponse, token: UUID, discovery: Bool) {
        guard token == revision else { return }
        isBusy = false
        if discovery {
            discoveryResult = result
            models = result.models
        } else {
            testResult = result
        }
    }

    func fail(_ message: String, token: UUID) {
        guard token == revision else { return }
        isBusy = false
        error = message
    }
}
