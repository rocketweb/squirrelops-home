import Foundation

/// Thread-safe storage for mock request handlers using an actor.
actor MockRequestHandlerStore {
    typealias Handler = @Sendable (URLRequest) throws -> (HTTPURLResponse, Data)

    private var handler: Handler?

    func setHandler(_ handler: Handler?) {
        self.handler = handler
    }

    func getHandler() -> Handler? {
        return handler
    }
}

/// A URLProtocol subclass that intercepts URL requests for testing.
/// Uses a static actor-based store for thread-safe handler management.
final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var store = MockRequestHandlerStore()

    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        Task {
            do {
                guard let handler = await MockURLProtocol.store.getHandler() else {
                    let error = NSError(
                        domain: "MockURLProtocol",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "No handler set"]
                    )
                    client?.urlProtocol(self, didFailWithError: error)
                    return
                }

                let (response, data) = try handler(request)
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: data)
                client?.urlProtocolDidFinishLoading(self)
            } catch {
                client?.urlProtocol(self, didFailWithError: error)
            }
        }
    }

    override func stopLoading() {}
}
