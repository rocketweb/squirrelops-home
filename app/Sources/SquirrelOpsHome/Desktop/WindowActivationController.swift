import AppKit

enum AppWindow: String, Sendable {
    case dashboard = "main"
    case help = "help"

    var title: String {
        switch self {
        case .dashboard: return "SquirrelOps Home"
        case .help: return "SquirrelOps Home Help"
        }
    }
}

@MainActor
protocol WindowActivating: AnyObject {
    var title: String { get }
    var isMiniaturized: Bool { get }
    func deminiaturize(_ sender: Any?)
    func makeKeyAndOrderFront(_ sender: Any?)
    func orderFrontRegardless()
}

extension NSWindow: WindowActivating {}

@MainActor
enum WindowActivationController {
    @discardableResult
    static func activateExistingWindow(
        _ target: AppWindow,
        windows: [any WindowActivating]
    ) -> Bool {
        guard let window = windows.first(where: { $0.title == target.title }) else {
            return false
        }
        if window.isMiniaturized {
            window.deminiaturize(nil)
        }
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        return true
    }

    static func present(
        _ target: AppWindow,
        openWindow: @escaping () -> Void
    ) {
        NSApp.unhide(nil)
        let existing = activateExistingWindow(
            target,
            windows: NSApp.windows.map { $0 as any WindowActivating }
        )
        if !existing {
            openWindow()
            DispatchQueue.main.async {
                _ = activateExistingWindow(
                    target,
                    windows: NSApp.windows.map { $0 as any WindowActivating }
                )
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        NSApp.activate(ignoringOtherApps: true)
    }
}
