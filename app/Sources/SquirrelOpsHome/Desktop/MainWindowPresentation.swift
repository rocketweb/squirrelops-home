import AppKit
import SwiftUI

struct MainWindowPresentation: Equatable {
    let contentSize: NSSize
    let minimumContentSize: NSSize
    let isResizable: Bool

    static let setup = MainWindowPresentation(
        contentSize: NSSize(width: 640, height: 520),
        minimumContentSize: NSSize(width: 640, height: 520),
        isResizable: false
    )

    static let dashboard = MainWindowPresentation(
        contentSize: NSSize(width: 1080, height: 720),
        minimumContentSize: NSSize(width: 800, height: 560),
        isResizable: true
    )

    static func forPairingState(isPaired: Bool) -> MainWindowPresentation {
        isPaired ? .dashboard : .setup
    }
}

@MainActor
private enum MainWindowPresentationController {
    static func apply(
        _ presentation: MainWindowPresentation,
        to window: NSWindow
    ) {
        let currentContentSize = window.contentRect(
            forFrameRect: window.frame
        ).size
        window.contentMinSize = presentation.minimumContentSize

        if presentation.isResizable {
            window.styleMask.insert(.resizable)
            window.contentMaxSize = NSSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            )

            if currentContentSize.width < presentation.minimumContentSize.width
                || currentContentSize.height < presentation.minimumContentSize.height
            {
                window.setContentSize(presentation.contentSize)
            }
        } else {
            window.styleMask.remove(.resizable)
            window.contentMaxSize = presentation.contentSize

            if currentContentSize != presentation.contentSize {
                window.setContentSize(presentation.contentSize)
            }
        }
    }
}

struct MainWindowPresentationReader: NSViewRepresentable {
    let presentation: MainWindowPresentation

    func makeNSView(context: Context) -> NSView {
        NSView(frame: .zero)
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            guard let window = nsView.window else { return }
            MainWindowPresentationController.apply(presentation, to: window)
        }
    }
}
