import AppKit
import SwiftUI

/// Native overscroll detection, separate from rendering so gesture boundaries
/// can be tested without a trackpad. Ordinary scrolling never arms a refresh.
struct PullRefreshGesture {
    // Visible elastic movement, not wheel-input units. On the macOS 27
    // acceptance trackpad, comfortable full pulls reached 47–52 points;
    // captured short-input replays stayed at or below 38 points.
    static let threshold: CGFloat = 44
    private(set) var isTracking = false
    private(set) var isArmed = false

    mutating func begin(atTop: Bool, isRefreshing: Bool) {
        isTracking = atTop && !isRefreshing
        isArmed = false
    }

    mutating func update(distance: CGFloat) {
        guard isTracking else { return }
        isArmed = isArmed || distance >= Self.threshold
    }

    mutating func end() -> Bool {
        let shouldRefresh = isTracking && isArmed
        self = Self()
        return shouldRefresh
    }
}

/// SwiftUI's refresh action alone does not provide a macOS ScrollView gesture.
/// Observe this scroll view's native gesture events without consuming them or
/// interfering with card controls and text selection. The native clip view is
/// the source of truth for visible movement, not accelerated scroll-wheel input.
struct PullToRefreshScrollView<Content: View>: View {
    let isRefreshing: Bool
    var showsRefreshConfirmation = false
    let refresh: @MainActor () -> Void
    @ViewBuilder let content: () -> Content

    @State private var pullDistance: CGFloat = 0

    var body: some View {
        ScrollView {
            content()
                .background(ScrollRefreshObserver(
                    isRefreshing: isRefreshing,
                    onPull: { pullDistance = $0 },
                    onRefresh: refresh
                ))
        }
        .overlay(alignment: .top) {
            if isRefreshing {
                ProgressView("Refreshing decoys…")
                    .controlSize(.small)
                    .padding(Spacing.sm)
                    .allowsHitTesting(false)
            } else if pullDistance > 8 {
                Label(
                    pullDistance >= PullRefreshGesture.threshold ? "Release to refresh" : "Pull to refresh",
                    systemImage: "arrow.down"
                )
                .font(Typography.bodySmall)
                .padding(Spacing.sm)
                .allowsHitTesting(false)
            } else if showsRefreshConfirmation {
                DecoyRefreshConfirmation()
                    .padding(.top, Spacing.sm)
                    .transition(.opacity)
                    .allowsHitTesting(false)
            }
        }
        .accessibilityAction(named: Text("Refresh decoys"), refresh)
        .contextMenu {
            Button("Refresh Decoys", action: refresh)
                .disabled(isRefreshing)
        }
    }
}

struct ScrollRefreshObserver: NSViewRepresentable {
    let isRefreshing: Bool
    let onPull: @MainActor (CGFloat) -> Void
    let onRefresh: @MainActor () -> Void

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> AttachmentView {
        let view = AttachmentView()
        view.attach = { [weak coordinator = context.coordinator] in coordinator?.attach(to: $0) }
        return view
    }

    func updateNSView(_ view: AttachmentView, context: Context) {
        context.coordinator.isRefreshing = isRefreshing
        context.coordinator.onPull = onPull
        context.coordinator.onRefresh = onRefresh
        // The SwiftUI hierarchy may not yet contain its NSScrollView during
        // makeNSView. Attachment and callbacks are confined to the main actor.
        Task { @MainActor [weak view] in view?.attach?(view?.enclosingScrollView) }
    }

    static func dismantleNSView(_ view: AttachmentView, coordinator: Coordinator) {
        view.attach = nil
        coordinator.attach(to: nil)
    }

    final class AttachmentView: NSView {
        var attach: (@MainActor (NSScrollView?) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            attach?(window == nil ? nil : enclosingScrollView)
        }
    }

    @MainActor
    final class Coordinator: NSObject {
        weak var scrollView: NSScrollView?
        var originalElasticity: NSScrollView.Elasticity = .automatic
        var originallyPostsBoundsChanges = false
        var monitor: Any?
        var isRefreshing = false
        var onPull: (@MainActor (CGFloat) -> Void)?
        var onRefresh: (@MainActor () -> Void)?
        var gesture = PullRefreshGesture()
        private var startingPull: CGFloat = 0

        /// Positive above the resting top edge, negative within the list. Fail
        /// closed while SwiftUI's native document has not acquired its geometry.
        var contentTop: CGFloat? {
            guard let scroll = scrollView, let document = scroll.documentView,
                  document.frame.height > 0, scroll.contentView.bounds.height > 0 else { return nil }
            let clip = scroll.contentView.bounds
            if document.isFlipped {
                return document.frame.minY - scroll.contentInsets.top - clip.minY
            }
            let restingTop = max(document.frame.minY, document.frame.maxY - clip.height)
            return clip.minY - restingTop - scroll.contentInsets.top
        }

        func attach(to view: NSScrollView?) {
            guard scrollView !== view else { return }
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
            if let clip = scrollView?.contentView {
                NotificationCenter.default.removeObserver(self, name: NSView.boundsDidChangeNotification, object: clip)
                clip.postsBoundsChangedNotifications = originallyPostsBoundsChanges
            }
            scrollView?.verticalScrollElasticity = originalElasticity
            scrollView = view
            gesture = PullRefreshGesture()
            guard let view else { return }
            originalElasticity = view.verticalScrollElasticity
            originallyPostsBoundsChanges = view.contentView.postsBoundsChangedNotifications
            view.contentView.postsBoundsChangedNotifications = true
            NotificationCenter.default.addObserver(self, selector: #selector(clipBoundsChanged),
                name: NSView.boundsDidChangeNotification, object: view.contentView)
            // Also allow a pull when the list is empty or shorter than its viewport.
            view.verticalScrollElasticity = .allowed
            monitor = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { [weak self] event in
                MainActor.assumeIsolated {
                    guard let self, let scroll = self.scrollView,
                          let window = scroll.window, event.window === window else { return }
                    let point = scroll.convert(event.locationInWindow, from: nil)
                    // Finish an in-progress gesture even if the pointer has
                    // moved outside the list. Never start one outside it.
                    guard self.gesture.isTracking || scroll.bounds.contains(point) else { return }
                    self.handleScrollEvent(event)
                }
                return event
            }
        }

        @objc private func clipBoundsChanged(_ notification: Notification) {
            updateVisiblePull()
        }

        private func updateVisiblePull() {
            guard gesture.isTracking else { return }
            guard !isRefreshing, let top = contentTop, top >= -1 else {
                gesture = PullRefreshGesture()
                onPull?(0)
                return
            }
            // A new gesture during the previous bounce must earn its own pull.
            let distance = max(0, top - startingPull)
            gesture.update(distance: distance)
            onPull?(gesture.isArmed ? max(distance, PullRefreshGesture.threshold) : distance)
        }

        func handleScrollEvent(_ event: NSEvent) {
            guard event.momentumPhase.isEmpty else { return }
            if event.phase.contains(.cancelled) {
                gesture = PullRefreshGesture()
                onPull?(0)
                return
            }
            if event.phase.contains(.began) {
                let top = contentTop
                gesture.begin(atTop: top.map { $0 >= -1 } ?? false, isRefreshing: isRefreshing)
                startingPull = max(0, top ?? 0)
                onPull?(0)
            }
            if event.phase.contains(.ended) {
                updateVisiblePull()
                let shouldRefresh = gesture.end()
                onPull?(0)
                if shouldRefresh && !isRefreshing { onRefresh?() }
                return
            }
            updateVisiblePull()
        }
    }
}

private struct DecoyRefreshActionKey: FocusedValueKey {
    typealias Value = @MainActor () -> Void
}

extension FocusedValues {
    var refreshDecoys: (@MainActor () -> Void)? {
        get { self[DecoyRefreshActionKey.self] }
        set { self[DecoyRefreshActionKey.self] = newValue }
    }
}

struct DecoyRefreshCommands: Commands {
    @FocusedValue(\.refreshDecoys) private var refresh

    var body: some Commands {
        CommandGroup(after: .toolbar) {
            Button("Refresh Decoys") { refresh?() }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(refresh == nil)
        }
    }
}
