import Foundation

/// Presents sensor timestamps consistently in the Mac's current local time.
///
/// Sensor APIs use ISO-8601 UTC timestamps, sometimes with fractional seconds.
/// Views should keep those source strings for sorting and filtering, then use
/// this presenter only at the display boundary.
enum TimestampPresentation {
    static let unavailable = "Unknown"

    static func local(
        _ timestamp: String,
        timeZone: TimeZone = .autoupdatingCurrent
    ) -> String {
        guard let date = parse(timestamp) else {
            return unavailable
        }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let components = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second],
            from: date
        )
        guard
            let year = components.year,
            let month = components.month,
            let day = components.day,
            let hour = components.hour,
            let minute = components.minute,
            let second = components.second
        else {
            return unavailable
        }

        return String(
            format: "%04d-%02d-%02d %02d:%02d:%02d",
            locale: Locale(identifier: "en_US_POSIX"),
            year,
            month,
            day,
            hour,
            minute,
            second
        )
    }

    /// Format only recognizable timestamps from generic detail dictionaries.
    /// Ordinary strings are returned unchanged.
    static func localIfRecognized(
        _ value: String,
        timeZone: TimeZone = .autoupdatingCurrent
    ) -> String {
        guard parse(value) != nil else { return value }
        return local(value, timeZone: timeZone)
    }

    private static func parse(_ timestamp: String) -> Date? {
        let value = timestamp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }

        let iso8601 = Date.ISO8601FormatStyle(includingFractionalSeconds: true)
        if let date = try? iso8601.parse(value) {
            return date
        }

        if value.count == 10 {
            if let date = try? iso8601.parse("\(value)T00:00:00Z") {
                return date
            }
        }

        // SQLite CURRENT_TIMESTAMP values omit both the `T` separator and zone,
        // but are UTC by definition.
        if value.count == 19 {
            let separator = value.index(value.startIndex, offsetBy: 10)
            if value[separator] == " " {
                var normalized = value
                normalized.replaceSubrange(separator...separator, with: "T")
                return try? iso8601.parse("\(normalized)Z")
            }
        }
        return nil
    }
}
