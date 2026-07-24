import Foundation
import Testing
@testable import SquirrelOpsHome

@Suite("Timestamp presentation")
struct TimestampPresentationTests {
    private let easternStandardTime = TimeZone(secondsFromGMT: -5 * 60 * 60)!

    @Test("Fractional UTC timestamp renders in local shape without fractions")
    func fractionalTimestamp() {
        #expect(
            TimestampPresentation.local(
                "2026-01-24T15:16:17.987654+00:00",
                timeZone: easternStandardTime
            ) == "2026-01-24 10:16:17"
        )
    }

    @Test("Offset timestamp is converted to the requested local time")
    func offsetTimestamp() {
        #expect(
            TimestampPresentation.local(
                "2026-01-24T15:16:17+02:00",
                timeZone: easternStandardTime
            ) == "2026-01-24 08:16:17"
        )
    }

    @Test("Whole-second and SQLite timestamps share the exact app format")
    func wholeSecondTimestamps() {
        let utc = TimeZone(secondsFromGMT: 0)!

        #expect(
            TimestampPresentation.local(
                "2026-01-24T15:16:17Z",
                timeZone: utc
            ) == "2026-01-24 15:16:17"
        )
        #expect(
            TimestampPresentation.local(
                "2026-01-24 15:16:17",
                timeZone: utc
            ) == "2026-01-24 15:16:17"
        )
        #expect(
            TimestampPresentation.local(
                "2026-01-24",
                timeZone: utc
            ) == "2026-01-24 00:00:00"
        )
    }

    @Test("Default presentation uses the system local time zone")
    func systemLocalTimeZone() throws {
        let timestamp = "2026-01-24T15:16:17Z"
        let date = try #require(
            try? Date.ISO8601FormatStyle().parse(timestamp)
        )
        let expected = DateFormatter()
        expected.locale = Locale(identifier: "en_US_POSIX")
        expected.calendar = Calendar(identifier: .gregorian)
        expected.timeZone = .autoupdatingCurrent
        expected.dateFormat = "yyyy-MM-dd HH:mm:ss"

        #expect(
            TimestampPresentation.local(timestamp)
                == expected.string(from: date)
        )
    }

    @Test("Invalid timestamps never leak raw server values into the UI")
    func invalidTimestamp() {
        #expect(
            TimestampPresentation.local(
                "not-a-timestamp",
                timeZone: easternStandardTime
            ) == TimestampPresentation.unavailable
        )
    }

    @Test("Generic values format only recognized timestamps")
    func genericValuesFormatOnlyTimestamps() {
        #expect(
            TimestampPresentation.localIfRecognized(
                "2026-07-24T15:16:17.987654Z",
                timeZone: easternStandardTime
            ) == "2026-07-24 10:16:17"
        )
        #expect(
            TimestampPresentation.localIfRecognized("server-2026-07-24")
                == "server-2026-07-24"
        )
    }
}
