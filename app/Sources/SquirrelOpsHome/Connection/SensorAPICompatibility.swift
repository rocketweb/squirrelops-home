import Foundation

/// A component version describes shipped code. This protocol number describes
/// whether the app and sensor can safely communicate.
enum SensorAPICompatibility {
    static let current = 2

    static func supports(_ sensorProtocol: Int?) -> Bool {
        sensorProtocol == current
    }

    static func errorMessage(for sensorProtocol: Int?) -> String {
        guard let sensorProtocol else {
            return "This sensor predates the SquirrelOps 2 compatibility contract. Update the sensor before connecting."
        }
        return "This app supports sensor API protocol \(current), but the sensor reports protocol \(sensorProtocol). Update the app or sensor so their API protocols match."
    }
}
