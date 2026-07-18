import Foundation

/// A Cedar value, used for request context. Serializes to the Cedar
/// JSON value format (including `__entity` / `__extn` escapes).
public indirect enum CedarValue: Hashable, Sendable {
    case bool(Bool)
    case long(Int64)
    case string(String)
    case entity(EntityUID)
    case set([CedarValue])
    case record([String: CedarValue])
    /// Cedar `decimal` extension value, e.g. `.decimal("12.34")`.
    case decimal(String)
    /// Cedar `ip` extension value, e.g. `.ipaddr("192.168.1.0/24")`.
    case ipaddr(String)

    /// The value in Cedar's JSON representation, as a Foundation object
    /// suitable for `JSONSerialization`.
    var jsonObject: Any {
        switch self {
        case .bool(let b):
            return b
        case .long(let n):
            return n
        case .string(let s):
            return s
        case .entity(let uid):
            return ["__entity": ["type": uid.type, "id": uid.id]]
        case .set(let values):
            return values.map(\.jsonObject)
        case .record(let fields):
            return fields.mapValues(\.jsonObject)
        case .decimal(let value):
            return ["__extn": ["fn": "decimal", "arg": value]]
        case .ipaddr(let value):
            return ["__extn": ["fn": "ip", "arg": value]]
        }
    }
}

extension CedarValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}

extension CedarValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int64) { self = .long(value) }
}

extension CedarValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}

extension CedarValue: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: CedarValue...) { self = .set(elements) }
}

extension CedarValue: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, CedarValue)...) {
        self = .record(Dictionary(uniqueKeysWithValues: elements))
    }
}

extension Dictionary where Key == String, Value == CedarValue {
    /// The context encoded as a Cedar context JSON string.
    func contextJSON() throws -> String {
        let object = mapValues(\.jsonObject)
        let data = try JSONSerialization.data(withJSONObject: object)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CedarError.json("context is not valid UTF-8")
        }
        return json
    }
}
