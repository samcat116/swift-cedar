import CedarFFI

/// Errors thrown by the Cedar SDK.
public enum CedarError: Error, Hashable, Sendable, CustomStringConvertible {
    /// Cedar source text failed to parse.
    case parse(String)
    /// Entities JSON was malformed or failed schema validation.
    case entities(String)
    /// A schema failed to parse.
    case schema(String)
    /// The authorization request was malformed or failed schema validation.
    case request(String)
    /// JSON (context, policy JSON, entities output) was invalid.
    case json(String)
    /// An unexpected internal error.
    case internalError(String)

    public var description: String {
        switch self {
        case .parse(let m): return "policy parse error: \(m)"
        case .entities(let m): return "entities error: \(m)"
        case .schema(let m): return "schema error: \(m)"
        case .request(let m): return "invalid request: \(m)"
        case .json(let m): return "JSON error: \(m)"
        case .internalError(let m): return "internal error: \(m)"
        }
    }
}

/// Runs an FFI call, translating FFI errors into `CedarError`.
func cedarCall<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let error as CedarFFI.CedarError {
        switch error {
        case .ParseError(let message): throw CedarError.parse(message)
        case .EntitiesError(let message): throw CedarError.entities(message)
        case .SchemaError(let message): throw CedarError.schema(message)
        case .RequestError(let message): throw CedarError.request(message)
        case .JsonError(let message): throw CedarError.json(message)
        case .InternalError(let message): throw CedarError.internalError(message)
        }
    }
}
