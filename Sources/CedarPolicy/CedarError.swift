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
    /// The SMT solver backing `SymbolicCompiler` could not be started, died,
    /// or timed out. Separate from `analysis` because it means the question
    /// went unanswered, not that the answer was no — a caller that fails
    /// closed on symbolic analysis has to tell those apart.
    case solver(String)
    /// The symbolic compiler rejected the query: a policy that is not
    /// well-typed for the request environment, an action absent from the
    /// schema, an unsupported construct.
    case analysis(String)

    public var description: String {
        switch self {
        case .parse(let m): return "policy parse error: \(m)"
        case .entities(let m): return "entities error: \(m)"
        case .schema(let m): return "schema error: \(m)"
        case .request(let m): return "invalid request: \(m)"
        case .json(let m): return "JSON error: \(m)"
        case .internalError(let m): return "internal error: \(m)"
        case .solver(let m): return "solver unavailable: \(m)"
        case .analysis(let m): return "symbolic analysis error: \(m)"
        }
    }

    /// Translate one FFI error. Shared by the sync and async call wrappers so
    /// a new FFI case cannot be handled in one and forgotten in the other.
    static func from(_ error: CedarFFI.CedarError) -> CedarError {
        switch error {
        case .ParseError(let message): return .parse(message)
        case .EntitiesError(let message): return .entities(message)
        case .SchemaError(let message): return .schema(message)
        case .RequestError(let message): return .request(message)
        case .JsonError(let message): return .json(message)
        case .InternalError(let message): return .internalError(message)
        case .SolverError(let message): return .solver(message)
        case .AnalysisError(let message): return .analysis(message)
        }
    }
}

/// Runs an FFI call, translating FFI errors into `CedarError`.
func cedarCall<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let error as CedarFFI.CedarError {
        throw CedarError.from(error)
    }
}

/// `cedarCall` for the async FFI surface (`SymbolicCompiler`).
func cedarCall<T>(_ body: () async throws -> T) async throws -> T {
    do {
        return try await body()
    } catch let error as CedarFFI.CedarError {
        throw CedarError.from(error)
    }
}
