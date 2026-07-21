import CedarFFI

/// The "type" of request an analysis reasons over: a principal type, an
/// action, and a resource type.
///
/// SymCC answers one request environment at a time, so a question about a
/// whole policy set is really N questions. Choosing N is the caller's job —
/// it knows which environments can possibly matter.
public struct RequestEnvironment: Hashable, Sendable {
    /// Fully-qualified principal entity type, e.g. `User`.
    public var principalType: String
    /// The action id, e.g. `vm:start`. The entity type is always `Action`.
    public var action: String
    /// Fully-qualified resource entity type, e.g. `Project`.
    public var resourceType: String

    public init(principalType: String, action: String, resourceType: String) {
        self.principalType = principalType
        self.action = action
        self.resourceType = resourceType
    }

    var ffi: FfiRequestEnv {
        FfiRequestEnv(principalType: principalType, action: action, resourceType: resourceType)
    }
}

/// The answer to one symbolic query.
public struct AnalysisResult: Hashable, Sendable {
    /// Whether the property asked about holds for every request in the
    /// environment.
    public let holds: Bool
    /// A concrete request violating the property, rendered for humans —
    /// present only when the caller asked for one and the property does not
    /// hold.
    public let counterexample: String?
}

/// Symbolic analysis of Cedar policies: proves properties over *every*
/// possible request in an environment, rather than evaluating one.
///
/// Backed by [SymCC](https://crates.io/crates/cedar-policy-symcc), which
/// compiles policies to SMT and discharges them with a local **cvc5 1.3.1**
/// process. That binary is a runtime dependency of this type only — the rest
/// of the SDK does not need it, and nothing links against it.
///
/// Each query spawns its own solver process. An SMT process is stateful and
/// one bad query poisons it, so sharing one would mean a lock and a recovery
/// story for no real gain: spawning costs nothing next to solving, and these
/// analyses belong on policy writes, not on the request path.
public final class SymbolicCompiler: @unchecked Sendable {
    let ffi: FfiSymbolicCompiler

    /// - Parameters:
    ///   - solverPath: Path to the cvc5 executable. Explicit rather than
    ///     inherited from the `CVC5` environment variable, so a caller that
    ///     fails closed when analysis is unavailable knows which binary it is
    ///     about to trust.
    ///   - timeout: Per-query wall-clock limit for the solver, in
    ///     milliseconds. A query that exceeds it throws `CedarError.solver`.
    public init(solverPath: String, timeoutMilliseconds: UInt32 = 60_000) {
        self.ffi = FfiSymbolicCompiler(solverPath: solverPath, timeoutMs: timeoutMilliseconds)
    }

    /// Is there any request in `environment` that both policy sets allow?
    ///
    /// `holds == false` means they overlap, and the counterexample is a
    /// request both would allow.
    public func checkDisjoint(
        _ a: PolicySet,
        _ b: PolicySet,
        schema: Schema,
        in environment: RequestEnvironment,
        withCounterexample: Bool = true
    ) async throws -> AnalysisResult {
        let result = try await cedarCall {
            try await ffi.checkDisjoint(
                schema: schema.ffi,
                policiesA: a.ffi,
                policiesB: b.ffi,
                env: environment.ffi,
                counterexample: withCounterexample
            )
        }
        return AnalysisResult(holds: result.holds, counterexample: result.counterexample)
    }

    /// Does every request in `environment` allowed by `a` get allowed by `b`
    /// — subsumption?
    ///
    /// `holds == false` means `a` reaches something `b` does not, and the
    /// counterexample is such a request.
    public func checkImplies(
        _ a: PolicySet,
        _ b: PolicySet,
        schema: Schema,
        in environment: RequestEnvironment,
        withCounterexample: Bool = true
    ) async throws -> AnalysisResult {
        let result = try await cedarCall {
            try await ffi.checkImplies(
                schema: schema.ffi,
                policiesA: a.ffi,
                policiesB: b.ffi,
                env: environment.ffi,
                counterexample: withCounterexample
            )
        }
        return AnalysisResult(holds: result.holds, counterexample: result.counterexample)
    }
}
