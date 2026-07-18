import CedarFFI

/// An authorization decision.
public enum Decision: Hashable, Sendable {
    case allow
    case deny
}

/// An authorization request: who (principal) wants to do what (action)
/// on which resource, with optional context.
public struct Request: Sendable {
    public var principal: EntityUID
    public var action: EntityUID
    public var resource: EntityUID
    public var context: [String: CedarValue]

    public init(
        principal: EntityUID,
        action: EntityUID,
        resource: EntityUID,
        context: [String: CedarValue] = [:]
    ) {
        self.principal = principal
        self.action = action
        self.resource = resource
        self.context = context
    }
}

/// The engine's answer to an authorization request.
public struct Response: Hashable, Sendable {
    public let decision: Decision
    /// Ids of the policies that determined the decision.
    public let determiningPolicies: [String]
    /// Evaluation errors encountered while deciding. A non-empty list does
    /// not imply a `deny`; Cedar skips policies that error.
    public let errors: [String]

    /// Convenience: `decision == .allow`.
    public var isAllowed: Bool { decision == .allow }
}

/// The Cedar authorization engine.
public final class Authorizer: @unchecked Sendable {
    let ffi: FfiAuthorizer

    public init() {
        self.ffi = FfiAuthorizer()
    }

    /// Evaluate a request against a policy set.
    /// - Parameters:
    ///   - request: The principal/action/resource/context to decide.
    ///   - policies: The policy set to evaluate.
    ///   - entities: Entity data referenced by the policies. Defaults to empty.
    ///   - schema: When provided, the request and context are validated
    ///     against the schema before evaluation.
    public func isAuthorized(
        _ request: Request,
        policies: PolicySet,
        entities: Entities = .empty(),
        schema: Schema? = nil
    ) throws -> Response {
        let contextJSON = request.context.isEmpty ? nil : try request.context.contextJSON()
        let response = try cedarCall {
            try ffi.isAuthorized(
                principal: request.principal.ffi,
                action: request.action.ffi,
                resource: request.resource.ffi,
                contextJson: contextJSON,
                policies: policies.ffi,
                entities: entities.ffi,
                schema: schema?.ffi
            )
        }
        return Response(
            decision: response.decision == .allow ? .allow : .deny,
            determiningPolicies: response.determiningPolicies,
            errors: response.errors
        )
    }

    /// Convenience overload taking principal/action/resource directly.
    public func isAuthorized(
        principal: EntityUID,
        action: EntityUID,
        resource: EntityUID,
        context: [String: CedarValue] = [:],
        policies: PolicySet,
        entities: Entities = .empty(),
        schema: Schema? = nil
    ) throws -> Response {
        try isAuthorized(
            Request(principal: principal, action: action, resource: resource, context: context),
            policies: policies,
            entities: entities,
            schema: schema
        )
    }
}

/// Namespace for SDK-level metadata.
public enum Cedar {
    /// The version of the underlying cedar-policy engine.
    public static var version: String { cedarVersion() }
}
