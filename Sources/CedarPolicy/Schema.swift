import CedarFFI

/// A Cedar schema. Used to validate policies, entities, and requests.
public final class Schema: @unchecked Sendable {
    let ffi: FfiSchema

    init(ffi: FfiSchema) {
        self.ffi = ffi
    }

    /// Parse a schema from the human-readable Cedar schema format.
    public convenience init(_ cedarSchema: String) throws {
        self.init(ffi: try cedarCall { try FfiSchema.parse(text: cedarSchema) })
    }

    /// Parse a schema from Cedar's JSON schema format.
    public static func fromJSON(_ json: String) throws -> Schema {
        Schema(ffi: try cedarCall { try FfiSchema.fromJson(json: json) })
    }

    /// Validate a policy set against this schema.
    public func validate(_ policies: PolicySet, mode: ValidationMode = .strict) -> ValidationResult {
        let result = validatePolicies(schema: ffi, policies: policies.ffi, mode: mode.ffi)
        return ValidationResult(
            passed: result.passed,
            errors: result.errors.map { ValidationIssue(policyID: $0.policyId, message: $0.message) },
            warnings: result.warnings.map { ValidationIssue(policyID: $0.policyId, message: $0.message) }
        )
    }
}

/// How strictly `Schema.validate` checks policies.
public enum ValidationMode: Sendable {
    case strict
    case permissive

    var ffi: FfiValidationMode {
        switch self {
        case .strict: return .strict
        case .permissive: return .permissive
        }
    }
}

/// A single validation error or warning.
public struct ValidationIssue: Hashable, Sendable {
    public let policyID: String
    public let message: String
}

/// The outcome of validating a policy set against a schema.
public struct ValidationResult: Hashable, Sendable {
    /// True when there are no validation errors (warnings may be present).
    public let passed: Bool
    public let errors: [ValidationIssue]
    public let warnings: [ValidationIssue]
}
