import CedarFFI

/// A single parsed Cedar policy (static policy or template).
public final class Policy: @unchecked Sendable {
    let ffi: FfiPolicy

    init(ffi: FfiPolicy) {
        self.ffi = ffi
    }

    /// Parse a policy from Cedar source text.
    /// - Parameters:
    ///   - text: Cedar source for a single policy.
    ///   - id: Optional policy id; Cedar assigns `policy0`-style ids otherwise.
    public convenience init(_ text: String, id: String? = nil) throws {
        self.init(ffi: try cedarCall { try FfiPolicy.parse(text: text, id: id) })
    }

    /// Build a policy from Cedar's JSON policy format.
    public static func fromJSON(_ json: String, id: String? = nil) throws -> Policy {
        Policy(ffi: try cedarCall { try FfiPolicy.fromJson(json: json, id: id) })
    }

    /// The policy's id.
    public var id: String { ffi.id() }

    /// The policy rendered as Cedar source text.
    public var text: String { ffi.toCedar() }

    /// The policy rendered in Cedar's JSON policy format.
    public func toJSON() throws -> String {
        try cedarCall { try ffi.toJson() }
    }

    /// The value of an annotation (e.g. `@advice("...")`), if present.
    public func annotation(_ key: String) -> String? {
        ffi.annotation(key: key)
    }
}

/// A set of Cedar policies evaluated together.
public final class PolicySet: @unchecked Sendable {
    let ffi: FfiPolicySet

    init(ffi: FfiPolicySet) {
        self.ffi = ffi
    }

    /// Parse a policy set from Cedar source text containing zero or more policies.
    public convenience init(_ text: String) throws {
        self.init(ffi: try cedarCall { try FfiPolicySet.parse(text: text) })
    }

    /// Build a policy set from individually parsed policies.
    public convenience init(policies: [Policy]) throws {
        self.init(ffi: try cedarCall { try FfiPolicySet.fromPolicies(policies: policies.map(\.ffi)) })
    }

    /// An empty policy set (every request is denied).
    public static func empty() -> PolicySet {
        PolicySet(ffi: FfiPolicySet.empty())
    }

    /// Ids of the policies in this set.
    public var policyIDs: [String] { ffi.policyIds() }

    public var isEmpty: Bool { ffi.isEmpty() }

    /// The policy set rendered as Cedar source text.
    public var text: String { ffi.toCedar() }
}
