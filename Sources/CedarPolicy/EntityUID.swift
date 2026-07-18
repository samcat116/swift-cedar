import CedarFFI

/// A reference to a Cedar entity, e.g. `User::"alice"`.
public struct EntityUID: Hashable, Sendable {
    /// The (possibly namespaced) entity type, e.g. `PhotoApp::User`.
    public var type: String
    /// The entity id, unescaped.
    public var id: String

    public init(type: String, id: String) {
        self.type = type
        self.id = id
    }

    var ffi: FfiEntityUid {
        FfiEntityUid(typeName: type, id: id)
    }
}

extension EntityUID: CustomStringConvertible {
    /// Cedar source representation, e.g. `User::"alice"`.
    public var description: String {
        let escaped = id
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\(type)::\"\(escaped)\""
    }
}

extension EntityUID: Codable {
    private enum CodingKeys: String, CodingKey {
        case type
        case id
    }
}
