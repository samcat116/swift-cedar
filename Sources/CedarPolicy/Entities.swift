import CedarFFI

/// The entities (principals, resources, their attributes and hierarchy)
/// available while evaluating an authorization request.
public final class Entities: @unchecked Sendable {
    let ffi: FfiEntities

    init(ffi: FfiEntities) {
        self.ffi = ffi
    }

    /// Parse entities from Cedar's entities JSON format.
    /// - Parameters:
    ///   - json: A JSON array of entity objects (`uid`, `attrs`, `parents`).
    ///   - schema: When provided, entities are validated against the schema.
    public convenience init(json: String, schema: Schema? = nil) throws {
        self.init(ffi: try cedarCall { try FfiEntities.fromJson(json: json, schema: schema?.ffi) })
    }

    /// An empty entity store.
    public static func empty() -> Entities {
        Entities(ffi: FfiEntities.empty())
    }

    /// The entities rendered in Cedar's entities JSON format.
    public func toJSON() throws -> String {
        try cedarCall { try ffi.toJson() }
    }
}
