import XCTest
@testable import CedarPolicy

final class ValidationTests: XCTestCase {
    let schemaText = """
        entity User;
        entity Photo;
        action view appliesTo {
            principal: [User],
            resource: [Photo],
            context: { mfa: Bool }
        };
        """

    func testValidPolicyPasses() throws {
        let schema = try Schema(schemaText)
        let policies = try PolicySet(
            """
            permit(principal == User::"alice", action == Action::"view", resource)
            when { context.mfa == true };
            """
        )
        let result = schema.validate(policies)
        XCTAssertTrue(result.passed, "unexpected errors: \(result.errors)")
        XCTAssertTrue(result.errors.isEmpty)
    }

    func testInvalidPolicyFails() throws {
        let schema = try Schema(schemaText)
        let policies = try PolicySet(
            """
            permit(principal == User::"alice", action == Action::"edit", resource);
            """
        )
        let result = schema.validate(policies)
        XCTAssertFalse(result.passed)
        XCTAssertFalse(result.errors.isEmpty)
        XCTAssertFalse(result.errors[0].message.isEmpty)
    }

    func testSchemaValidatedRequestRejectsBadContext() throws {
        let schema = try Schema(schemaText)
        let policies = try PolicySet("permit(principal, action, resource);")
        // Context has a field the schema does not allow -> request error.
        XCTAssertThrowsError(
            try Authorizer().isAuthorized(
                principal: EntityUID(type: "User", id: "alice"),
                action: EntityUID(type: "Action", id: "view"),
                resource: EntityUID(type: "Photo", id: "x.jpg"),
                context: ["unexpected": "field"],
                policies: policies,
                schema: schema
            )
        )
    }

    func testBadSchemaThrows() {
        XCTAssertThrowsError(try Schema("entity ;;;")) { error in
            guard case CedarError.schema = error else {
                return XCTFail("expected CedarError.schema, got \(error)")
            }
        }
    }
}
