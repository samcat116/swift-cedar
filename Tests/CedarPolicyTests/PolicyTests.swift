import XCTest
@testable import CedarPolicy

final class PolicyTests: XCTestCase {
    func testParseSinglePolicy() throws {
        let policy = try Policy(
            """
            @advice("deny-by-default")
            permit(principal == User::"alice", action, resource);
            """,
            id: "p1"
        )
        XCTAssertEqual(policy.id, "p1")
        XCTAssertEqual(policy.annotation("advice"), "deny-by-default")
        XCTAssertNil(policy.annotation("missing"))
        XCTAssertTrue(policy.text.contains("permit"))
    }

    func testParseErrorThrows() {
        XCTAssertThrowsError(try PolicySet("permit(principal action resource);")) { error in
            guard case CedarError.parse = error else {
                return XCTFail("expected CedarError.parse, got \(error)")
            }
        }
    }

    func testJSONRoundTrip() throws {
        let policy = try Policy(
            "permit(principal == User::\"alice\", action, resource);",
            id: "roundtrip"
        )
        let json = try policy.toJSON()
        let restored = try Policy.fromJSON(json, id: "roundtrip")
        XCTAssertEqual(restored.id, "roundtrip")
        XCTAssertTrue(restored.text.contains("User::\"alice\""))
    }

    func testPolicySetFromPolicies() throws {
        let set = try PolicySet(policies: [
            try Policy("permit(principal, action, resource);", id: "a"),
            try Policy("forbid(principal == User::\"x\", action, resource);", id: "b"),
        ])
        XCTAssertEqual(Set(set.policyIDs), ["a", "b"])
        XCTAssertFalse(set.isEmpty)
        XCTAssertTrue(PolicySet.empty().isEmpty)
    }

    func testEntityUIDDescription() {
        XCTAssertEqual(
            EntityUID(type: "PhotoApp::User", id: "ali\"ce").description,
            #"PhotoApp::User::"ali\"ce""#
        )
    }

    func testCedarVersion() {
        XCTAssertTrue(Cedar.version.hasPrefix("4."))
    }
}
