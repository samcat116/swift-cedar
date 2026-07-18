import XCTest
@testable import CedarPolicy

final class AuthorizationTests: XCTestCase {
    let policies = try! PolicySet(
        """
        @id("alice-can-view")
        permit(
            principal == User::"alice",
            action == Action::"view",
            resource == Photo::"VacationPhoto94.jpg"
        );
        """
    )

    func testAllow() throws {
        let response = try Authorizer().isAuthorized(
            principal: EntityUID(type: "User", id: "alice"),
            action: EntityUID(type: "Action", id: "view"),
            resource: EntityUID(type: "Photo", id: "VacationPhoto94.jpg"),
            policies: policies
        )
        XCTAssertEqual(response.decision, .allow)
        XCTAssertTrue(response.isAllowed)
        XCTAssertEqual(response.determiningPolicies.count, 1)
        XCTAssertTrue(response.errors.isEmpty)
    }

    func testDenyDifferentPrincipal() throws {
        let response = try Authorizer().isAuthorized(
            principal: EntityUID(type: "User", id: "bob"),
            action: EntityUID(type: "Action", id: "view"),
            resource: EntityUID(type: "Photo", id: "VacationPhoto94.jpg"),
            policies: policies
        )
        XCTAssertEqual(response.decision, .deny)
        XCTAssertTrue(response.determiningPolicies.isEmpty)
    }

    func testDenyEmptyPolicySet() throws {
        let response = try Authorizer().isAuthorized(
            principal: EntityUID(type: "User", id: "alice"),
            action: EntityUID(type: "Action", id: "view"),
            resource: EntityUID(type: "Photo", id: "VacationPhoto94.jpg"),
            policies: .empty()
        )
        XCTAssertEqual(response.decision, .deny)
    }

    func testContextCondition() throws {
        let policies = try PolicySet(
            """
            permit(principal, action == Action::"login", resource)
            when { context.mfa == true && context.riskScore <= 50 };
            """
        )
        let base = Request(
            principal: EntityUID(type: "User", id: "alice"),
            action: EntityUID(type: "Action", id: "login"),
            resource: EntityUID(type: "App", id: "console")
        )

        var request = base
        request.context = ["mfa": true, "riskScore": 10]
        XCTAssertTrue(try Authorizer().isAuthorized(request, policies: policies).isAllowed)

        request.context = ["mfa": false, "riskScore": 10]
        XCTAssertFalse(try Authorizer().isAuthorized(request, policies: policies).isAllowed)

        request.context = ["mfa": true, "riskScore": 90]
        XCTAssertFalse(try Authorizer().isAuthorized(request, policies: policies).isAllowed)
    }

    func testEntityHierarchy() throws {
        let policies = try PolicySet(
            """
            permit(
                principal in Group::"admins",
                action,
                resource
            );
            """
        )
        let entities = try Entities(
            json: """
            [
                { "uid": { "type": "User", "id": "alice" },
                  "attrs": {},
                  "parents": [ { "type": "Group", "id": "admins" } ] },
                { "uid": { "type": "User", "id": "bob" },
                  "attrs": {},
                  "parents": [] },
                { "uid": { "type": "Group", "id": "admins" },
                  "attrs": {},
                  "parents": [] }
            ]
            """
        )

        let alice = try Authorizer().isAuthorized(
            principal: EntityUID(type: "User", id: "alice"),
            action: EntityUID(type: "Action", id: "delete"),
            resource: EntityUID(type: "Photo", id: "x.jpg"),
            policies: policies,
            entities: entities
        )
        XCTAssertTrue(alice.isAllowed)

        let bob = try Authorizer().isAuthorized(
            principal: EntityUID(type: "User", id: "bob"),
            action: EntityUID(type: "Action", id: "delete"),
            resource: EntityUID(type: "Photo", id: "x.jpg"),
            policies: policies,
            entities: entities
        )
        XCTAssertFalse(bob.isAllowed)
    }

    func testForbidOverridesPermit() throws {
        let policies = try PolicySet(
            """
            permit(principal, action, resource);
            forbid(principal == User::"mallory", action, resource);
            """
        )
        let mallory = try Authorizer().isAuthorized(
            principal: EntityUID(type: "User", id: "mallory"),
            action: EntityUID(type: "Action", id: "view"),
            resource: EntityUID(type: "Photo", id: "x.jpg"),
            policies: policies
        )
        XCTAssertEqual(mallory.decision, .deny)
    }
}
