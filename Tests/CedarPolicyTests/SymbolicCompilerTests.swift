import XCTest

@testable import CedarPolicy

/// Symbolic analysis needs a cvc5 executable; without one there is nothing to
/// test. Point `CVC5` at the binary (or put `cvc5` on `PATH`) to run these.
private func cvc5Path() -> String? {
    if let configured = ProcessInfo.processInfo.environment["CVC5"], !configured.isEmpty {
        return FileManager.default.isExecutableFile(atPath: configured) ? configured : nil
    }
    let paths = ProcessInfo.processInfo.environment["PATH"]?.split(separator: ":") ?? []
    for directory in paths {
        let candidate = "\(directory)/cvc5"
        if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
    }
    return nil
}

final class SymbolicCompilerTests: XCTestCase {
    private let schema = try! Schema(
        """
        entity User;
        entity Photo { private: Bool };
        action view appliesTo { principal: [User], resource: [Photo] };
        """
    )

    private let viewEnvironment = RequestEnvironment(
        principalType: "User", action: "view", resourceType: "Photo")

    private func compiler() throws -> SymbolicCompiler {
        guard let path = cvc5Path() else {
            throw XCTSkip("cvc5 not found; set CVC5 or put it on PATH")
        }
        return SymbolicCompiler(solverPath: path)
    }

    func testOverlappingSetsAreNotDisjoint() async throws {
        let compiler = try compiler()
        let a = try PolicySet(#"permit(principal, action, resource);"#)
        let b = try PolicySet(#"permit(principal == User::"alice", action, resource);"#)

        let result = try await compiler.checkDisjoint(a, b, schema: schema, in: viewEnvironment)
        XCTAssertFalse(result.holds)
        // The counterexample is a request both sets allow, which is the whole
        // point of asking with one: it names the overlap concretely.
        let counterexample = try XCTUnwrap(result.counterexample)
        XCTAssertTrue(counterexample.contains("alice"), counterexample)
    }

    func testMutuallyExclusiveConditionsAreDisjoint() async throws {
        let compiler = try compiler()
        let a = try PolicySet(
            #"permit(principal, action, resource) when { resource.private };"#)
        let b = try PolicySet(
            #"permit(principal, action, resource) when { !resource.private };"#)

        let result = try await compiler.checkDisjoint(a, b, schema: schema, in: viewEnvironment)
        XCTAssertTrue(result.holds)
        XCTAssertNil(result.counterexample)
    }

    func testSubsumptionHoldsInOneDirectionOnly() async throws {
        let compiler = try compiler()
        let narrow = try PolicySet(#"permit(principal == User::"alice", action, resource);"#)
        let wide = try PolicySet(#"permit(principal, action, resource);"#)

        let forwards = try await compiler.checkImplies(
            narrow, wide, schema: schema, in: viewEnvironment)
        XCTAssertTrue(forwards.holds)

        let backwards = try await compiler.checkImplies(
            wide, narrow, schema: schema, in: viewEnvironment)
        XCTAssertFalse(backwards.holds)
        XCTAssertNotNil(backwards.counterexample)
    }

    func testMissingSolverIsASolverError() async throws {
        let compiler = SymbolicCompiler(solverPath: "/nonexistent/cvc5")
        let policies = try PolicySet(#"permit(principal, action, resource);"#)
        do {
            _ = try await compiler.checkDisjoint(
                policies, policies, schema: schema, in: viewEnvironment)
            XCTFail("expected a solver error")
        } catch CedarError.solver {
            // A caller that fails closed depends on this being distinguishable
            // from an analysis error.
        }
    }

    func testActionOutsideTheSchemaIsAnAnalysisError() async throws {
        let compiler = try compiler()
        let policies = try PolicySet(#"permit(principal, action, resource);"#)
        let unknown = RequestEnvironment(
            principalType: "User", action: "delete", resourceType: "Photo")
        do {
            _ = try await compiler.checkDisjoint(
                policies, policies, schema: schema, in: unknown)
            XCTFail("expected an analysis error")
        } catch CedarError.analysis {
        }
    }
}
