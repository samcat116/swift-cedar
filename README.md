# swift-cedar

A Swift SDK for the [Cedar policy language](https://docs.cedarpolicy.com/) — express
fine-grained permissions as policies and evaluate them natively on Apple platforms.

The SDK wraps the official [`cedar-policy`](https://crates.io/crates/cedar-policy) Rust
crate (the same engine behind AWS Verified Permissions) via
[UniFFI](https://mozilla.github.io/uniffi-rs/), packaged as an XCFramework, with an
idiomatic Swift API on top. It is **not** a reimplementation, so evaluation semantics
match upstream Cedar exactly.

## Usage

```swift
import CedarPolicy

let policies = try PolicySet(
    """
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource == Photo::"VacationPhoto94.jpg"
    );
    """
)

let response = try Authorizer().isAuthorized(
    principal: EntityUID(type: "User", id: "alice"),
    action: EntityUID(type: "Action", id: "view"),
    resource: EntityUID(type: "Photo", id: "VacationPhoto94.jpg"),
    policies: policies
)

response.isAllowed            // true
response.determiningPolicies  // ["policy0"]
```

### Context

Request context uses `CedarValue`, which supports Swift literals and Cedar's
extension types:

```swift
let response = try Authorizer().isAuthorized(
    principal: EntityUID(type: "User", id: "alice"),
    action: EntityUID(type: "Action", id: "login"),
    resource: EntityUID(type: "App", id: "console"),
    context: [
        "mfa": true,
        "riskScore": 10,
        "sourceIP": .ipaddr("10.0.0.1"),
    ],
    policies: policies
)
```

### Entities

Entity data (attributes and hierarchy) uses Cedar's entities JSON format:

```swift
let entities = try Entities(
    json: """
    [
        { "uid": { "type": "User", "id": "alice" },
          "attrs": { "department": "Engineering" },
          "parents": [ { "type": "Group", "id": "admins" } ] }
    ]
    """
)
```

### Schemas and validation

```swift
let schema = try Schema(
    """
    entity User;
    entity Photo;
    action view appliesTo { principal: [User], resource: [Photo] };
    """
)

// Validate policies at authoring time:
let result = schema.validate(policies)   // .passed, .errors, .warnings

// Or validate requests/entities at evaluation time:
try Authorizer().isAuthorized(request, policies: policies, entities: entities, schema: schema)
```

### Symbolic analysis

`Authorizer` answers one request. `SymbolicCompiler` answers questions about
*every* request: whether two policy sets can ever both allow the same one
(`checkDisjoint`), and whether one set's allows are contained in another's
(`checkImplies` — subsumption). Both return a concrete counterexample when the
property fails, which is what makes an answer explainable rather than merely
correct.

```swift
let compiler = SymbolicCompiler(solverPath: "/usr/local/bin/cvc5")
let environment = RequestEnvironment(
    principalType: "User", action: "view", resourceType: "Photo")

let result = try await compiler.checkDisjoint(
    proposedGrant, ceiling, schema: schema, in: environment)

if !result.holds {
    print("overlap: \(result.counterexample ?? "")")
}
```

This is backed by [SymCC](https://crates.io/crates/cedar-policy-symcc), which
compiles policies to SMT and discharges them with a local **cvc5 1.3.1**
process:

```sh
./scripts/install-cvc5.sh            # /usr/local/bin/cvc5, checksum-verified
```

cvc5 is a runtime dependency of `SymbolicCompiler` alone — the prebuilt
binaries do not contain it, nothing links against it, and the rest of the SDK
works without it. Analysis reasons one request environment at a time, so a
question about a whole policy set is N queries; choosing which environments
can possibly matter is the caller's job. A missing or dead solver throws
`CedarError.solver`, kept distinct from `CedarError.analysis` so callers that
fail closed can tell "unanswered" from "the answer is no".

## Installing

Tagged releases ship prebuilt binaries (no Rust toolchain needed):

- **Apple platforms** — `CedarFFI.xcframework.zip` (macOS arm64 + x86_64, iOS
  device and simulator)
- **Linux** — `CedarFFI.artifactbundle.zip` (x86_64 + aarch64 gnu), consumed as
  a static-library artifact bundle ([SE-0482](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0482-swiftpm-static-library-binary-target-non-apple-platforms.md));
  requires Swift 6.3 or later

The `Package.swift` on each release tag points at those assets, so this is just:

```swift
.package(url: "https://github.com/samcat116/swift-cedar.git", from: "0.1.0")
```

## Building from source

On `main` the binary target is path-based and generated, not checked in, so the
Rust core must be built once before the Swift package resolves. Both scripts
require a Rust toolchain.

macOS:

```sh
./scripts/build-xcframework.sh   # artifacts/CedarFFI.xcframework
swift test
```

By default the script builds the slices for the Rust targets you have installed.
For iOS device + simulator slices:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
./scripts/build-xcframework.sh
```

Linux (Swift 6.3+):

```sh
./scripts/build-linux.sh         # artifacts/CedarFFI.artifactbundle
swift test
```

The symbolic-analysis tests skip themselves unless a cvc5 is on `PATH` or named
by `CVC5`; `./scripts/install-cvc5.sh` provides one.

## Releasing

The `Release` GitHub Actions workflow (manual dispatch, takes a version number)
builds the XCFramework and the Linux artifact bundle, uploads both as release
assets, and tags a commit whose `Package.swift` references them by
`url:`/`checksum:`. The stamped manifest exists only on the tag; `main` keeps
the path-based targets for local development.

## Layout

- `rust/` — the `cedar-ffi` crate: a thin UniFFI wrapper over `cedar-policy`
  and `cedar-policy-symcc`
- `Sources/CedarFFI/` — UniFFI-generated bindings (regenerated by the build script)
- `Sources/CedarPolicy/` — the public Swift API
- `Tests/CedarPolicyTests/` — authorization, parsing, validation, and symbolic
  analysis tests (the last skip themselves without cvc5)

## Not yet implemented

- Template linking (`PolicySet` parses templates but there is no link API yet)
- Partial evaluation

## License

Apache-2.0, matching upstream Cedar.
