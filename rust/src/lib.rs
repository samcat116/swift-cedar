//! FFI layer exposing the official `cedar-policy` crate to Swift via UniFFI.
//!
//! This crate keeps the FFI surface small and string/record based; the
//! ergonomic Swift API lives in the `CedarPolicy` Swift target that wraps
//! the generated bindings.

use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, Policy,
    PolicyId, PolicySet, Request, RequestEnv, Schema, ValidationMode, Validator,
};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler, CompiledPolicySet};
use tokio::process::Command;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CedarError {
    #[error("policy parse error: {message}")]
    ParseError { message: String },
    #[error("entities error: {message}")]
    EntitiesError { message: String },
    #[error("schema error: {message}")]
    SchemaError { message: String },
    #[error("invalid request: {message}")]
    RequestError { message: String },
    #[error("JSON error: {message}")]
    JsonError { message: String },
    #[error("internal error: {message}")]
    InternalError { message: String },
    /// The SMT solver could not be started, died, or timed out. Distinct from
    /// `AnalysisError` because it says the question went unanswered rather
    /// than that the answer was no — callers that fail closed need to tell
    /// those apart.
    #[error("solver unavailable: {message}")]
    SolverError { message: String },
    /// The symbolic compiler rejected the query itself: a policy that is not
    /// well-typed for the request environment, an action absent from the
    /// schema, an unsupported construct.
    #[error("symbolic analysis error: {message}")]
    AnalysisError { message: String },
}

fn parse_err(e: impl std::fmt::Display) -> CedarError {
    CedarError::ParseError {
        message: e.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Shared records & enums
// ---------------------------------------------------------------------------

/// A Cedar entity reference, e.g. `User::"alice"`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiEntityUid {
    /// Fully-qualified entity type, e.g. `PhotoApp::User`.
    pub type_name: String,
    /// The entity id (unescaped), e.g. `alice`.
    pub id: String,
}

impl FfiEntityUid {
    fn to_cedar(&self) -> Result<EntityUid, CedarError> {
        let ty = EntityTypeName::from_str(&self.type_name).map_err(parse_err)?;
        Ok(EntityUid::from_type_name_and_id(
            ty,
            EntityId::new(&self.id),
        ))
    }
}

fn uid_to_ffi(uid: &EntityUid) -> FfiEntityUid {
    FfiEntityUid {
        type_name: uid.type_name().to_string(),
        id: uid.id().unescaped().to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDecision {
    Allow,
    Deny,
}

/// The result of an authorization query.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiResponse {
    pub decision: FfiDecision,
    /// Ids of the policies that contributed to the decision.
    pub determining_policies: Vec<String>,
    /// Evaluation errors encountered while deciding (does not imply Deny).
    pub errors: Vec<String>,
}

/// One validation error or warning.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiValidationIssue {
    pub policy_id: String,
    pub message: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiValidationResult {
    pub passed: bool,
    pub errors: Vec<FfiValidationIssue>,
    pub warnings: Vec<FfiValidationIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiValidationMode {
    Strict,
    Permissive,
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

/// A single parsed Cedar policy.
#[derive(uniffi::Object)]
pub struct FfiPolicy {
    policy: Policy,
}

#[uniffi::export]
impl FfiPolicy {
    /// Parse a single policy (static or template) from Cedar source text.
    #[uniffi::constructor]
    pub fn parse(text: String, id: Option<String>) -> Result<Arc<Self>, CedarError> {
        let pid = id.map(|i| PolicyId::new(&i));
        let policy = Policy::parse(pid, &text).map_err(parse_err)?;
        Ok(Arc::new(Self { policy }))
    }

    /// Build a policy from the Cedar JSON policy format.
    #[uniffi::constructor]
    pub fn from_json(json: String, id: Option<String>) -> Result<Arc<Self>, CedarError> {
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| CedarError::JsonError {
                message: e.to_string(),
            })?;
        let pid = id.map(|i| PolicyId::new(&i));
        let policy = Policy::from_json(pid, value).map_err(parse_err)?;
        Ok(Arc::new(Self { policy }))
    }

    pub fn id(&self) -> String {
        self.policy.id().to_string()
    }

    /// The policy rendered in the Cedar JSON policy format.
    pub fn to_json(&self) -> Result<String, CedarError> {
        let value = self.policy.to_json().map_err(|e| CedarError::JsonError {
            message: e.to_string(),
        })?;
        Ok(value.to_string())
    }

    pub fn to_cedar(&self) -> String {
        self.policy.to_string()
    }

    /// The value of an annotation on this policy, if present.
    pub fn annotation(&self, key: String) -> Option<String> {
        self.policy.annotation(&key).map(|v| v.to_string())
    }
}

/// A set of Cedar policies (and templates).
#[derive(uniffi::Object)]
pub struct FfiPolicySet {
    policy_set: PolicySet,
}

#[uniffi::export]
impl FfiPolicySet {
    /// Parse a policy set from Cedar source text (may contain many policies).
    #[uniffi::constructor]
    pub fn parse(text: String) -> Result<Arc<Self>, CedarError> {
        let policy_set = PolicySet::from_str(&text).map_err(parse_err)?;
        Ok(Arc::new(Self { policy_set }))
    }

    /// Build a policy set from individually parsed policies.
    #[uniffi::constructor]
    pub fn from_policies(policies: Vec<Arc<FfiPolicy>>) -> Result<Arc<Self>, CedarError> {
        let policy_set = PolicySet::from_policies(policies.iter().map(|p| p.policy.clone()))
            .map_err(|e| CedarError::InternalError {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Self { policy_set }))
    }

    #[uniffi::constructor]
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            policy_set: PolicySet::new(),
        })
    }

    pub fn policy_ids(&self) -> Vec<String> {
        self.policy_set
            .policies()
            .map(|p| p.id().to_string())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.policy_set.is_empty()
    }

    pub fn to_cedar(&self) -> String {
        self.policy_set.to_string()
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// A Cedar schema, used for request/entity validation and policy validation.
#[derive(uniffi::Object)]
pub struct FfiSchema {
    schema: Schema,
}

#[uniffi::export]
impl FfiSchema {
    /// Parse a schema from the human-readable Cedar schema format.
    #[uniffi::constructor]
    pub fn parse(text: String) -> Result<Arc<Self>, CedarError> {
        let (schema, _warnings) =
            Schema::from_cedarschema_str(&text).map_err(|e| CedarError::SchemaError {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Self { schema }))
    }

    /// Parse a schema from the Cedar JSON schema format.
    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Arc<Self>, CedarError> {
        let schema = Schema::from_json_str(&json).map_err(|e| CedarError::SchemaError {
            message: e.to_string(),
        })?;
        Ok(Arc::new(Self { schema }))
    }
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

/// The set of entities (principals, resources, parents, attributes) used
/// when evaluating an authorization request.
#[derive(uniffi::Object)]
pub struct FfiEntities {
    entities: Entities,
}

#[uniffi::export]
impl FfiEntities {
    /// Parse entities from the Cedar entities JSON format. If a schema is
    /// provided, entities are validated against it.
    #[uniffi::constructor]
    pub fn from_json(json: String, schema: Option<Arc<FfiSchema>>) -> Result<Arc<Self>, CedarError> {
        let entities = Entities::from_json_str(&json, schema.as_deref().map(|s| &s.schema))
            .map_err(|e| CedarError::EntitiesError {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Self { entities }))
    }

    #[uniffi::constructor]
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            entities: Entities::empty(),
        })
    }

    pub fn to_json(&self) -> Result<String, CedarError> {
        let mut out = Vec::new();
        self.entities
            .write_to_json(&mut out)
            .map_err(|e| CedarError::JsonError {
                message: e.to_string(),
            })?;
        String::from_utf8(out).map_err(|e| CedarError::InternalError {
            message: e.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// The Cedar authorization engine.
#[derive(uniffi::Object)]
pub struct FfiAuthorizer {
    authorizer: Authorizer,
}

#[uniffi::export]
impl FfiAuthorizer {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            authorizer: Authorizer::new(),
        })
    }

    /// Evaluate an authorization request against a policy set and entities.
    ///
    /// `context_json` is a JSON object (Cedar context JSON format) or None
    /// for an empty context. If a schema is provided, the request is
    /// validated against it.
    #[allow(clippy::too_many_arguments)]
    pub fn is_authorized(
        &self,
        principal: FfiEntityUid,
        action: FfiEntityUid,
        resource: FfiEntityUid,
        context_json: Option<String>,
        policies: Arc<FfiPolicySet>,
        entities: Arc<FfiEntities>,
        schema: Option<Arc<FfiSchema>>,
    ) -> Result<FfiResponse, CedarError> {
        let principal = principal.to_cedar()?;
        let action = action.to_cedar()?;
        let resource = resource.to_cedar()?;

        let context = match context_json {
            Some(json) => {
                let schema_pair = schema.as_deref().map(|s| (&s.schema, &action));
                Context::from_json_str(&json, schema_pair).map_err(|e| CedarError::JsonError {
                    message: e.to_string(),
                })?
            }
            None => Context::empty(),
        };

        let request = Request::new(
            principal,
            action,
            resource,
            context,
            schema.as_deref().map(|s| &s.schema),
        )
        .map_err(|e| CedarError::RequestError {
            message: e.to_string(),
        })?;

        let response = self
            .authorizer
            .is_authorized(&request, &policies.policy_set, &entities.entities);

        Ok(FfiResponse {
            decision: match response.decision() {
                Decision::Allow => FfiDecision::Allow,
                Decision::Deny => FfiDecision::Deny,
            },
            determining_policies: response
                .diagnostics()
                .reason()
                .map(|id| id.to_string())
                .collect(),
            errors: response
                .diagnostics()
                .errors()
                .map(|e| e.to_string())
                .collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a policy set against a schema.
#[uniffi::export]
pub fn validate_policies(
    schema: Arc<FfiSchema>,
    policies: Arc<FfiPolicySet>,
    mode: FfiValidationMode,
) -> FfiValidationResult {
    let validator = Validator::new(schema.schema.clone());
    let mode = match mode {
        FfiValidationMode::Strict => ValidationMode::Strict,
        FfiValidationMode::Permissive => ValidationMode::Permissive,
    };
    let result = validator.validate(&policies.policy_set, mode);
    FfiValidationResult {
        passed: result.validation_passed(),
        errors: result
            .validation_errors()
            .map(|e| FfiValidationIssue {
                policy_id: e.policy_id().to_string(),
                message: e.to_string(),
            })
            .collect(),
        warnings: result
            .validation_warnings()
            .map(|w| FfiValidationIssue {
                policy_id: w.policy_id().to_string(),
                message: w.to_string(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Symbolic analysis (SymCC)
// ---------------------------------------------------------------------------

/// The "type" of request an analysis is performed over: which principal type,
/// which action, which resource type.
///
/// SymCC reasons one request environment at a time, so a question about a
/// whole policy set is really N questions. The caller chooses N — it knows
/// which environments can possibly matter and which are a waste of a solver
/// process.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRequestEnv {
    /// Fully-qualified principal entity type, e.g. `User`.
    pub principal_type: String,
    /// The action id, e.g. `vm:start` (the type is always `Action`).
    pub action: String,
    /// Fully-qualified resource entity type, e.g. `Project`.
    pub resource_type: String,
}

/// The answer to one analysis query.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAnalysisResult {
    /// Whether the property asked about holds.
    pub holds: bool,
    /// A concrete request violating the property, rendered for humans, when
    /// the caller asked for one and the property does not hold.
    pub counterexample: Option<String>,
}

/// A symbolic compiler over a local cvc5 process.
///
/// Stateless by construction: each query spawns its own solver, because a
/// long-lived SMT process is stateful, poisonable by one bad query, and would
/// have to be serialized behind a lock anyway. Spawning is negligible next to
/// solving, and these analyses run on policy writes, not on the request path.
#[derive(uniffi::Object)]
pub struct FfiSymbolicCompiler {
    solver_path: String,
    timeout_ms: u32,
}

/// The two-policy-set questions this compiler can answer.
enum Query {
    /// Is any request allowed by both sets?
    Disjoint,
    /// Does every request allowed by the first set get allowed by the second?
    Implies,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiSymbolicCompiler {
    /// Build a compiler driving the cvc5 executable at `solver_path`.
    ///
    /// The path is explicit rather than read from the ambient `CVC5`
    /// environment variable the way `LocalSolver::cvc5()` does: a server
    /// deciding whether to fail closed needs to know *which* binary it is
    /// about to trust, and inheriting it from the environment makes that
    /// unanswerable.
    #[uniffi::constructor]
    pub fn new(solver_path: String, timeout_ms: u32) -> Arc<Self> {
        Arc::new(Self {
            solver_path,
            timeout_ms,
        })
    }

    /// Returns whether no request in `env` is allowed by both policy sets.
    ///
    /// `holds == false` means the sets overlap, and the counterexample is a
    /// request both would allow.
    pub async fn check_disjoint(
        &self,
        schema: Arc<FfiSchema>,
        policies_a: Arc<FfiPolicySet>,
        policies_b: Arc<FfiPolicySet>,
        env: FfiRequestEnv,
        counterexample: bool,
    ) -> Result<FfiAnalysisResult, CedarError> {
        self.run(Query::Disjoint, schema, policies_a, policies_b, env, counterexample)
            .await
    }

    /// Returns whether every request in `env` allowed by `policies_a` is also
    /// allowed by `policies_b` — subsumption.
    ///
    /// `holds == false` means the first set reaches something the second does
    /// not, and the counterexample is such a request.
    pub async fn check_implies(
        &self,
        schema: Arc<FfiSchema>,
        policies_a: Arc<FfiPolicySet>,
        policies_b: Arc<FfiPolicySet>,
        env: FfiRequestEnv,
        counterexample: bool,
    ) -> Result<FfiAnalysisResult, CedarError> {
        self.run(Query::Implies, schema, policies_a, policies_b, env, counterexample)
            .await
    }
}

impl FfiSymbolicCompiler {
    async fn run(
        &self,
        query: Query,
        schema: Arc<FfiSchema>,
        policies_a: Arc<FfiPolicySet>,
        policies_b: Arc<FfiPolicySet>,
        env: FfiRequestEnv,
        counterexample: bool,
    ) -> Result<FfiAnalysisResult, CedarError> {
        let request_env = env.to_cedar()?;
        // Compilation is where a policy that is not well-typed for this
        // environment is caught; it is an analysis error, not a solver one.
        let compiled_a =
            CompiledPolicySet::compile(&policies_a.policy_set, &request_env, &schema.schema)
                .map_err(analysis_err)?;
        let compiled_b =
            CompiledPolicySet::compile(&policies_b.policy_set, &request_env, &schema.schema)
                .map_err(analysis_err)?;

        let mut compiler = self.spawn()?;
        if counterexample {
            let found = match query {
                Query::Disjoint => {
                    compiler
                        .check_disjoint_with_counterexample_opt(&compiled_a, &compiled_b)
                        .await
                }
                Query::Implies => {
                    compiler
                        .check_implies_with_counterexample_opt(&compiled_a, &compiled_b)
                        .await
                }
            }
            .map_err(solver_err)?;
            Ok(FfiAnalysisResult {
                holds: found.is_none(),
                counterexample: found.map(|env| env.to_string()),
            })
        } else {
            let holds = match query {
                Query::Disjoint => compiler.check_disjoint_opt(&compiled_a, &compiled_b).await,
                Query::Implies => compiler.check_implies_opt(&compiled_a, &compiled_b).await,
            }
            .map_err(solver_err)?;
            Ok(FfiAnalysisResult {
                holds,
                counterexample: None,
            })
        }
    }

    fn spawn(&self) -> Result<CedarSymCompiler<LocalSolver>, CedarError> {
        let mut command = Command::new(&self.solver_path);
        command
            .args(["--lang", "smt"])
            .arg(format!("--tlimit={}", self.timeout_ms));
        let solver = LocalSolver::from_command(&mut command).map_err(solver_err)?;
        CedarSymCompiler::new(solver).map_err(solver_err)
    }
}

impl FfiRequestEnv {
    fn to_cedar(&self) -> Result<RequestEnv, CedarError> {
        let principal = EntityTypeName::from_str(&self.principal_type).map_err(parse_err)?;
        let resource = EntityTypeName::from_str(&self.resource_type).map_err(parse_err)?;
        let action = FfiEntityUid {
            type_name: "Action".to_string(),
            id: self.action.clone(),
        }
        .to_cedar()?;
        Ok(RequestEnv::new(principal, action, resource))
    }
}

fn solver_err(e: impl std::fmt::Display) -> CedarError {
    CedarError::SolverError {
        message: e.to_string(),
    }
}

fn analysis_err(e: impl std::fmt::Display) -> CedarError {
    CedarError::AnalysisError {
        message: e.to_string(),
    }
}

/// The version of the underlying cedar-policy engine.
#[uniffi::export]
pub fn cedar_version() -> String {
    cedar_policy::get_sdk_version().to_string()
}

// Keep the unused helper from warning until template linking lands.
#[allow(dead_code)]
fn _unused(uid: &EntityUid) -> FfiEntityUid {
    uid_to_ffi(uid)
}
