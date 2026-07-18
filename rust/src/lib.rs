//! FFI layer exposing the official `cedar-policy` crate to Swift via UniFFI.
//!
//! This crate keeps the FFI surface small and string/record based; the
//! ergonomic Swift API lives in the `CedarPolicy` Swift target that wraps
//! the generated bindings.

use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, Policy,
    PolicyId, PolicySet, Request, Schema, ValidationMode, Validator,
};

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
