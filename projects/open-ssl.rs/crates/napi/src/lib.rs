//! Platform-neutral N-API surface for OpenSSL.
//!
//! This crate forwards generic capabilities to the `wae` facade and contains no
//! platform `cfg` branches and no platform string literals. Missing host
//! capabilities arrive as structured upstream errors. Audit is wrapped at every
//! capability boundary through the shared `wae.audit/v0` facility.
//!
//! The skeleton round registers the full capability table. `acme-plan` is the
//! local-only planning capability, while `acme-issue` drives the real issuance
//! state machine over the product-owned HTTPS transport. Every other domain
//! command resolves to `not_implemented` with a stable code.

#![deny(missing_docs)]

use std::{cell::RefCell, env, path::PathBuf, time::Duration};

use boost_net::http::Url;
use open_ssl_core::{
    CapabilityState, Error as CoreError, ErrorCode,
    audit::capability_ids,
    config::{IssueConfig, ResolvedTarget},
    dns::{
        MANUAL_PROVIDER,
        cloudflare::{Cloudflare, DEFAULT_API_BASE, PROVIDER_ID as CLOUDFLARE_PROVIDER, Zone},
        credentials::{ProjectRoot, ProjectSecrets},
    },
    flow::{self, FlowOptions, FlowOutcome},
    platform::{CapabilityItem, capabilities as core_capabilities, platform as core_platform},
    state::{DirectoryKind, IssuePlan, plan_issue},
    tls::HttpsTransport,
};
use serde::Serialize;
use serde_json::{Value, json};
use wae::{
    CallContext, Error, JsValue, Result, function, optional_string_prop, register_module,
    webview::{IpcHandler, IpcOutcome, OpenOptions, WebViewError, open},
};

mod audit;

use audit::Summary;
use wae::audit::Mode;

const APP_TITLE: &str = "OpenSSL";
const GUI_DIR_ENV: &str = "OPEN_SSL_GUI";

thread_local! {
    static GUI: RefCell<Option<wae::webview::WebViewHost>> = const { RefCell::new(None) };
}

struct HostIpc;

impl IpcHandler for HostIpc {
    fn on_ipc(&mut self, message: &str) -> IpcOutcome {
        let Ok(request) = serde_json::from_str::<Value>(message)
        else {
            return IpcOutcome::ReplyToPage(r#"{"ok":false,"error":"invalid json"}"#.to_string());
        };
        let kind = request.get("type").and_then(Value::as_str).unwrap_or_default();
        match kind {
            "close" => IpcOutcome::CloseWindow,
            "capabilities" => match audit::run(capability_ids::CAPABILITIES, Mode::Execute, Value::Null, || {
                Ok((capability_report(), Summary::new(1, "capabilities")))
            }) {
                Ok(report) => IpcOutcome::ReplyToPage(reply(json!({ "ok": true, "data": report }))),
                Err(error) => IpcOutcome::ReplyToPage(reply(json!({ "ok": false, "error": error_payload(&error) }))),
            },
            other => IpcOutcome::ReplyToPage(reply(json!({ "ok": false, "error": format!("unknown message: {other}") }))),
        }
    }
}

fn reply(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| r#"{"ok":false,"error":"serialization failed"}"#.to_string())
}

/// The structured error shape shared by the native boundary and the CLI.
fn error_payload(error: &CoreError) -> Value {
    let platform = core_platform();
    json!({
        "code": error.code().as_str(),
        "capability": error.capability(),
        "platform": format!("{}-{}", platform.os, platform.arch),
        "message": error.message(),
    })
}

fn core_error(error: CoreError) -> Error {
    let text = match serde_json::to_string(&error_payload(&error)) {
        Ok(json) => format!("wae.error:{json}"),
        Err(_) => "wae.error:{\"code\":\"internal_error\",\"message\":\"error payload serialization failed\"}".to_string(),
    };
    // Capability errors are refusals, so the audit record uses `rejected` with the
    // capability state code instead of a generic execution failure.
    if audit::is_refusal(error.code()) { Error::new(text).refused(error.code().as_str()) } else { Error::new(text) }
}

/// Upstream host failure codes that mean a required GUI dependency is missing.
const GUI_DEPENDENCY_CODES: &[&str] = &["webview2_runtime_missing", "webkit_dependency_missing", "webkit_symbol_missing", "gtk_init_failed"];

fn webview_error(error: WebViewError) -> CoreError {
    match &error {
        WebViewError::Unsupported { capability, .. } => CoreError::unavailable(
            CapabilityState::UnsupportedPlatform,
            capability_ids::GUI,
            format!("upstream webview capability {capability:?} is unavailable on this target"),
        ),
        WebViewError::Host(failure) if GUI_DEPENDENCY_CODES.contains(&failure.code) => {
            CoreError::unavailable(CapabilityState::DependencyBlocked, capability_ids::GUI, error.to_string())
        }
        _ => CoreError::new(ErrorCode::Internal, error.to_string()),
    }
}

/// Capability report with the upstream facade row the domain cannot know about.
///
/// The `wae` facade only compiles on targets that carry a WebView backend, so `gui`
/// exists wherever this crate builds. Missing runtime libraries still surface from
/// `gui-open` as `dependency_blocked`, because the Linux backend resolves GTK at
/// runtime rather than at build time.
fn capability_report() -> open_ssl_core::platform::CapabilitiesReport {
    let mut report = core_capabilities();
    report.items.push(CapabilityItem {
        id: capability_ids::GUI,
        state: None,
        code: None,
        reason: "available",
        detail: "Host the WebView GUI over the same native capability boundary.",
    });
    let note = "`gui` covers `openGui`, `pumpEvents`, `closeGui` and `isGuiOpen`, missing runtime dependencies surface as `dependency_blocked` from `gui-open`";
    report.notes.push(note);
    report
}

/// Resolve a domain capability to its structured refusal.
///
/// Available capabilities keep dedicated exports, unknown ids are caller errors,
/// and the remaining registered domain capabilities are still `not_implemented`.
fn invoke_error(capability: &str) -> CoreError {
    let report = core_capabilities();
    let Some(item) = report.get(capability)
    else {
        return CoreError::new(ErrorCode::InvalidArgument, format!("unknown capability `{capability}`"));
    };
    if item.is_available() {
        return CoreError::new(ErrorCode::InvalidArgument, format!("`{capability}` has a dedicated export, use it instead of `invoke`"));
    }
    CoreError::unavailable(item.state.unwrap_or(CapabilityState::NotImplemented), item.id, item.reason)
}

fn json_to_js(env: wae::Env, value: Value) -> Result<JsValue> {
    match value {
        Value::Null => env.null(),
        Value::Bool(value) => env.boolean(value),
        Value::Number(number) => match number.as_i64() {
            Some(value) => env.int64(value),
            None => env.double(number.as_f64().unwrap_or(0.0)),
        },
        Value::String(text) => env.string(&text),
        Value::Array(items) => {
            let array = env.array_with_length(items.len())?;
            for (index, item) in items.into_iter().enumerate() {
                array.set_element(index as u32, json_to_js(env, item)?)?;
            }
            Ok(array)
        }
        Value::Object(map) => {
            let object = env.object()?;
            for (key, item) in map {
                object.set_named(&key, json_to_js(env, item)?)?;
            }
            Ok(object)
        }
    }
}

fn value_to_js<T: serde::Serialize>(ctx: &CallContext, value: &T) -> Result<JsValue> {
    let json = serde_json::to_value(value).map_err(|error| Error::new(format!("serialize failed: {error}")))?;
    json_to_js(ctx.env(), json)
}

fn object_arg(ctx: &CallContext) -> Result<Option<JsValue>> {
    let Some(arg) = ctx.args().first().copied()
    else {
        return Ok(None);
    };
    if arg.is_undefined()? {
        return Ok(None);
    }
    Ok(Some(arg))
}

fn resolve_gui_dir(requested: Option<String>) -> Result<String> {
    if let Some(dir) = requested
        && !dir.trim().is_empty()
    {
        return Ok(dir);
    }
    if let Ok(dir) = env::var(GUI_DIR_ENV)
        && !dir.trim().is_empty()
    {
        return Ok(dir);
    }
    let candidates = [PathBuf::from("projects/open-ssl.ts/packages/open-ssl/dist/gui"), PathBuf::from("dist/gui"), PathBuf::from("gui")];
    for candidate in candidates {
        if candidate.join("index.html").is_file() {
            return Ok(candidate.display().to_string());
        }
    }
    Err(Error::new("gui content dir not found: pass `contentDir` or build `projects/open-ssl.ts/packages/open-ssl/dist/gui`"))
}

fn actor_kind(value: Option<&str>) -> wae::audit::ActorKind {
    match value {
        Some(value) if value.eq_ignore_ascii_case("agent") => wae::audit::ActorKind::Agent,
        _ => wae::audit::ActorKind::User,
    }
}

fn query_from_arg(arg: Option<JsValue>) -> Result<wae::audit::Query> {
    let mut query = wae::audit::Query::default();
    let Some(arg) = arg
    else {
        return Ok(query);
    };
    query.actor_kind = optional_string_prop(arg, "kind")?.map(|value| actor_kind(Some(value.as_str())));
    query.actor_id = optional_string_prop(arg, "id")?;
    query.capability = optional_string_prop(arg, "capability")?;
    query.from_ms = optional_i64(arg, "fromMs")?.map(|value| value.max(0) as u64);
    query.to_ms = optional_i64(arg, "toMs")?.map(|value| value.max(0) as u64);
    query.limit = optional_i64(arg, "limit")?.map(|value| value.max(0) as usize);
    Ok(query)
}

fn optional_i64(obj: JsValue, name: &str) -> Result<Option<i64>> {
    let value = obj.get_named(name)?;
    if value.is_undefined()? {
        return Ok(None);
    }
    Ok(Some(value.as_i64()?))
}

#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::VERSION, Mode::DryRun, Value::Null, || {
        Ok((env!("CARGO_PKG_VERSION").to_string(), Summary::new(0, "version")))
    });
    match result {
        Ok(version) => ctx.env().string(&version),
        Err(error) => Err(core_error(error)),
    }
}

#[function]
fn capabilities(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::CAPABILITIES, Mode::DryRun, Value::Null, || {
        let report = capability_report();
        let summary = Summary::new(report.items.len() as u64, "capabilities");
        Ok((report, summary))
    });
    match result {
        Ok(report) => value_to_js(&ctx, &report),
        Err(error) => Err(core_error(error)),
    }
}

/// Resolve one domain capability. The skeleton round always refuses with the
/// capability's stable unavailable code.
#[function]
fn invoke(ctx: CallContext) -> Result<JsValue> {
    let capability = ctx.args().first().copied().ok_or_else(|| Error::new("invoke requires a capability id"))?.as_string()?;
    let refusal = invoke_error(&capability);
    let result = audit::run(&capability, Mode::Execute, json!({ "capability": &capability }), move || Err(refusal));
    match result {
        Ok(()) => Err(Error::new("invoke must not resolve in the skeleton round")),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    let arg = object_arg(&ctx)?;
    let content_dir = resolve_gui_dir(arg.and_then(|obj| optional_string_prop(obj, "contentDir").ok().flatten()))?;
    let title = arg.and_then(|obj| optional_string_prop(obj, "title").ok().flatten()).unwrap_or_else(|| APP_TITLE.to_string());
    let params = json!({ "contentDir": &content_dir, "title": &title });

    let result = audit::run(capability_ids::GUI, Mode::Execute, params, || {
        let options = OpenOptions::from_content_dir(&content_dir, &title);
        let host = open(options, Box::new(HostIpc)).map_err(webview_error)?;
        let backend = host.backend_name().to_string();
        GUI.with(|slot| {
            *slot.borrow_mut() = Some(host);
        });
        Ok((backend, Summary::new(1, "gui window opened")))
    });
    match result {
        Ok(backend) => {
            let object = ctx.env().object()?;
            object.set_named("backend", ctx.env().string(&backend)?)?;
            Ok(object)
        }
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::GUI, Mode::Execute, Value::Null, || {
        let alive = GUI.with(|slot| slot.borrow_mut().as_mut().map(|host| host.pump()).unwrap_or(false));
        Ok((alive, Summary::new(1, "gui event pump")))
    });
    match result {
        Ok(alive) => ctx.env().boolean(alive),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::GUI, Mode::Execute, Value::Null, || {
        let closed = GUI.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.as_mut() {
                Some(host) => host.close().is_ok(),
                None => false,
            }
        });
        if closed {
            GUI.with(|slot| {
                slot.borrow_mut().take();
            });
        }
        Ok((closed, Summary::new(1, "gui window close")))
    });
    match result {
        Ok(closed) => ctx.env().boolean(closed),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    let result = audit::run(capability_ids::GUI, Mode::DryRun, Value::Null, || {
        let alive = GUI.with(|slot| slot.borrow().as_ref().map(|host| host.is_alive()).unwrap_or(false));
        Ok((alive, Summary::new(1, "gui status")))
    });
    match result {
        Ok(alive) => ctx.env().boolean(alive),
        Err(error) => Err(core_error(error)),
    }
}

#[function(js_name = "configureAudit")]
fn configure_audit(ctx: CallContext) -> Result<JsValue> {
    let arg = object_arg(&ctx)?;
    let actor = wae::audit::Actor {
        kind: actor_kind(arg.and_then(|obj| optional_string_prop(obj, "actorKind").ok().flatten()).as_deref()),
        id: arg.and_then(|obj| optional_string_prop(obj, "actorId").ok().flatten()).unwrap_or_else(|| "unknown".to_string()),
        source: arg.and_then(|obj| optional_string_prop(obj, "actorSource").ok().flatten()).unwrap_or_else(|| "local".to_string()),
    };
    let session = arg.and_then(|obj| optional_string_prop(obj, "session").ok().flatten());
    let host = arg.and_then(|obj| optional_string_prop(obj, "host").ok().flatten());
    audit::configure(actor, session, host);
    let object = ctx.env().object()?;
    object.set_named("ok", ctx.env().boolean(true)?)?;
    Ok(object)
}

#[function(js_name = "auditQuery")]
fn audit_query(ctx: CallContext) -> Result<JsValue> {
    let filter = query_from_arg(ctx.args().first().copied())?;
    let params = json!({ "capability": filter.capability, "limit": filter.limit });
    let result = audit::run(capability_ids::AUDIT_QUERY, Mode::DryRun, params, || {
        let entries = audit::query(&filter).map_err(|error| CoreError::new(ErrorCode::Internal, error.to_string()))?;
        let summary = Summary::new(entries.len() as u64, "audit query");
        Ok((entries, summary))
    });
    match result {
        Ok(entries) => {
            let json = serde_json::to_string(&entries).map_err(|error| Error::new(error.to_string()))?;
            ctx.env().string(&json)
        }
        Err(error) => Err(core_error(error)),
    }
}

/// Decoded options shared by `acmePlan` and `acmeIssue`.
///
/// `kind` and `dnsProvider` may be omitted: the project's `open-ssl.json`
/// supplies them and the final defaults are `staging` and the `manual`
/// provider. A flag always wins over the configuration, so ordinary
/// users only ever type the domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueArguments {
    /// Project root that owns `.secrets/open-ssl.json`. `None` uses the process working directory.
    pub project_root: Option<PathBuf>,
    /// ACME directory the request targets. `None` defers to the configuration.
    pub kind: Option<DirectoryKind>,
    /// DNS provider id. `None` defers to the configuration, then to `manual`.
    pub dns_provider: Option<String>,
    /// Identifiers requested from the CA.
    pub identifiers: Vec<String>,
    /// Cloudflare zone id, when the caller manages the zone by id.
    pub dns_zone_id: Option<String>,
    /// Cloudflare zone name, when the caller manages the zone by name.
    pub dns_zone_name: Option<String>,
    /// Account contacts, for example `mailto:ops@example.com`.
    pub contact: Vec<String>,
    /// With the `manual` provider: the action id returned by a prepare run,
    /// resuming that order after the operator placed the records. `None`
    /// prepares a new action instead.
    pub action: Option<String>,
}

/// Report returned by `acmeIssue`.
///
/// A dry run carries the plan, a real run carries the issuance report with the
/// delivered generation, and a manual prepare run carries the typed
/// `actionRequired` descriptor instead of a report. Failure is a structured
/// error, never a silent `blocked`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueOutcome {
    /// Whether the call ran as a local-only plan.
    pub dry_run: bool,
    /// Plan produced by a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<IssuePlan>,
    /// Report produced by a real run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<flow::IssueReport>,
    /// Descriptor produced by a manual prepare run, to be resumed with `action`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_required: Option<flow::ActionRequired>,
}

/// Merge flags, the project configuration, and the defaults into one target.
///
/// Precedence is fixed: flag > `open-ssl.json` > default (`staging`,
/// `manual`). A present but malformed configuration file is an explicit
/// failure; it never degrades into "no configuration".
fn resolve_target(arguments: &IssueArguments) -> open_ssl_core::Result<(ProjectRoot, ResolvedTarget)> {
    let project = resolve_project(arguments)?;
    let config = IssueConfig::load(&project)?;
    let kind = arguments.kind.or(config.as_ref().and_then(|entry| entry.kind)).unwrap_or(DirectoryKind::Staging);
    let dns_provider = arguments
        .dns_provider
        .clone()
        .or_else(|| config.as_ref().and_then(|entry| entry.dns_provider.clone()))
        .unwrap_or_else(|| MANUAL_PROVIDER.to_owned());
    let mut zone_id = arguments.dns_zone_id.clone();
    let mut zone_name = arguments.dns_zone_name.clone();
    if zone_id.is_none() && zone_name.is_none() {
        if let Some(zone) = config.as_ref().and_then(|entry| entry.zone.clone()) {
            zone_id = zone.id;
            zone_name = zone.name;
        }
    }
    let contact = if arguments.contact.is_empty() { config.map(|entry| entry.contact).unwrap_or_default() } else { arguments.contact.clone() };
    Ok((project, ResolvedTarget { kind, dns_provider, zone_id, zone_name, contact }))
}

/// Run the local-only plan behind `acmePlan`.
///
/// Only project state and the availability of the provider token are read. It
/// never returns a token, writes a file, or touches DNS.
pub fn run_acme_plan(arguments: &IssueArguments) -> open_ssl_core::Result<IssuePlan> {
    let (project, target) = resolve_target(arguments)?;
    plan_issue(&project, target.kind, &target.dns_provider, &arguments.identifiers)
}

/// Run `acmeIssue`.
///
/// A dry run is exactly [`run_acme_plan`]: no lock, no state, no DNS, no key. A
/// real drive runs the full issuance state machine over the product-owned HTTPS
/// transport and the configured DNS provider. The project lock covers the whole
/// flow, and any failure leaves a structured error with a non-zero exit code at
/// the CLI boundary instead of a silent `blocked` result.
pub fn run_acme_issue(arguments: &IssueArguments, dry_run: bool) -> open_ssl_core::Result<IssueOutcome> {
    let (project, target) = resolve_target(arguments)?;
    issue_with(&project, arguments, &target, dry_run)
}

fn issue_with(
    project: &ProjectRoot,
    arguments: &IssueArguments,
    target: &ResolvedTarget,
    dry_run: bool,
) -> open_ssl_core::Result<IssueOutcome> {
    if dry_run {
        let plan = plan_issue(project, target.kind, &target.dns_provider, &arguments.identifiers)?;
        return Ok(IssueOutcome { dry_run: true, plan: Some(plan), report: None, action_required: None });
    }
    let options = FlowOptions {
        kind: target.kind,
        directory_url: flow::directory_url(target.kind),
        dns_provider: &target.dns_provider,
        identifiers: &arguments.identifiers,
        contact: &target.contact,
        poll_attempts: 40,
        poll_delay: Duration::from_secs(3),
    };
    let transport = HttpsTransport::new();
    let outcome = match target.dns_provider.as_str() {
        CLOUDFLARE_PROVIDER => {
            let zone = resolve_zone(target)?;
            let secrets = ProjectSecrets::load(project)?;
            let token = secrets.dns_token(CLOUDFLARE_PROVIDER)?;
            let api_base = Url::parse(DEFAULT_API_BASE)
                .map_err(|error| CoreError::new(ErrorCode::Internal, format!("Cloudflare API base is invalid: {error}")))?;
            let mut dns = Cloudflare::with_zone(transport.clone(), api_base, token, zone);
            // API providers place records themselves; there is no waiting stage,
            // so an action id can never apply to them.
            FlowOutcome::Report(flow::issue_api(project, &options, transport, &mut dns)?)
        }
        MANUAL_PROVIDER => {
            // 人工路径不经过任何 provider：第一次运行 prepare 落盘指引并返回
            // actionRequired，操作者放好记录后第二次带 `--action <actionId>` 续跑，
            // 由 CA 完成真正的 dns-01 校验。native 层不做终端交互。
            flow::issue_manual(project, &options, transport, arguments.action.as_deref())?
        }
        other => {
            return Err(invalid_argument(format!(
                "`acme-issue` can drive the `{CLOUDFLARE_PROVIDER}` and `{MANUAL_PROVIDER}` providers only, not `{other}`"
            )));
        }
    };
    match outcome {
        FlowOutcome::Report(report) => Ok(IssueOutcome { dry_run: false, plan: None, report: Some(report), action_required: None }),
        FlowOutcome::ActionRequired(action) => Ok(IssueOutcome { dry_run: false, plan: None, report: None, action_required: Some(action) }),
    }
}

/// The zone must be configured (in `open-ssl.json`) or passed explicitly; the
/// adapter never guesses it from the challenge name. Exactly one of id and
/// name may be present.
fn resolve_zone(target: &ResolvedTarget) -> open_ssl_core::Result<Zone> {
    match (target.zone_id.as_deref(), target.zone_name.as_deref()) {
        (Some(id), None) => Zone::id(id),
        (None, Some(name)) => Zone::name(name),
        (Some(_), Some(_)) => Err(invalid_argument("the `zone` must give exactly one of `id` and `name`")),
        (None, None) => Err(invalid_argument(
            "the cloudflare provider needs a zone: set `zone.name` or `zone.id` in `open-ssl.json`, or pass `--dns-zone-name` / `--dns-zone-id`",
        )),
    }
}

fn resolve_project(arguments: &IssueArguments) -> open_ssl_core::Result<ProjectRoot> {
    match &arguments.project_root {
        Some(path) => ProjectRoot::new(path),
        None => ProjectRoot::from_current_dir(),
    }
}

fn invalid_argument(message: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::InvalidArgument, message)
}

fn napi_error(error: Error) -> CoreError {
    CoreError::new(ErrorCode::Internal, error.to_string())
}

fn issue_object(arg: Option<JsValue>, capability: &str) -> std::result::Result<JsValue, CoreError> {
    let object = arg.ok_or_else(|| invalid_argument(format!("`{capability}` requires an options object")))?;
    if object.type_of().map_err(napi_error)? != wae::sys::napi_object {
        return Err(invalid_argument(format!("`{capability}` options must be an object")));
    }
    Ok(object)
}

fn issue_arguments(object: JsValue) -> std::result::Result<IssueArguments, CoreError> {
    let project_root = optional_project_root(object)?;
    // `kind` and `dnsProvider` may be omitted; the project configuration and
    // then the defaults supply them.
    let kind = optional_string_prop(object, "kind").map_err(napi_error)?.as_deref().map(directory_kind).transpose()?;
    let dns_provider = optional_string_prop(object, "dnsProvider").map_err(napi_error)?;
    let identifiers = string_array(object, "identifiers")?;
    let dns_zone_id = optional_string_prop(object, "dnsZoneId").map_err(napi_error)?;
    let dns_zone_name = optional_string_prop(object, "dnsZoneName").map_err(napi_error)?;
    let contact = optional_string_array(object, "contact")?;
    let action = optional_string_prop(object, "action").map_err(napi_error)?;
    Ok(IssueArguments { project_root, kind, dns_provider, identifiers, dns_zone_id, dns_zone_name, contact, action })
}

/// `contact` may be omitted; a present value must be an array of strings.
fn optional_string_array(object: JsValue, name: &str) -> std::result::Result<Vec<String>, CoreError> {
    let value = object.get_named(name).map_err(napi_error)?;
    if value.is_undefined().map_err(napi_error)? {
        return Ok(Vec::new());
    }
    string_array(object, name)
}

/// `projectRoot` may be omitted, but a present value must be a usable string:
/// a malformed value never falls back to the working directory silently.
fn optional_project_root(object: JsValue) -> std::result::Result<Option<PathBuf>, CoreError> {
    let value = object.get_named("projectRoot").map_err(napi_error)?;
    if value.is_undefined().map_err(napi_error)? {
        return Ok(None);
    }
    if value.type_of().map_err(napi_error)? != wae::sys::napi_string {
        return Err(invalid_argument("`projectRoot` must be a string"));
    }
    let path = value.as_string().map_err(napi_error)?;
    if path.trim().is_empty() {
        return Err(invalid_argument("`projectRoot` must not be empty"));
    }
    Ok(Some(PathBuf::from(path)))
}

fn directory_kind(value: &str) -> std::result::Result<DirectoryKind, CoreError> {
    match value.trim() {
        "staging" => Ok(DirectoryKind::Staging),
        "production" => Ok(DirectoryKind::Production),
        other => Err(invalid_argument(format!("`kind` must be `staging` or `production`, not `{other}`"))),
    }
}

#[allow(dead_code)]
fn required_string(object: JsValue, name: &str) -> std::result::Result<String, CoreError> {
    let value = object.get_named(name).map_err(napi_error)?;
    if value.type_of().map_err(napi_error)? != wae::sys::napi_string {
        return Err(invalid_argument(format!("`{name}` must be a string")));
    }
    let text = value.as_string().map_err(napi_error)?;
    if text.trim().is_empty() {
        return Err(invalid_argument(format!("`{name}` must not be empty")));
    }
    Ok(text)
}

fn required_bool(object: JsValue, name: &str) -> std::result::Result<bool, CoreError> {
    let value = object.get_named(name).map_err(napi_error)?;
    if value.type_of().map_err(napi_error)? != wae::sys::napi_boolean {
        return Err(invalid_argument(format!("`{name}` must be a boolean")));
    }
    value.as_bool().map_err(napi_error)
}

/// Read a string array through property lookup, because the N-API value helpers
/// expose element writes but no element reads.
fn string_array(object: JsValue, name: &str) -> std::result::Result<Vec<String>, CoreError> {
    let not_an_array = || invalid_argument(format!("`{name}` must be an array of strings"));
    let value = object.get_named(name).map_err(napi_error)?;
    if value.type_of().map_err(napi_error)? != wae::sys::napi_object {
        return Err(not_an_array());
    }
    let length = value.get_named("length").and_then(JsValue::as_i64).map_err(|_| not_an_array())?;
    let mut items = Vec::new();
    for index in 0..length {
        let item = value.get_named(&index.to_string()).map_err(napi_error)?;
        if item.type_of().map_err(napi_error)? != wae::sys::napi_string {
            return Err(not_an_array());
        }
        items.push(item.as_string().map_err(napi_error)?);
    }
    Ok(items)
}

/// Audit parameters describe the effective target, not the raw flags: they
/// carry the merged kind, provider, zone, and contacts.
fn issue_params(target: &ResolvedTarget, identifiers: &[String], dry_run: Option<bool>) -> Value {
    let mut params = json!({
        "kind": target.kind.as_str(),
        "dnsProvider": &target.dns_provider,
        "identifiers": identifiers,
        "contact": &target.contact,
    });
    if let Some(object) = params.as_object_mut() {
        if let Some(id) = &target.zone_id {
            object.insert("dnsZoneId".to_owned(), Value::String(id.clone()));
        }
        if let Some(name) = &target.zone_name {
            object.insert("dnsZoneName".to_owned(), Value::String(name.clone()));
        }
    }
    if let (Some(dry_run), Some(object)) = (dry_run, params.as_object_mut()) {
        object.insert("dryRun".to_owned(), Value::Bool(dry_run));
    }
    params
}

/// Target summary: identifiers, directory, and provider only. No token and no path.
fn plan_summary(target: &ResolvedTarget, identifiers: &[String]) -> String {
    format!("{} identifier(s) against the {} directory via {}", identifiers.len(), target.kind.as_str(), target.dns_provider)
}

fn issue_summary(target: &ResolvedTarget, identifiers: &[String], outcome: &IssueOutcome) -> String {
    let base = plan_summary(target, identifiers);
    match (&outcome.report, &outcome.action_required) {
        (Some(report), _) => format!("{base}: delivered generation {}", report.generation),
        (None, Some(action)) => format!("{base}: action {} awaiting manual DNS", action.action_id),
        (None, None) => format!("{base}: dry run"),
    }
}

#[function(js_name = "acmePlan")]
fn acme_plan(ctx: CallContext) -> Result<JsValue> {
    let object = issue_object(object_arg(&ctx)?, "acmePlan").map_err(core_error)?;
    let arguments = issue_arguments(object).map_err(core_error)?;
    let (project, target) = resolve_target(&arguments).map_err(core_error)?;
    let params = issue_params(&target, &arguments.identifiers, None);
    let plan = audit::run(capability_ids::ACME_PLAN, Mode::DryRun, params, || {
        let plan = plan_issue(&project, target.kind, &target.dns_provider, &arguments.identifiers)?;
        Ok((plan, Summary::new(arguments.identifiers.len() as u64, plan_summary(&target, &arguments.identifiers))))
    })
    .map_err(core_error)?;
    value_to_js(&ctx, &plan)
}

#[function(js_name = "acmeIssue")]
fn acme_issue(ctx: CallContext) -> Result<JsValue> {
    let object = issue_object(object_arg(&ctx)?, "acmeIssue").map_err(core_error)?;
    let arguments = issue_arguments(object).map_err(core_error)?;
    let dry_run = required_bool(object, "dryRun").map_err(core_error)?;
    let (project, target) = resolve_target(&arguments).map_err(core_error)?;
    let mode = if dry_run { Mode::DryRun } else { Mode::Execute };
    let params = issue_params(&target, &arguments.identifiers, Some(dry_run));
    let outcome = audit::run(capability_ids::ACME_ISSUE, mode, params, || {
        let outcome = issue_with(&project, &arguments, &target, dry_run)?;
        let summary = Summary::new(arguments.identifiers.len() as u64, issue_summary(&target, &arguments.identifiers, &outcome));
        Ok((outcome, summary))
    })
    .map_err(core_error)?;
    value_to_js(&ctx, &outcome)
}

register_module![
    version,
    capabilities,
    invoke,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open,
    configure_audit,
    audit_query,
    acme_plan,
    acme_issue
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_gui_runtime_dependencies_map_to_dependency_blocked() {
        for code in GUI_DEPENDENCY_CODES {
            let mapped = webview_error(WebViewError::host(code, "load_libraries", "missing dependency"));
            assert_eq!(mapped.code(), ErrorCode::DependencyBlocked);
            assert_eq!(mapped.capability(), Some(capability_ids::GUI));
        }
    }

    #[test]
    fn other_host_failures_stay_plain_domain_errors() {
        let mapped = webview_error(WebViewError::host("create_window_failed", "create_window", "boom"));
        assert_eq!(mapped.code(), ErrorCode::Internal);
    }

    #[test]
    fn capability_report_lists_gui_and_reasons_for_unavailable_rows() {
        let report = capability_report();
        let gui = report.get(capability_ids::GUI).expect("gui row");
        assert!(gui.is_available());
        assert!(report.notes.iter().any(|note| note.contains("dependency_blocked")));
        for id in [capability_ids::HOST_INSTALL, capability_ids::HOST_UNINSTALL, capability_ids::REMOTE_AGENT] {
            let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
            assert!(!item.is_available());
            assert!(!item.reason.is_empty());
            assert!(!item.detail.is_empty());
        }
    }

    #[test]
    fn invoke_refuses_every_domain_capability_with_its_stable_code() {
        for id in [
            capability_ids::CERTIFICATE_INSPECT,
            capability_ids::CERTIFICATE_ISSUE,
            capability_ids::CSR_CREATE,
            capability_ids::PRIVATE_KEY_STORE,
            capability_ids::REMOTE_AGENT,
        ] {
            let error = invoke_error(id);
            assert_eq!(error.code(), ErrorCode::NotImplemented);
            assert_eq!(error.capability(), Some(id));
        }
    }

    #[test]
    fn invoke_rejects_unknown_and_meta_capabilities_as_usage_errors() {
        assert_eq!(invoke_error("not-a-capability").code(), ErrorCode::InvalidArgument);
        assert_eq!(invoke_error(capability_ids::CAPABILITIES).code(), ErrorCode::InvalidArgument);
        assert!(invoke_error(capability_ids::CAPABILITIES).capability().is_none());
    }
}
