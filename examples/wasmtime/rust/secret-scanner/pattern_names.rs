// Shared by BOTH hosts in this directory: main.rs (module) and
// main_component.rs (component).
//
// A native host does not get `pattern_name` for free. `emit_name_map: true` in
// the config generates that helper into a STUB, and a stub is for a guest
// compiled to WASM — this binary is native and has no stub in either format. So
// the table lives here, and `include!` keeps one copy of it.
//
// The order is the order of `regexps:` in the config, because a pattern id IS
// that index.
const PATTERN_NAMES: &[&str] = &[
    "aws_key",
    "aws_secret",
    "github_pat",
    "github_oauth",
    "github_app",
    "jwt",
    "slack_token",
    "stripe_live",
    "stripe_test",
    "google_api",
];

fn pattern_name(id: i32) -> &'static str {
    PATTERN_NAMES.get(id as usize).copied().unwrap_or("unknown")
}
