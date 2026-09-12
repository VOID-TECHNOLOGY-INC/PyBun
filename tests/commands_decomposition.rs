use std::fs;
use std::path::PathBuf;

#[test]
fn commands_mod_remains_a_thin_routing_and_rendering_shell() {
    let commands_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/commands");
    let module = fs::read_to_string(commands_dir.join("mod.rs")).expect("read commands/mod.rs");
    let dispatch =
        fs::read_to_string(commands_dir.join("dispatch.rs")).expect("read commands/dispatch.rs");

    assert!(
        module.lines().count() <= 600,
        "commands/mod.rs must stay at or below the Issue #346 target"
    );
    assert!(module.contains("pub use dispatch::execute;"));

    for group in [
        "package",
        "execution",
        "testing",
        "tooling",
        "maintenance",
        "python",
        "project",
    ] {
        assert!(
            dispatch.contains(&format!("async fn dispatch_{group}(")),
            "missing focused {group} dispatcher"
        );
    }
}
