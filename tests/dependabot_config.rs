use std::fs;

fn dependabot_config() -> String {
    fs::read_to_string(".github/dependabot.yml")
        .expect("Dependabot config should exist at .github/dependabot.yml")
}

#[test]
fn dependabot_config_covers_project_dependency_ecosystems() {
    let config = dependabot_config();

    for ecosystem in ["cargo", "pip", "github-actions"] {
        assert!(
            config.contains(&format!("package-ecosystem: \"{ecosystem}\"")),
            "Dependabot config should include {ecosystem} updates"
        );
    }
}

#[test]
fn dependabot_config_limits_noise_and_groups_patch_updates() {
    let config = dependabot_config();

    assert!(
        config.contains("open-pull-requests-limit: 5"),
        "Dependabot should cap concurrent update PRs"
    );
    assert!(
        config.contains("interval: \"weekly\""),
        "Dependabot should run weekly"
    );
    assert!(
        config.contains("patterns:\n          - \"*\""),
        "Dependabot should group minor and patch updates"
    );
}
