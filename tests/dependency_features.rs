use toml::Value;

fn dependency_features<'a>(manifest: &'a Value, section: &str, name: &str) -> Vec<&'a str> {
    manifest[section][name]["features"]
        .as_array()
        .unwrap_or_else(|| panic!("{section}.{name}.features must be an array"))
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .unwrap_or_else(|| panic!("{section}.{name} features must be strings"))
        })
        .collect()
}

#[test]
fn tokio_runtime_and_test_features_are_separated() {
    let manifest: Value =
        toml::from_str(include_str!("../Cargo.toml")).expect("Cargo.toml should parse");

    assert_eq!(
        manifest["dependencies"]["tokio"]["default-features"].as_bool(),
        Some(false),
        "production tokio dependency should opt out of implicit defaults"
    );
    let runtime_features = dependency_features(&manifest, "dependencies", "tokio");
    for feature in ["full", "macros", "net"] {
        assert!(
            !runtime_features.contains(&feature),
            "the direct production tokio dependency must not request test-only feature {feature}"
        );
    }

    assert_eq!(
        manifest["dev-dependencies"]["tokio"]["default-features"].as_bool(),
        Some(false),
        "test tokio dependency should opt out of implicit defaults"
    );
    let test_features = dependency_features(&manifest, "dev-dependencies", "tokio");
    for feature in ["macros", "net"] {
        assert!(
            test_features.contains(&feature),
            "tests directly require tokio feature {feature}"
        );
    }
}
