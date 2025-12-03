use pybun::lockfile::{Lockfile, Package, PackageSource};

#[test]
fn roundtrip_preserves_data() {
    let mut lock = Lockfile::new(vec!["3.12".into()], vec!["macos-arm64".into()]);
    lock.add_package(Package {
        name: "requests".into(),
        version: "2.31.0".into(),
        source: PackageSource::Registry {
            index: "pypi".into(),
            url: "https://pypi.org/simple".into(),
        },
        wheel: "requests-2.31.0-py3-none-any.whl".into(),
        hash: "sha256:deadbeef".into(),
        dependencies: vec!["urllib3>=1.26".into(), "certifi>=2023.0".into()],
    });

    let bytes = lock.to_bytes().expect("encode");
    let decoded = Lockfile::from_bytes(&bytes).expect("decode");

    assert_eq!(decoded, lock);
}

#[test]
fn serialization_is_deterministic() {
    let mut lock_a = Lockfile::new(vec!["3.11".into()], vec!["linux-x86_64".into()]);
    for name in ["b", "a", "c"] {
        lock_a.add_package(Package {
            name: name.into(),
            version: "1.0.0".into(),
            source: PackageSource::Registry {
                index: "pypi".into(),
                url: "https://pypi.org/simple".into(),
            },
            wheel: format!("{name}-1.0.0-py3-none-any.whl"),
            hash: "sha256:abc123".into(),
            dependencies: vec![],
        });
    }

    let mut lock_b = Lockfile::new(vec!["3.11".into()], vec!["linux-x86_64".into()]);
    for name in ["c", "b", "a"] {
        lock_b.add_package(Package {
            name: name.into(),
            version: "1.0.0".into(),
            source: PackageSource::Registry {
                index: "pypi".into(),
                url: "https://pypi.org/simple".into(),
            },
            wheel: format!("{name}-1.0.0-py3-none-any.whl"),
            hash: "sha256:abc123".into(),
            dependencies: vec![],
        });
    }

    let bytes_a = lock_a.to_bytes().expect("encode a");
    let bytes_b = lock_b.to_bytes().expect("encode b");

    assert_eq!(bytes_a, bytes_b, "serialization should be deterministic");
}

#[test]
fn invalid_magic_is_rejected() {
    let lock = Lockfile::new(vec!["3.10".into()], vec!["linux-x86_64".into()]);
    let bytes = lock.to_bytes().expect("encode");
    let mut corrupted = bytes.clone();
    corrupted[0] = b'X';

    let err = Lockfile::from_bytes(&corrupted).expect_err("should reject bad magic");
    assert!(err.to_string().contains("magic"));
}
