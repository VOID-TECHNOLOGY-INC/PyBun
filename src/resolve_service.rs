//! Transport-independent dependency resolution service.
//!
//! CLI commands and MCP tools construct the same request and delegate through
//! this boundary. Index discovery and response rendering remain concerns of
//! their respective adapters.

use crate::resolver::{
    PackageIndex, Requirement, Resolution, ResolveError, ResolveOptions, resolve_with_options,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    pub requirements: Vec<Requirement>,
    pub options: ResolveOptions,
}

impl ResolveRequest {
    pub fn new(requirements: Vec<Requirement>, options: ResolveOptions) -> Self {
        Self {
            requirements,
            options,
        }
    }
}

pub async fn resolve(
    request: ResolveRequest,
    index: &impl PackageIndex,
) -> Result<Resolution, ResolveError> {
    resolve_with_options(request.requirements, index, request.options).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::InMemoryIndex;

    #[tokio::test]
    async fn delegates_request_to_resolver_core() {
        let mut index = InMemoryIndex::default();
        index.add("demo", "1.0", Vec::<String>::new());

        let resolution = resolve(
            ResolveRequest::new(vec![Requirement::exact("demo", "1.0")], Default::default()),
            &index,
        )
        .await
        .expect("request should resolve");

        assert_eq!(resolution.packages["demo"].version, "1.0");
    }

    #[tokio::test]
    async fn preserves_request_options() {
        let mut index = InMemoryIndex::default();
        index.add("demo", "2.0rc1", Vec::<String>::new());

        let resolution = resolve(
            ResolveRequest::new(
                vec![Requirement::any("demo")],
                ResolveOptions {
                    allow_prerelease: true,
                    ..Default::default()
                },
            ),
            &index,
        )
        .await
        .expect("pre-release option should reach resolver");

        assert_eq!(resolution.packages["demo"].version, "2.0rc1");
    }
}
