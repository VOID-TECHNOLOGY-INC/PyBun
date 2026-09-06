use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

fn workflow_paths() -> Vec<PathBuf> {
    let mut paths = fs::read_dir(".github/workflows")
        .expect("workflow directory should exist")
        .map(|entry| entry.expect("workflow entry should be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn job_blocks(contents: &str) -> Vec<(&str, String)> {
    let lines = contents.lines().collect::<Vec<_>>();
    let jobs_index = lines
        .iter()
        .position(|line| *line == "jobs:")
        .expect("workflow should define jobs");
    let mut blocks = Vec::new();
    let mut index = jobs_index + 1;

    while index < lines.len() {
        let line = lines[index];
        if indentation(line) == 2 && line.trim_end().ends_with(':') && !line.trim().starts_with('#')
        {
            let name = line.trim().trim_end_matches(':');
            let start = index;
            index += 1;
            while index < lines.len() {
                let next = lines[index];
                if indentation(next) == 2
                    && next.trim_end().ends_with(':')
                    && !next.trim().starts_with('#')
                {
                    break;
                }
                index += 1;
            }
            blocks.push((name, lines[start..index].join("\n")));
        } else {
            index += 1;
        }
    }

    blocks
}

#[test]
fn third_party_actions_are_pinned_to_commit_shas() {
    let action = Regex::new(r"^uses:\s*([^\s@]+)@([^\s#]+)").unwrap();
    let sha = Regex::new(r"^[0-9a-f]{40}$").unwrap();

    for path in workflow_paths() {
        for (line_number, line) in read(&path).lines().enumerate() {
            let trimmed = line.trim();
            if let Some(captures) = action.captures(trimmed) {
                let repository = &captures[1];
                if !repository.starts_with("./") {
                    assert!(
                        sha.is_match(&captures[2]),
                        "{}:{} uses mutable action reference `{}`",
                        path.display(),
                        line_number + 1,
                        &captures[2]
                    );
                }
            }
        }
    }
}

#[test]
fn workflows_define_concurrency_and_every_job_has_a_timeout() {
    for path in workflow_paths() {
        let contents = read(&path);
        assert!(
            contents.lines().any(|line| line == "concurrency:"),
            "{} lacks top-level concurrency control",
            path.display()
        );

        for (job, block) in job_blocks(&contents) {
            assert!(
                block
                    .lines()
                    .any(|line| line.starts_with("    timeout-minutes:")),
                "{} job `{job}` lacks timeout-minutes",
                path.display()
            );
        }
    }
}

#[test]
fn permissions_are_scoped_per_job() {
    for path in workflow_paths() {
        let contents = read(&path);
        let top_level_permissions = contents
            .lines()
            .position(|line| line == "permissions:")
            .map(|start| {
                contents
                    .lines()
                    .skip(start + 1)
                    .take_while(|line| line.is_empty() || indentation(line) > 0)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        assert!(
            !top_level_permissions.contains(": write"),
            "{} grants write permissions at workflow scope",
            path.display()
        );

        for (job, block) in job_blocks(&contents) {
            assert!(
                block
                    .lines()
                    .any(|line| line.starts_with("    permissions:")),
                "{} job `{job}` lacks an explicit permissions block",
                path.display()
            );
        }
    }
}

#[test]
fn release_jobs_have_only_the_permissions_they_need() {
    let contents = read(Path::new(".github/workflows/release.yml"));
    let jobs = job_blocks(&contents);
    let block = |name| {
        jobs.iter()
            .find(|(job, _)| *job == name)
            .unwrap_or_else(|| panic!("release workflow lacks `{name}` job"))
            .1
            .as_str()
    };

    for job in ["build", "metadata"] {
        let job_block = block(job);
        assert!(
            job_block.contains("contents: read"),
            "`{job}` needs contents: read"
        );
        assert!(
            !job_block.contains("contents: write"),
            "`{job}` must not write contents"
        );
        assert!(
            !job_block.contains("pull-requests: write"),
            "`{job}` must not write pull requests"
        );
    }

    for job in ["check-size", "codesign-placeholder"] {
        assert!(
            block(job).lines().any(|line| line == "    permissions: {}"),
            "`{job}` should run without a GITHUB_TOKEN permission"
        );
    }

    assert!(block("package-managers").contains("contents: write"));
    assert!(block("package-managers").contains("pull-requests: write"));
    assert!(block("release").contains("contents: write"));
    assert!(!block("release").contains("pull-requests: write"));
}

#[test]
fn secrets_are_not_interpolated_into_run_scripts() {
    for path in workflow_paths() {
        let contents = read(&path);
        let lines = contents.lines().collect::<Vec<_>>();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            let trimmed = line.trim_start();
            if trimmed.starts_with("run:") {
                let run_indent = indentation(line);
                assert!(
                    !trimmed.contains("${{ secrets."),
                    "{}:{} interpolates a secret into run",
                    path.display(),
                    index + 1
                );
                index += 1;
                while index < lines.len()
                    && (lines[index].trim().is_empty() || indentation(lines[index]) > run_indent)
                {
                    assert!(
                        !lines[index].contains("${{ secrets."),
                        "{}:{} interpolates a secret into a run block",
                        path.display(),
                        index + 1
                    );
                    index += 1;
                }
            } else {
                index += 1;
            }
        }
    }
}

#[test]
fn build_provenance_is_attested_in_the_build_job() {
    let contents = read(Path::new(".github/workflows/release.yml"));
    let jobs = job_blocks(&contents);
    let build = jobs.iter().find(|(job, _)| *job == "build").unwrap();
    let metadata = jobs.iter().find(|(job, _)| *job == "metadata").unwrap();

    assert!(build.1.contains("actions/attest-build-provenance@"));
    assert!(!metadata.1.contains("actions/attest-build-provenance@"));
}
