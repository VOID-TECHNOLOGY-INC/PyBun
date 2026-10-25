use super::RenderDetail;
use crate::cli::{DriftArgs, InitArgs, InitTemplate};
use crate::schema::{Diagnostic, DiagnosticLevel, EventCollector, EventType};
use color_eyre::eyre::{Result, eyre};
use dialoguer::{Input, theme::ColorfulTheme};
use serde_json::json;
use std::fs;
use std::io::IsTerminal;

// ---------------------------------------------------------------------------
// pybun init
// ---------------------------------------------------------------------------

pub(super) fn sanitize_project_name(name: &str) -> String {
    let sanitized: String = name
        .replace([' ', '-'], "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_lowercase();

    if sanitized.chars().next().is_some_and(|c| c.is_numeric()) {
        format!("_{}", sanitized)
    } else {
        sanitized
    }
}

fn init_metadata(
    name: &str,
    description: Option<&str>,
    python: Option<&str>,
    author: Option<&str>,
) -> Result<String> {
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !name.ends_with(|c: char| c.is_ascii_alphanumeric())
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        return Err(eyre!(
            "Invalid project name: use ASCII letters, digits, dots, underscores or hyphens, starting and ending with a letter or digit"
        ));
    }
    let mut project = json!({"name": name, "version": "0.1.0", "dependencies": []});
    if let Some(value) = description {
        project["description"] = json!(value);
    }
    if let Some(value) = python {
        crate::pep440::Pep440Version::parse(value)
            .filter(|version| version.local.is_empty())
            .ok_or_else(|| eyre!("Invalid Python version: expected a version such as 3.12"))?;
        project["requires-python"] = json!(format!(">={}", value.trim()));
    }
    if let Some(value) = author {
        project["authors"] = json!([{"name": value}]);
    }
    Ok(toml::to_string_pretty(&json!({
        "project": project,
        "build-system": {"requires": ["hatchling"], "build-backend": "hatchling.build"},
    }))?)
}

pub(super) fn init_project(
    args: &InitArgs,
    collector: &mut EventCollector,
) -> Result<RenderDetail> {
    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let pyproject_path = cwd.join("pyproject.toml");
    let gitignore_path = cwd.join(".gitignore");
    let readme_path = cwd.join("README.md");

    let default_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .map(|name| sanitize_project_name(name).trim_matches('_').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "my_project".to_string());

    // Resolve arguments (interactive or defaults)
    let (name, description, python, author, template) = if args.yes {
        (
            args.name.clone().unwrap_or(default_name),
            args.description.clone(),
            args.python.clone().or_else(|| Some("3.12".to_string())), // Default to 3.12 if not specified
            args.author.clone(),
            args.template,
        )
    } else {
        // Interactive mode — requires a terminal
        if !std::io::stdin().is_terminal() {
            collector.diagnostic(Diagnostic {
                level: DiagnosticLevel::Error,
                code: Some("E_INIT_NOT_INTERACTIVE".to_string()),
                message: "Interactive prompt requires a terminal".to_string(),
                file: None,
                line: None,
                suggestion: Some(
                    "Run with --yes to accept defaults non-interactively: pybun init --yes"
                        .to_string(),
                ),
                context: None,
                exception_type: None,
                location: None,
                next_action: None,
                fix_candidates: None,
            });
            return Err(eyre!(
                "Interactive prompt requires a terminal. Run with --yes to accept defaults non-interactively: pybun init --yes"
            ));
        }

        let theme = ColorfulTheme::default();

        // Name
        let name: String = if let Some(n) = &args.name {
            n.clone()
        } else {
            Input::with_theme(&theme)
                .with_prompt("Project name")
                .default(default_name)
                .interact_text()?
        };

        // Description
        let description: Option<String> = if let Some(d) = &args.description {
            Some(d.clone())
        } else {
            let d: String = Input::with_theme(&theme)
                .with_prompt("Description")
                .allow_empty(true)
                .interact_text()?;
            if d.is_empty() { None } else { Some(d) }
        };

        // Python Version
        let python: Option<String> = if let Some(p) = &args.python {
            Some(p.clone())
        } else {
            let p: String = Input::with_theme(&theme)
                .with_prompt("Python version")
                .default("3.12".to_string())
                .interact_text()?;
            Some(p)
        };

        // Author
        let author: Option<String> = if let Some(a) = &args.author {
            Some(a.clone())
        } else {
            let a: String = Input::with_theme(&theme)
                .with_prompt("Author")
                .allow_empty(true)
                .interact_text()?;
            if a.is_empty() { None } else { Some(a) }
        };

        // Template
        let template = args.template; // Can also make this interactive later if needed

        (name, description, python, author, template)
    };

    // Check main file existence
    if pyproject_path.exists() {
        return Err(eyre!(
            "pyproject.toml already exists at {}",
            pyproject_path.display()
        ));
    }

    let pyproject = init_metadata(
        &name,
        description.as_deref(),
        python.as_deref(),
        author.as_deref(),
    )?;

    // Write pyproject.toml
    fs::write(&pyproject_path, &pyproject)
        .map_err(|e| eyre!("failed to write pyproject.toml: {}", e))?;
    let mut files_created = vec![pyproject_path.display().to_string()];
    let mut files_skipped = vec![];

    // Create .gitignore (with check)
    if !gitignore_path.exists() {
        let gitignore_content = r#"# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Virtual environments
.venv/
venv/
ENV/

# Distribution / packaging
dist/
build/
*.egg-info/

# PyBun
pybun.lockb
.pybun/

# IDE
.vscode/
.idea/
*.swp
*.swo
"#;
        fs::write(&gitignore_path, gitignore_content)
            .map_err(|e| eyre!("failed to write .gitignore: {}", e))?;
        files_created.push(gitignore_path.display().to_string());
    } else {
        files_skipped.push(gitignore_path.display().to_string());
    }

    // Create README.md (with check)
    if !readme_path.exists() {
        let readme_content = format!("# {}\n\nA Python project.\n", name);
        fs::write(&readme_path, readme_content)
            .map_err(|e| eyre!("failed to write README.md: {}", e))?;
        files_created.push(readme_path.display().to_string());
    } else {
        files_skipped.push(readme_path.display().to_string());
    }

    // Create src layout if package template
    if matches!(template, InitTemplate::Package) {
        let package_name = sanitize_project_name(&name);
        let src_dir = cwd.join("src").join(&package_name);
        fs::create_dir_all(&src_dir).map_err(|e| eyre!("failed to create src directory: {}", e))?;

        let init_path = src_dir.join("__init__.py");
        // Safe to overwrite empty init or check? Usually safe to check.
        if !init_path.exists() {
            fs::write(&init_path, "").map_err(|e| eyre!("failed to write __init__.py: {}", e))?;
            files_created.push(init_path.display().to_string());
        } else {
            files_skipped.push(init_path.display().to_string());
        }
    }

    let summary = format!(
        "Initialized project '{}' with {} files ({} skipped)",
        name,
        files_created.len(),
        files_skipped.len()
    );

    Ok(RenderDetail::with_json(
        summary,
        json!({
            "project_name": name,
            "template": format!("{:?}", template).to_lowercase(),
            "files_created": files_created,
            "files_skipped": files_skipped,
        }),
    ))
}

pub(super) fn run_drift(args: &DriftArgs, collector: &mut EventCollector) -> Result<RenderDetail> {
    use crate::drift;

    let cwd =
        std::env::current_dir().map_err(|e| eyre!("failed to get current directory: {}", e))?;
    let root = if let Some(path) = &args.path {
        if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        }
    } else {
        cwd
    };

    // Require pyproject.toml
    if !root.join("pyproject.toml").exists() {
        collector.error_with_code(
            "E_DRIFT_NO_PYPROJECT",
            format!("pyproject.toml not found in {}", root.display()),
            "Run `pybun init` to create a pyproject.toml, or specify a directory with `pybun drift --path <PATH>`.",
        );
        return Ok(RenderDetail::error(
            "pyproject.toml not found".to_string(),
            json!({
                "undeclared_imports": [],
                "unused_declarations": [],
                "analysis_notes": ["pyproject.toml not found"],
                "files_scanned": 0
            }),
        ));
    }

    collector.event(EventType::Custom);

    let result = drift::analyze(&root);

    let undeclared_count = result.undeclared_imports.len();
    let unused_count = result.unused_declarations.len();

    // Surface undeclared imports as warnings
    for u in &result.undeclared_imports {
        collector.diagnostic(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: Some("W_DRIFT_UNDECLARED_IMPORT".to_string()),
            message: format!(
                "Package '{}' is imported but not declared in pyproject.toml",
                u.package
            ),
            file: None,
            line: None,
            suggestion: Some(format!("Run `pybun add {}`", u.package)),
            context: None,
            exception_type: None,
            location: None,
            next_action: None,
            fix_candidates: None,
        });
    }

    // Surface unused declarations as warnings
    for u in &result.unused_declarations {
        collector.diagnostic(Diagnostic {
            level: DiagnosticLevel::Warning,
            code: Some("W_DRIFT_UNUSED_DECLARATION".to_string()),
            message: format!(
                "Package '{}' is declared in pyproject.toml but never imported",
                u.package
            ),
            file: None,
            line: None,
            suggestion: Some(format!("Run `pybun remove {}`", u.package)),
            context: None,
            exception_type: None,
            location: None,
            next_action: None,
            fix_candidates: None,
        });
    }

    let summary = if undeclared_count == 0 && unused_count == 0 {
        format!("No drift detected ({} files scanned)", result.files_scanned)
    } else {
        format!(
            "Drift detected: {} undeclared import(s), {} unused declaration(s) ({} files scanned)",
            undeclared_count, unused_count, result.files_scanned
        )
    };

    Ok(RenderDetail::with_json(
        summary,
        json!({
            "undeclared_imports": result.undeclared_imports,
            "unused_declarations": result.unused_declarations,
            "analysis_notes": result.analysis_notes,
            "files_scanned": result.files_scanned,
        }),
    ))
}

#[cfg(test)]
mod init_tests {
    use super::init_metadata;

    #[test]
    fn serializes_free_form_metadata() {
        let value = "quoted \"value\"\nC:\\demo 日本語";
        let encoded = init_metadata("123-demo", Some(value), Some("3.12"), Some(value)).unwrap();
        let parsed: toml::Value = toml::from_str(&encoded).unwrap();
        assert_eq!(parsed["project"]["description"].as_str(), Some(value));
        assert_eq!(
            parsed["project"]["authors"][0]["name"].as_str(),
            Some(value)
        );
        assert_eq!(
            parsed["project"]["requires-python"].as_str(),
            Some(">=3.12")
        );
    }

    #[test]
    fn validates_distribution_names_and_python_requirements() {
        for name in ["demo", "123-demo", "A.b_c-d"] {
            assert!(init_metadata(name, None, Some("3.12.0rc1"), None).is_ok());
        }
        for name in ["", "_demo", "demo-", "../demo", "bad name", "日本語"] {
            assert!(init_metadata(name, None, None, None).is_err());
        }
        for version in ["", ">=3.12", "3.12+local", "3.12\nother", "3.12\""] {
            assert!(init_metadata("demo", None, Some(version), None).is_err());
        }
    }
}
