//! Read-only, shared CLI/MCP affected-test selection.
use crate::proc_exec::{ProcExecOutcome, spawn_with_timeout};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const AST_SELECTION: &str = r#"
import ast, collections, json, pathlib, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    request = json.load(stream)
root = pathlib.Path(request['root'])
files, changed = request['files'], set(request['changed'])
tests = sorted(p for p in files if p.endswith('.py') and (pathlib.Path(p).name.startswith('test_') or pathlib.Path(p).name.endswith('_test.py')) and (root / p).is_file())
notes, fallback = [], False
modules = collections.defaultdict(set)
def module_name(path):
    parts = list(pathlib.PurePosixPath(path).with_suffix('').parts)
    if parts and parts[-1] == '__init__':
        parts.pop()
    return '.'.join(parts)
for path in sorted(set(files) | changed):
    if path.endswith('.py'):
        parts = module_name(path).split('.')
        # Import roots vary across src/workspace/pytest layouts. Retain every
        # directory-root candidate; ambiguity may over-select, never hide tests.
        for offset in range(len(parts)):
            modules['.'.join(parts[offset:])].add(path)
graph = collections.defaultdict(set)
def link(path, name):
    parts = name.split('.')
    for length in range(1, len(parts) + 1):
        graph[path].update(modules.get('.'.join(parts[:length]), ()))
if not changed:
    notes.append('No changed files detected')
elif any(not p.endswith('.py') or pathlib.Path(p).name == 'conftest.py' for p in changed):
    fallback = True
    notes.append('Configuration or non-Python change: conservatively selecting all tests')
else:
    for path in files:
        if not path.endswith('.py') or not (root / path).is_file():
            continue
        try:
            tree = ast.parse((root / path).read_text(encoding='utf-8'), filename=path)
        except (SyntaxError, UnicodeError, OSError):
            fallback = True
            notes.append('AST evidence unavailable: ' + path)
            continue
        for node in ast.walk(tree):
            dynamic = ((isinstance(node, ast.Import) and any(alias.name in ('importlib', 'builtins') or alias.name.startswith('importlib.') for alias in node.names))
                or (isinstance(node, ast.ImportFrom) and node.module and (node.module in ('importlib', 'builtins') or node.module.startswith('importlib.')))
                or (isinstance(node, ast.Name) and node.id in ('__import__', 'pytest_plugins'))
                or (isinstance(node, ast.Attribute) and node.attr == 'import_module')
                or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec')))
            if dynamic:
                fallback = True
                notes.append('Dynamic import evidence requires conservative selection: ' + path)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    link(path, alias.name)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ''
                if node.level:
                    package = module_name(path).split('.')
                    if pathlib.Path(path).name != '__init__.py':
                        package = package[:-1]
                    if node.level > len(package):
                        fallback = True
                        notes.append('Relative import evidence unavailable: ' + path)
                        continue
                    package = package[:len(package) - node.level + 1]
                    base = '.'.join(package + ([base] if base else []))
                link(path, base)
                for alias in node.names:
                    if alias.name != '*':
                        link(path, '.'.join(p for p in (base, alias.name) if p))
# Pytest fixtures implicitly depend on conftest files in ancestor directories.
for test in tests:
    for parent in pathlib.PurePosixPath(test).parents:
        config = str(parent / 'conftest.py')
        if config in files:
            graph[test].add(config)
selected = []
for test in tests:
    reason, chain = None, []
    if test in changed:
        reason, chain = 'direct', [test]
    elif changed and fallback:
        reason, chain = 'conservative', []
    elif changed:
        queue, visited = collections.deque([[test]]), {test}
        while queue:
            current = queue.popleft()
            if current[-1] in changed:
                reason, chain = 'transitive', current
                break
            for dependency in sorted(graph[current[-1]]):
                if dependency not in visited:
                    visited.add(dependency)
                    queue.append(current + [dependency])
    if reason:
        selected.append({'path': str(root / test), 'selection_reason': reason, 'chain': chain})
print(json.dumps({'selection': selected, 'analysis_notes': sorted(set(notes)), 'changed_files': sorted(changed), 'base_revision': request['base_revision']}))
"#;

pub struct AffectedSelection {
    pub paths: Vec<PathBuf>,
    detail: Value,
}

impl AffectedSelection {
    pub fn annotate(&self, result: &mut Value) {
        for key in ["results", "tests", "passed", "failures"] {
            if let Some(entries) = result.get_mut(key).and_then(Value::as_array_mut) {
                for entry in entries {
                    if let Some(path) = entry
                        .get("path")
                        .or_else(|| entry.get("file"))
                        .and_then(Value::as_str)
                        && let Some(evidence) = self.detail["selection"]
                            .as_array()
                            .and_then(|items| items.iter().find(|item| item["path"] == path))
                    {
                        entry["selection_reason"] = evidence["selection_reason"].clone();
                    }
                }
            }
        }
        for key in ["selection", "changed_files", "base_revision"] {
            result[key] = self.detail[key].clone();
        }
        let mut notes = result["analysis_notes"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        notes.extend(
            self.detail["analysis_notes"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        result["analysis_notes"] = json!(notes);
    }
}

fn output(command: &mut Command) -> Result<Vec<u8>, String> {
    match spawn_with_timeout(command, Some(30), true).map_err(|_| "Affected-test analysis could not start its required process")? {
        ProcExecOutcome::Completed { status, stdout, .. } if status.success() => Ok(stdout.unwrap_or_default()),
        _ => Err("Affected-test analysis failed or timed out; check git, the base reference, and the target Python runtime".into()),
    }
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    output(
        Command::new("git")
            .current_dir(root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args),
    )
}

fn paths(bytes: Vec<u8>) -> Result<BTreeSet<String>, String> {
    let text = String::from_utf8(bytes).map_err(|_| "Git returned non-UTF-8 paths")?;
    Ok(text
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter(|path| {
            !path.split('/').any(|part| {
                [".git", ".venv", "venv", "__pycache__", ".pytest_cache"].contains(&part)
            }) && !path.starts_with(".pybun/receipts/")
        })
        .map(String::from)
        .collect())
}

pub fn select(working_dir: &Path, since: Option<&str>) -> Result<AffectedSelection, String> {
    let root = String::from_utf8(git(working_dir, &["rev-parse", "--show-toplevel"])?)
        .map_err(|_| "Invalid git root")?;
    let root = PathBuf::from(root.trim_end_matches(['\n', '\r']))
        .canonicalize()
        .map_err(|_| "Cannot resolve git root")?;
    let reference = format!("{}^{{commit}}", since.unwrap_or("HEAD"));
    let base = String::from_utf8(git(
        &root,
        &["rev-parse", "--verify", "--end-of-options", &reference],
    )?)
    .map_err(|_| "Invalid git reference")?;
    let base = base.trim();
    let mut changed = paths(git(
        &root,
        &["diff", "--name-only", "--no-renames", "-z", base, "--"],
    )?)?;
    changed.extend(paths(git(
        &root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?)?);
    let files = paths(git(
        &root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?)?;
    for path in &files {
        let candidate = root.join(path);
        if candidate.exists()
            && !candidate
                .canonicalize()
                .is_ok_and(|path| path.starts_with(&root))
        {
            return Err("Affected-test analysis refuses a path outside the git repository".into());
        }
    }
    let python = crate::env::find_python_env(working_dir)
        .map_err(|_| "Affected-test analysis requires a Python runtime")?;
    let mut request =
        tempfile::NamedTempFile::new().map_err(|_| "Cannot create AST analysis request")?;
    serde_json::to_writer(
        &mut request,
        &json!({"root": root, "files": files, "changed": changed, "base_revision": base}),
    )
    .map_err(|_| "Cannot write AST analysis request")?;
    let bytes = output(
        Command::new(python.python_path)
            .args(["-I", "-c", AST_SELECTION])
            .arg(request.path()),
    )?;
    let detail: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid AST selection response")?;
    for key in ["analysis_notes", "changed_files"] {
        if !detail[key]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
        {
            return Err("Invalid AST selection evidence".into());
        }
    }
    if detail["base_revision"] != base {
        return Err("AST selection base revision mismatch".into());
    }
    let selection = detail["selection"]
        .as_array()
        .ok_or("Missing AST selection evidence")?;
    let mut selected_paths = Vec::new();
    for item in selection {
        if !matches!(
            item["selection_reason"].as_str(),
            Some("direct" | "transitive" | "conservative")
        ) || !item["chain"]
            .as_array()
            .is_some_and(|chain| chain.iter().all(Value::is_string))
        {
            return Err("Invalid AST selection evidence".into());
        }
        let path = PathBuf::from(item["path"].as_str().ok_or("Invalid AST selection path")?);
        if path.extension().is_none_or(|extension| extension != "py")
            || !path
                .canonicalize()
                .is_ok_and(|path| path.starts_with(&root) && path.is_file())
        {
            return Err("Invalid AST selection path".into());
        }
        selected_paths.push(path);
    }
    Ok(AffectedSelection {
        paths: selected_paths,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ast(files: &[(&str, &str)], changed: &[&str]) -> Value {
        let temp = tempfile::tempdir().unwrap();
        for (path, source) in files {
            let path = temp.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, source).unwrap();
        }
        let mut request = tempfile::NamedTempFile::new().unwrap();
        serde_json::to_writer(&mut request, &json!({"root": temp.path(), "files": files.iter().map(|(path, _)| path).collect::<Vec<_>>(), "changed": changed, "base_revision": "fixture"})).unwrap();
        let bytes = output(
            Command::new("python3")
                .args(["-I", "-c", AST_SELECTION])
                .arg(request.path()),
        )
        .unwrap();
        assert!(
            !temp.path().join("executed").exists(),
            "AST selection must not execute project code"
        );
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn ast_handles_src_layout_relative_imports_aliases_multiline_and_cycles() {
        let result = ast(
            &[
                ("src/pkg/__init__.py", ""),
                ("src/pkg/a.py", "from .b import VALUE\n"),
                ("src/pkg/b.py", "from . import a\nVALUE=1\n"),
                (
                    "test_graph.py",
                    "from pkg import (\n    a as first,\n)\ndef test_graph():\n    pass\n",
                ),
            ],
            &["src/pkg/b.py"],
        );
        assert_eq!(result["selection"].as_array().unwrap().len(), 1);
        assert_eq!(result["selection"][0]["selection_reason"], "transitive");
        assert_eq!(
            result["selection"][0]["chain"],
            json!(["test_graph.py", "src/pkg/a.py", "src/pkg/b.py"])
        );
    }

    #[test]
    fn ast_ignores_strings_without_executing_code() {
        let result = ast(
            &[
                (
                    "core.py",
                    "from pathlib import Path\nPath('executed').write_text('unsafe')\n",
                ),
                (
                    "test_strings.py",
                    "source = 'import core'\ndef test_strings():\n    pass\n",
                ),
            ],
            &["core.py"],
        );
        assert!(result["selection"].as_array().unwrap().is_empty());
    }

    #[test]
    fn ast_conservatively_handles_aliased_dynamic_imports() {
        let result = ast(
            &[
                ("core.py", "VALUE=1\n"),
                (
                    "test_dynamic.py",
                    "from importlib import import_module as load\ndef test_dynamic():\n    load('core')\n",
                ),
            ],
            &["core.py"],
        );
        assert_eq!(result["selection"].as_array().unwrap().len(), 1);
        assert_eq!(result["selection"][0]["selection_reason"], "conservative");
    }

    #[test]
    fn ast_preserves_implicit_fixtures_sibling_imports_and_src_named_modules() {
        for (files, changed) in [
            (
                vec![
                    ("core.py", "VALUE=1\n"),
                    ("conftest.py", "import core\n"),
                    ("test_fixture.py", "def test_fixture():\n    pass\n"),
                ],
                "core.py",
            ),
            (
                vec![
                    ("tests/helper.py", "VALUE=1\n"),
                    ("tests/test_example.py", "from helper import VALUE\n"),
                ],
                "tests/helper.py",
            ),
            (
                vec![
                    ("pkg/src.py", "VALUE=1\n"),
                    ("test_example.py", "import pkg.src\n"),
                ],
                "pkg/src.py",
            ),
        ] {
            let result = ast(&files, &[changed]);
            assert_eq!(
                result["selection"].as_array().unwrap().len(),
                1,
                "{changed}: {result}"
            );
        }
    }

    #[test]
    fn git_paths_preserve_spaces_and_filter_runtime_cache_artifacts() {
        let result = paths(b"tests/test space.py\0venv/bin/python\0.venv/bin/python\0__pycache__/core.pyc\0.pytest_cache/v/cache\0.pybun/receipts/id.json\0".to_vec()).unwrap();
        assert_eq!(result, BTreeSet::from(["tests/test space.py".to_string()]));
        assert!(paths(vec![0xff]).is_err());
    }
}
