//! Rust-based module finder for accelerated Python import resolution.
//!
//! This module provides a high-performance module finder that can replace
//! Python's default `sys.meta_path` entry for import resolution. It uses
//! parallel filesystem scanning to find modules quickly.
//!
//! The module finder is opt-in and guarded by a flag to allow fallback
//! to CPython's native import system when needed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use serde::{Deserialize, Serialize};

/// Configuration for the module finder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFinderConfig {
    /// Whether the module finder is enabled.
    pub enabled: bool,
    /// Search paths for modules (similar to sys.path).
    pub search_paths: Vec<PathBuf>,
    /// Number of threads for parallel scanning.
    #[serde(default = "default_threads")]
    pub threads: usize,
    /// Cache discovered modules for faster subsequent lookups.
    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,
    /// File extensions to consider as Python modules.
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,
}

impl Default for ModuleFinderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            search_paths: Vec::new(),
            threads: default_threads(),
            cache_enabled: default_cache_enabled(),
            extensions: default_extensions(),
        }
    }
}

fn default_threads() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn default_cache_enabled() -> bool {
    true
}

fn default_extensions() -> Vec<String> {
    vec![
        ".py".to_string(),
        ".pyc".to_string(),
        ".pyd".to_string(),
        ".so".to_string(),
    ]
}

/// Type of module found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleType {
    /// A single-file module (e.g., foo.py).
    Module,
    /// A package directory with __init__.py.
    Package,
    /// A namespace package (directory without __init__.py, PEP 420).
    NamespacePackage,
    /// A compiled extension module (.so, .pyd).
    Extension,
}

/// Information about a discovered module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Full module name (e.g., "foo.bar.baz").
    pub name: String,
    /// Filesystem path to the module.
    pub path: PathBuf,
    /// Type of module.
    pub module_type: ModuleType,
    /// Parent search path that contains this module.
    pub search_path: PathBuf,
}

/// Result of a module search operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSearchResult {
    /// Found module info, if any.
    pub module: Option<ModuleInfo>,
    /// Paths searched during resolution.
    pub searched_paths: Vec<PathBuf>,
    /// Time taken for the search in microseconds.
    pub duration_us: u64,
}

/// Result of a directory scan operation.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Discovered modules.
    pub modules: Vec<ModuleInfo>,
    /// Time taken for the scan in microseconds.
    pub duration_us: u64,
}

/// Parallel scan threshold: if a directory has more than this many immediate
/// subdirectories, process them across threads to amortize traversal cost.
const PARALLEL_SUBDIR_THRESHOLD: usize = 10;

/// Recognize an ABI/platform tag as used in CPython extension module
/// filenames, e.g. the `cpython-312-x86_64-linux-gnu` in
/// `foo.cpython-312-x86_64-linux-gnu.so`, the `abi3` in `foo.abi3.so`, or the
/// `cp312-win_amd64` in `foo.cp312-win_amd64.pyd` (Issue #405).
///
/// This is a conservative filename-pattern parser, not a check against a
/// specific target interpreter's actual `EXTENSION_SUFFIXES` — it accepts any
/// well-formed CPython-style tag so standalone scanning (with no known target
/// interpreter) still recognizes real extension modules. It does not attempt
/// to validate ABI *compatibility* with a particular interpreter/platform.
fn is_extension_abi_tag(tag: &str) -> bool {
    if tag == "abi3" {
        return true;
    }
    if let Some(rest) = tag.strip_prefix("cpython-") {
        return rest.starts_with(|c: char| c.is_ascii_digit());
    }
    if let Some(rest) = tag.strip_prefix("cp") {
        let digit_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digit_end == 0 {
            return false;
        }
        let remainder = &rest[digit_end..];
        return remainder.is_empty() || remainder.starts_with('-');
    }
    false
}

/// Compute the logical module stem for a filename against a plain extension
/// suffix (".so" or ".pyd"), stripping a recognized ABI/platform tag when
/// present (Issue #405). Returns `None` when `file_name` doesn't end with
/// `ext` at all.
///
/// Examples (`ext = ".so"`):
/// - `foo.so` -> `foo` (no tag)
/// - `foo.cpython-312-x86_64-linux-gnu.so` -> `foo`
/// - `foo.abi3.so` -> `foo`
/// - `foo.bar.so` -> `foo.bar` (`bar` isn't a recognized tag, so the whole
///   remainder is treated as the stem, matching the pre-#405 plain-suffix
///   behavior for anything that isn't ABI-tagged)
fn extension_module_stem<'a>(file_name: &'a str, ext: &str) -> Option<&'a str> {
    let without_ext = file_name.strip_suffix(ext)?;
    if let Some(dot_idx) = without_ext.rfind('.') {
        let tag = &without_ext[dot_idx + 1..];
        if is_extension_abi_tag(tag) {
            return Some(&without_ext[..dot_idx]);
        }
    }
    Some(without_ext)
}

/// Search `dir` for an extension module file (`.so`/`.pyd`, optionally
/// ABI-tagged) whose logical stem equals `name` (Issue #405). Unlike plain
/// `.py`/`.pyc` lookup, the exact filename can't be constructed ahead of time
/// when an ABI tag may be present, so the directory has to be listed.
fn find_extension_module_file(dir: &Path, name: &str, ext: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        if extension_module_stem(&file_name, ext) == Some(name) {
            return Some(entry.path());
        }
    }
    None
}

/// Outcome of resolving one module-name lookup within a single search path
/// (Issue #406). A concrete package/module/extension always takes precedence
/// over a namespace-package directory — both within one search path (a
/// sibling `foo/` without `__init__.py` never shadows `foo.py`) and across
/// multiple search paths (a namespace directory found in an earlier
/// `sys.path` entry never shadows a concrete module found in a later one),
/// mirroring CPython's path-based finder / PEP 420 semantics.
enum FindResult {
    Concrete(ModuleInfo),
    Namespace(ModuleInfo),
}

/// The Rust-based module finder.
#[derive(Debug)]
pub struct ModuleFinder {
    config: ModuleFinderConfig,
    /// Cache of module name -> ModuleInfo.
    cache: Arc<std::sync::RwLock<HashMap<String, Option<ModuleInfo>>>>,
}

impl ModuleFinder {
    /// Create a new module finder with the given configuration.
    pub fn new(config: ModuleFinderConfig) -> Self {
        Self {
            config,
            cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create a module finder with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ModuleFinderConfig::default())
    }

    /// Check if the module finder is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the configuration.
    pub fn config(&self) -> &ModuleFinderConfig {
        &self.config
    }

    /// Add a search path.
    ///
    /// Invalidates the lookup cache (Issue #407): `find_module` caches
    /// negative results (`None`) as well as positive ones, keyed only by
    /// module name — not by which search paths were in effect when the miss
    /// was recorded. Without invalidation, a module that was absent under
    /// the old path list stays permanently "not found" for this
    /// `ModuleFinder` even after a path containing it is added, since the
    /// stale cached `None` short-circuits the actual (now-successful)
    /// filesystem search. Clearing the whole cache is coarser than strictly
    /// necessary (it also drops still-valid positive entries from unrelated,
    /// unchanged paths) but is the simplest invalidation that can't leave a
    /// stale miss behind, and search-path mutation is expected to be rare
    /// relative to lookups. No-op (and no invalidation) when `path` is
    /// already present, since the effective configuration — and therefore
    /// every cached result — is unchanged.
    pub fn add_search_path(&mut self, path: PathBuf) {
        if !self.config.search_paths.contains(&path) {
            self.config.search_paths.push(path);
            self.clear_cache();
        }
    }

    /// Find a module by its fully qualified name.
    ///
    /// # Arguments
    /// * `module_name` - The full module name (e.g., "os.path" or "numpy.core")
    ///
    /// # Returns
    /// A `ModuleSearchResult` containing the found module or None.
    pub fn find_module(&self, module_name: &str) -> ModuleSearchResult {
        let start = std::time::Instant::now();

        // Check cache first
        if self.config.cache_enabled
            && let Ok(cache) = self.cache.read()
            && let Some(cached) = cache.get(module_name)
        {
            return ModuleSearchResult {
                module: cached.clone(),
                searched_paths: vec![],
                duration_us: start.elapsed().as_micros() as u64,
            };
        }

        let mut searched_paths = Vec::new();
        let module_parts: Vec<&str> = module_name.split('.').collect();
        // A namespace-package directory found in an earlier search path must
        // not shadow a concrete module/package found in a later one (PEP 420;
        // Issue #406) — CPython accumulates namespace portions and only falls
        // back to them once no path entry yields a concrete candidate. Defer
        // the first namespace hit here and keep scanning; return it only if
        // no search path produces a concrete match. (This records just the
        // first namespace portion's path, not the full merged portion list —
        // `ModuleInfo` models one filesystem location, so exposing all
        // contributing directories would need a richer result type; that's
        // out of scope here and is fine for anything short of true multi-portion
        // namespace package `__path__` semantics.)
        let mut namespace_candidate: Option<ModuleInfo> = None;

        // Search in each path
        for search_path in &self.config.search_paths {
            if !search_path.exists() {
                continue;
            }

            searched_paths.push(search_path.clone());

            match self.find_in_path(search_path, &module_parts) {
                Some(FindResult::Concrete(module_info)) => {
                    // A concrete package/module/extension always wins immediately.
                    if self.config.cache_enabled
                        && let Ok(mut cache) = self.cache.write()
                    {
                        cache.insert(module_name.to_string(), Some(module_info.clone()));
                    }

                    return ModuleSearchResult {
                        module: Some(module_info),
                        searched_paths,
                        duration_us: start.elapsed().as_micros() as u64,
                    };
                }
                Some(FindResult::Namespace(module_info)) if namespace_candidate.is_none() => {
                    namespace_candidate = Some(module_info);
                }
                _ => {}
            }
        }

        if let Some(module_info) = namespace_candidate {
            if self.config.cache_enabled
                && let Ok(mut cache) = self.cache.write()
            {
                cache.insert(module_name.to_string(), Some(module_info.clone()));
            }

            return ModuleSearchResult {
                module: Some(module_info),
                searched_paths,
                duration_us: start.elapsed().as_micros() as u64,
            };
        }

        // Cache the negative result
        if self.config.cache_enabled
            && let Ok(mut cache) = self.cache.write()
        {
            cache.insert(module_name.to_string(), None);
        }

        ModuleSearchResult {
            module: None,
            searched_paths,
            duration_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Find a module within a specific search path.
    ///
    /// Returns `FindResult::Concrete` for a regular package/module/extension,
    /// `FindResult::Namespace` for a PEP 420 namespace-package directory (no
    /// `__init__.py`), or `None` if nothing matches `module_parts` here at
    /// all. A namespace directory is only ever a fallback: it's checked last,
    /// after every concrete candidate, so `foo.py` (or `foo/__init__.py`,
    /// or a `foo.<ext>` extension module) is never shadowed by a sibling
    /// `foo/` directory that merely happens to exist without an `__init__.py`
    /// (Issue #406 — this previously returned the namespace directory
    /// immediately on sight, before checking for a concrete `foo.py`).
    fn find_in_path(&self, search_path: &Path, module_parts: &[&str]) -> Option<FindResult> {
        if module_parts.is_empty() {
            return None;
        }

        // Build the path to the module
        let mut current_path = search_path.to_path_buf();
        for part in module_parts.iter().take(module_parts.len() - 1) {
            current_path = current_path.join(part);
            if !current_path.is_dir() {
                return None;
            }
        }

        let last_part = module_parts.last()?;
        let module_name = module_parts.join(".");
        let package_dir = current_path.join(last_part);

        // 1. Regular package: foo/__init__.py always wins outright.
        if package_dir.is_dir() {
            let init_py = package_dir.join("__init__.py");
            if init_py.exists() {
                return Some(FindResult::Concrete(ModuleInfo {
                    name: module_name,
                    path: init_py,
                    module_type: ModuleType::Package,
                    search_path: search_path.to_path_buf(),
                }));
            }
        }

        // 2. Regular module / extension files, in configured suffix order.
        for ext in &self.config.extensions {
            if ext == ".so" || ext == ".pyd" {
                // ABI-tagged extension modules (Issue #405) don't have a
                // predictable exact filename (`foo.cpython-312-...-gnu.so`),
                // so unlike the plain-suffix case below they can't be found
                // by constructing one candidate path — the directory has to
                // be listed and each entry's logical name compared instead.
                if let Some(module_file) = find_extension_module_file(&current_path, last_part, ext)
                {
                    return Some(FindResult::Concrete(ModuleInfo {
                        name: module_name,
                        path: module_file,
                        module_type: ModuleType::Extension,
                        search_path: search_path.to_path_buf(),
                    }));
                }
                continue;
            }

            let module_file = current_path.join(format!("{}{}", last_part, ext));
            if module_file.is_file() {
                return Some(FindResult::Concrete(ModuleInfo {
                    name: module_name,
                    path: module_file,
                    module_type: ModuleType::Module,
                    search_path: search_path.to_path_buf(),
                }));
            }
        }

        // 3. No concrete candidate: fall back to a namespace-package portion
        // (PEP 420) if `foo/` exists without `__init__.py`.
        if package_dir.is_dir() {
            return Some(FindResult::Namespace(ModuleInfo {
                name: module_name,
                path: package_dir,
                module_type: ModuleType::NamespacePackage,
                search_path: search_path.to_path_buf(),
            }));
        }

        None
    }

    /// Scan a directory and return all discovered modules.
    ///
    /// Uses `DirEntry::file_type()` to avoid extra `stat` syscalls per entry,
    /// and spawns threads for top-level subdirectories when there are many of them.
    /// Only the top-level split is parallelised; deeper recursion is sequential
    /// to bound the total number of live threads.
    pub fn scan_directory(&self, dir: &Path) -> Vec<ModuleInfo> {
        if !dir.is_dir() {
            return Vec::new();
        }
        // Seed the cycle-detection ancestor set with the canonical root itself,
        // so a top-level symlink that points back at `dir` (e.g. `dir/loop ->
        // dir`) is caught immediately rather than after one extra descent.
        let mut ancestors = HashSet::new();
        if let Ok(canonical_root) = std::fs::canonicalize(dir) {
            ancestors.insert(canonical_root);
        }
        self.scan_directory_inner(dir, dir, "", true, &ancestors)
    }

    /// Scan a directory and return modules with timing information.
    pub fn scan_directory_timed(&self, dir: &Path) -> ScanResult {
        let start = std::time::Instant::now();
        let modules = self.scan_directory(dir);
        ScanResult {
            duration_us: start.elapsed().as_micros() as u64,
            modules,
        }
    }

    /// Inner recursive scan.
    ///
    /// Uses `DirEntry::file_type()` for the common case (no extra stat syscall);
    /// falls back to `path.metadata()` for symlinks so they are followed correctly.
    ///
    /// `parallel`: when true and there are enough top-level subdirectories,
    /// spawn threads for that level only. Recursive calls always pass `false`
    /// to bound the total number of live threads.
    ///
    /// `ancestors`: canonical (symlink-resolved) paths of every directory
    /// currently on the recursion stack from the scan root down to `dir`
    /// (Issue #404). Directories are followed through symlinks, so a symlink
    /// cycle (e.g. `pkg/loop -> pkg`, or `a/b/back -> a`) could otherwise
    /// recurse indefinitely. Tracking ancestors *per recursion branch*
    /// (rather than a single set shared across the whole scan, as
    /// `drift.rs::collect_py_files` does) means two unrelated symlinks that
    /// happen to point at the same real directory are each still fully
    /// scanned — only an actual cycle back to one of *this path's own*
    /// ancestors is suppressed. Each branch clones and extends its own set on
    /// the way down, so this is race-free across the parallel dispatch below
    /// without needing a shared/synchronized set.
    fn scan_directory_inner(
        &self,
        base_path: &Path,
        dir: &Path,
        prefix: &str,
        parallel: bool,
        ancestors: &HashSet<PathBuf>,
    ) -> Vec<ModuleInfo> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };

        let mut modules = Vec::new();
        // Subdirs deferred for potential parallel dispatch: (path, module_name)
        let mut subdirs: Vec<(PathBuf, String)> = Vec::new();

        for entry in entries.flatten() {
            let Ok(raw_ft) = entry.file_type() else {
                continue;
            };
            let file_name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };

            if file_name.starts_with('.') || file_name == "__pycache__" {
                continue;
            }

            let path = entry.path();

            // Resolve symlinks: `file_type()` returns the link's own type, not its
            // target's type. Follow the link so that symlinked .py files and
            // package directories (common in venvs and editable installs) are found.
            let (effective_is_dir, effective_is_file) = if raw_ft.is_symlink() {
                let Ok(meta) = path.metadata() else { continue };
                (meta.is_dir(), meta.is_file())
            } else {
                (raw_ft.is_dir(), raw_ft.is_file())
            };

            if effective_is_dir {
                let module_name = if prefix.is_empty() {
                    file_name.clone()
                } else {
                    format!("{}.{}", prefix, file_name)
                };

                // One stat per directory to detect package vs namespace package.
                let init_py = path.join("__init__.py");
                if init_py.exists() {
                    modules.push(ModuleInfo {
                        name: module_name.clone(),
                        path: init_py,
                        module_type: ModuleType::Package,
                        search_path: base_path.to_path_buf(),
                    });
                } else {
                    // Directory without __init__.py is a namespace package (PEP 420).
                    modules.push(ModuleInfo {
                        name: module_name.clone(),
                        path: path.clone(),
                        module_type: ModuleType::NamespacePackage,
                        search_path: base_path.to_path_buf(),
                    });
                }

                subdirs.push((path, module_name));
            } else if effective_is_file {
                for ext in &self.config.extensions {
                    let is_extension_ext = ext == ".so" || ext == ".pyd";
                    // Extension modules (.so/.pyd) commonly carry an ABI/platform
                    // tag between the logical name and the plain suffix (e.g.
                    // `foo.cpython-312-x86_64-linux-gnu.so`, `foo.abi3.so`,
                    // `foo.cp312-win_amd64.pyd`). A plain `strip_suffix` would
                    // report the wrong logical module name, with the tag still
                    // attached (Issue #405). `extension_module_stem` strips a
                    // recognized tag too; plain `.py`/`.pyc` matching is
                    // unaffected.
                    let stem = if is_extension_ext {
                        extension_module_stem(&file_name, ext.as_str())
                    } else {
                        file_name.strip_suffix(ext.as_str())
                    };
                    let Some(stem) = stem else { continue };
                    if stem == "__init__" {
                        break; // already emitted as package above
                    }
                    let module_name = if prefix.is_empty() {
                        stem.to_string()
                    } else {
                        format!("{}.{}", prefix, stem)
                    };
                    let module_type = if is_extension_ext {
                        ModuleType::Extension
                    } else {
                        ModuleType::Module
                    };
                    modules.push(ModuleInfo {
                        name: module_name,
                        path: path.clone(),
                        module_type,
                        search_path: base_path.to_path_buf(),
                    });
                    break;
                }
            }
        }

        // Dispatch subdirectory traversal: parallel only at the top-level call so
        // that the total number of live threads stays bounded by the top-level
        // subdirectory count (≤ PARALLEL_SUBDIR_THRESHOLD or the dir's width).
        if parallel && subdirs.len() > PARALLEL_SUBDIR_THRESHOLD && self.config.threads > 1 {
            let sub_results: Vec<Vec<ModuleInfo>> = thread::scope(|s| {
                let handles: Vec<_> = subdirs
                    .iter()
                    .filter_map(|(path, name)| {
                        // Skip descent (but keep the module entry already recorded
                        // above) on a symlink cycle or an unresolvable path.
                        let next_ancestors = self.next_ancestors(path, ancestors)?;
                        // Recursive calls use parallel=false to prevent unbounded spawning.
                        Some(s.spawn(move || {
                            self.scan_directory_inner(base_path, path, name, false, &next_ancestors)
                        }))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap_or_default())
                    .collect()
            });
            for result in sub_results {
                modules.extend(result);
            }
        } else {
            for (path, name) in &subdirs {
                let Some(next_ancestors) = self.next_ancestors(path, ancestors) else {
                    continue;
                };
                modules.extend(self.scan_directory_inner(
                    base_path,
                    path,
                    name,
                    false,
                    &next_ancestors,
                ));
            }
        }

        modules
    }

    /// Canonicalize `path` and check it against the current recursion branch's
    /// `ancestors` (Issue #404). Returns `None` — meaning "do not recurse into
    /// this directory" — when `path` resolves to a directory already on this
    /// branch's ancestor chain (a symlink cycle) or when canonicalization
    /// fails (e.g. a dangling symlink, or a permission error); the directory's
    /// own module entry is unaffected either way since it was already recorded
    /// by the caller before this is consulted. Otherwise returns a new,
    /// independent ancestor set (the branch's ancestors plus `path`'s
    /// canonical form) for the recursive call to use.
    fn next_ancestors(
        &self,
        path: &Path,
        ancestors: &HashSet<PathBuf>,
    ) -> Option<HashSet<PathBuf>> {
        let canonical = std::fs::canonicalize(path).ok()?;
        if ancestors.contains(&canonical) {
            return None;
        }
        let mut next = ancestors.clone();
        next.insert(canonical);
        Some(next)
    }

    /// Clear the module cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Get the number of cached entries.
    pub fn cache_size(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Parallel scan of multiple directories, returning modules with timing.
    pub fn parallel_scan_timed(&self, directories: &[PathBuf]) -> ScanResult {
        let start = std::time::Instant::now();
        let modules = self.parallel_scan(directories);
        ScanResult {
            duration_us: start.elapsed().as_micros() as u64,
            modules,
        }
    }

    /// Parallel scan of multiple directories.
    ///
    /// For a single directory the internal subdirectory parallelism inside
    /// `scan_directory_inner` handles concurrency; this outer loop is for
    /// scanning multiple distinct root paths in parallel.
    pub fn parallel_scan(&self, directories: &[PathBuf]) -> Vec<ModuleInfo> {
        if directories.is_empty() {
            return Vec::new();
        }

        if directories.len() == 1 {
            return self.scan_directory(&directories[0]);
        }

        if directories.len() <= 2 || self.config.threads <= 1 {
            return directories
                .iter()
                .flat_map(|d| self.scan_directory(d))
                .collect();
        }

        // Parallel scan across multiple root directories.
        let chunk_size = directories.len().div_ceil(self.config.threads);
        let chunks: Vec<_> = directories.chunks(chunk_size).collect();

        thread::scope(|s| {
            let handles: Vec<_> = chunks
                .iter()
                .map(|chunk| {
                    s.spawn(|| {
                        chunk
                            .iter()
                            .flat_map(|d| self.scan_directory(d))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();

            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        })
    }
}

/// Generate Python code that installs this module finder into sys.meta_path.
///
/// This returns Python code that can be executed to install a custom finder
/// that delegates to the Rust implementation via a socket/pipe.
pub fn generate_finder_python_code(socket_path: &str) -> String {
    format!(
        r#"
import sys
import importlib.abc
import importlib.machinery

class PybunModuleFinder(importlib.abc.MetaPathFinder):
    """
    Custom module finder that delegates to PyBun's Rust implementation
    for accelerated module resolution.
    """
    
    def __init__(self, socket_path):
        self.socket_path = socket_path
        self._fallback = None
    
    def find_spec(self, fullname, path, target=None):
        # TODO: Implement IPC to Rust module finder
        # For now, return None to fall back to default finders
        return None
    
    def invalidate_caches(self):
        pass

# Install the finder at the beginning of sys.meta_path
_pybun_finder = PybunModuleFinder("{socket_path}")
sys.meta_path.insert(0, _pybun_finder)
"#,
        socket_path = socket_path
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_module_structure(dir: &Path) {
        // Create a package structure:
        // dir/
        //   foo.py
        //   bar/
        //     __init__.py
        //     baz.py
        //     qux/
        //       __init__.py
        //       quux.py

        fs::write(dir.join("foo.py"), "# foo module").unwrap();

        let bar_dir = dir.join("bar");
        fs::create_dir_all(&bar_dir).unwrap();
        fs::write(bar_dir.join("__init__.py"), "# bar package").unwrap();
        fs::write(bar_dir.join("baz.py"), "# baz module").unwrap();

        let qux_dir = bar_dir.join("qux");
        fs::create_dir_all(&qux_dir).unwrap();
        fs::write(qux_dir.join("__init__.py"), "# qux package").unwrap();
        fs::write(qux_dir.join("quux.py"), "# quux module").unwrap();
    }

    #[test]
    fn test_find_simple_module() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let result = finder.find_module("foo");

        assert!(result.module.is_some());
        let module = result.module.unwrap();
        assert_eq!(module.name, "foo");
        assert_eq!(module.module_type, ModuleType::Module);
        assert!(module.path.ends_with("foo.py"));
    }

    #[test]
    fn test_find_package() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let result = finder.find_module("bar");

        assert!(result.module.is_some());
        let module = result.module.unwrap();
        assert_eq!(module.name, "bar");
        assert_eq!(module.module_type, ModuleType::Package);
        assert!(module.path.ends_with("__init__.py"));
    }

    #[test]
    fn test_find_nested_module() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let result = finder.find_module("bar.baz");

        assert!(result.module.is_some());
        let module = result.module.unwrap();
        assert_eq!(module.name, "bar.baz");
        assert_eq!(module.module_type, ModuleType::Module);
    }

    #[test]
    fn test_find_deeply_nested_module() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let result = finder.find_module("bar.qux.quux");

        assert!(result.module.is_some());
        let module = result.module.unwrap();
        assert_eq!(module.name, "bar.qux.quux");
        assert_eq!(module.module_type, ModuleType::Module);
    }

    #[test]
    fn test_module_not_found() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let result = finder.find_module("nonexistent");

        assert!(result.module.is_none());
        assert!(!result.searched_paths.is_empty());
    }

    #[test]
    fn test_cache_hit() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);

        // First lookup
        let result1 = finder.find_module("foo");
        assert!(result1.module.is_some());
        assert_eq!(finder.cache_size(), 1);

        // Second lookup should be cached (searched_paths will be empty)
        let result2 = finder.find_module("foo");
        assert!(result2.module.is_some());
        assert!(result2.searched_paths.is_empty()); // Cache hit indicator
    }

    #[test]
    fn test_cache_disabled() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: false,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);

        finder.find_module("foo");
        assert_eq!(finder.cache_size(), 0);
    }

    #[test]
    fn test_scan_directory() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        // Should find: foo, bar, bar.baz, bar.qux, bar.qux.quux
        assert!(modules.len() >= 5);

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"bar.baz"));
        assert!(names.contains(&"bar.qux"));
        assert!(names.contains(&"bar.qux.quux"));
    }

    #[test]
    fn test_namespace_package() {
        let temp = TempDir::new().unwrap();

        // Create a namespace package (directory without __init__.py)
        let ns_dir = temp.path().join("mynamespace");
        fs::create_dir_all(&ns_dir).unwrap();
        fs::write(ns_dir.join("submodule.py"), "# submodule").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let result = finder.find_module("mynamespace");

        assert!(result.module.is_some());
        let module = result.module.unwrap();
        assert_eq!(module.module_type, ModuleType::NamespacePackage);
    }

    #[test]
    fn test_clear_cache() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        finder.find_module("foo");
        assert_eq!(finder.cache_size(), 1);

        finder.clear_cache();
        assert_eq!(finder.cache_size(), 0);
    }

    #[test]
    fn test_parallel_scan() {
        let temp1 = TempDir::new().unwrap();
        let temp2 = TempDir::new().unwrap();

        fs::write(temp1.path().join("mod1.py"), "# mod1").unwrap();
        fs::write(temp2.path().join("mod2.py"), "# mod2").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![],
            cache_enabled: true,
            threads: 2,
            ..Default::default()
        };

        let finder = ModuleFinder::new(config);
        let modules =
            finder.parallel_scan(&[temp1.path().to_path_buf(), temp2.path().to_path_buf()]);

        assert_eq!(modules.len(), 2);
        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"mod1"));
        assert!(names.contains(&"mod2"));
    }

    #[test]
    fn test_add_search_path() {
        let mut finder = ModuleFinder::with_defaults();
        assert!(finder.config().search_paths.is_empty());

        finder.add_search_path(PathBuf::from("/some/path"));
        assert_eq!(finder.config().search_paths.len(), 1);

        // Adding the same path again should not duplicate
        finder.add_search_path(PathBuf::from("/some/path"));
        assert_eq!(finder.config().search_paths.len(), 1);
    }

    #[test]
    fn test_default_config() {
        let config = ModuleFinderConfig::default();
        assert!(!config.enabled);
        assert!(config.search_paths.is_empty());
        assert!(config.threads > 0);
        assert!(config.cache_enabled);
        assert!(!config.extensions.is_empty());
    }

    #[test]
    fn test_generate_python_code() {
        let code = generate_finder_python_code("/tmp/pybun.sock");
        assert!(code.contains("PybunModuleFinder"));
        assert!(code.contains("sys.meta_path"));
        assert!(code.contains("/tmp/pybun.sock"));
    }

    #[test]
    fn test_scan_directory_timed_returns_duration() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.scan_directory_timed(temp.path());

        assert!(!result.modules.is_empty());
        // Duration should be non-negative (u64 is always >= 0, but should be > 0 for real work)
        // On a loaded CI machine this might be 0µs on very fast runs, so just assert it's a number.
        let _ = result.duration_us;
    }

    #[test]
    fn test_parallel_scan_timed_returns_duration() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.parallel_scan_timed(&[temp.path().to_path_buf()]);

        assert!(!result.modules.is_empty());
        let _ = result.duration_us;
    }

    #[test]
    fn test_scan_with_many_subdirs_finds_all_modules() {
        let temp = TempDir::new().unwrap();

        // Create PARALLEL_SUBDIR_THRESHOLD + 5 packages to trigger parallel path
        for i in 0..15 {
            let pkg = temp.path().join(format!("pkg{i}"));
            fs::create_dir_all(&pkg).unwrap();
            fs::write(pkg.join("__init__.py"), "").unwrap();
            fs::write(pkg.join("mod.py"), "").unwrap();
        }

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            threads: 4,
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        // Each package contributes: the package itself + one module = 30 total
        assert_eq!(
            modules.len(),
            30,
            "expected 30 modules (15 packages + 15 modules)"
        );
        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"pkg0"));
        assert!(names.contains(&"pkg0.mod"));
        assert!(names.contains(&"pkg14"));
    }

    #[test]
    fn test_scan_with_few_subdirs_uses_sequential_path() {
        // Fewer than PARALLEL_SUBDIR_THRESHOLD subdirs — still correct results
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            threads: 4,
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());
        assert!(modules.len() >= 5);
    }

    #[test]
    fn test_scan_reports_namespace_package() {
        let temp = TempDir::new().unwrap();

        // Namespace package: directory without __init__.py
        let ns_dir = temp.path().join("mynamespace");
        fs::create_dir_all(&ns_dir).unwrap();
        fs::write(ns_dir.join("submodule.py"), "# submodule").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.contains(&"mynamespace"),
            "scan should report namespace package; got {:?}",
            names
        );
        let ns_mod = modules.iter().find(|m| m.name == "mynamespace").unwrap();
        assert_eq!(
            ns_mod.module_type,
            ModuleType::NamespacePackage,
            "directory without __init__.py should be NamespacePackage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_follows_symlinked_py_files() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let real_file = temp.path().join("real_mod.py");
        fs::write(&real_file, "# real module").unwrap();

        // Create a symlink to the .py file
        let link = temp.path().join("linked_mod.py");
        symlink(&real_file, &link).unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.contains(&"linked_mod"),
            "scan should follow symlinks to .py files; got {:?}",
            names
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_follows_symlinked_package_dirs() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();

        // Create the real package in a separate dir
        let real_pkg = temp.path().join("_real_pkg");
        fs::create_dir_all(&real_pkg).unwrap();
        fs::write(real_pkg.join("__init__.py"), "# pkg").unwrap();
        fs::write(real_pkg.join("mod.py"), "# mod").unwrap();

        // Symlink the package directory
        let link = temp.path().join("linked_pkg");
        symlink(&real_pkg, &link).unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.contains(&"linked_pkg"),
            "scan should follow symlinked package dirs; got {:?}",
            names
        );
        let pkg = modules.iter().find(|m| m.name == "linked_pkg").unwrap();
        assert_eq!(
            pkg.module_type,
            ModuleType::Package,
            "symlinked dir with __init__.py should be Package"
        );
    }

    // =========================================================================
    // Issue #404: directory symlink cycles must not cause unbounded recursion.
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn test_scan_terminates_on_self_symlink_cycle() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let pkg = temp.path().join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(pkg.join("mod.py"), "").unwrap();

        // pkg/loop -> pkg (self-cycle)
        symlink(&pkg, pkg.join("loop")).unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        // Terminating at all (rather than hanging/stack-overflowing) is the
        // primary assertion here.
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"pkg"), "expected pkg: {names:?}");
        assert!(names.contains(&"pkg.mod"), "expected pkg.mod: {names:?}");
        // The `loop` entry itself is preserved (it's a real, discoverable
        // namespace/package dir from the scanner's point of view)...
        assert!(names.contains(&"pkg.loop"), "expected pkg.loop: {names:?}");
        // ...but descent into it must not repeat pkg's own contents endlessly.
        assert!(
            !names.contains(&"pkg.loop.mod"),
            "recursion into the self-cycle must be suppressed: {names:?}"
        );
        assert!(
            modules.len() < 20,
            "module count must stay bounded for a self-cycle, got {}: {:?}",
            modules.len(),
            names
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_terminates_on_parent_symlink_cycle() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let a = temp.path().join("a");
        let b = a.join("b");
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("__init__.py"), "").unwrap();
        fs::write(b.join("__init__.py"), "").unwrap();
        fs::write(b.join("mod.py"), "").unwrap();

        // a/b/back -> a (cycle back to a grandparent, not a direct self-link)
        symlink(&a, b.join("back")).unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"a"), "expected a: {names:?}");
        assert!(names.contains(&"a.b"), "expected a.b: {names:?}");
        assert!(names.contains(&"a.b.mod"), "expected a.b.mod: {names:?}");
        assert!(names.contains(&"a.b.back"), "expected a.b.back: {names:?}");
        // a.b.back would recurse back into `a` (its own ancestor); that
        // descent must be suppressed rather than repeating a.b.mod forever.
        assert!(
            !names.contains(&"a.b.back.b"),
            "recursion through the parent-cycle must be suppressed: {names:?}"
        );
        assert!(
            modules.len() < 20,
            "module count must stay bounded for a parent-cycle, got {}: {:?}",
            modules.len(),
            names
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_handles_duplicate_symlink_aliases_to_same_target() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();

        let real_pkg = temp.path().join("_real_pkg");
        fs::create_dir_all(&real_pkg).unwrap();
        fs::write(real_pkg.join("__init__.py"), "").unwrap();
        fs::write(real_pkg.join("mod.py"), "").unwrap();

        // Two independent (non-ancestor) symlinks pointing at the same target.
        symlink(&real_pkg, temp.path().join("alias_one")).unwrap();
        symlink(&real_pkg, temp.path().join("alias_two")).unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        // Both aliases are represented, and since neither is an ancestor of
        // the other, both are fully scanned (documented policy: ancestor-only
        // cycle detection, not whole-scan canonical deduplication).
        assert!(
            names.contains(&"alias_one"),
            "expected alias_one: {names:?}"
        );
        assert!(
            names.contains(&"alias_two"),
            "expected alias_two: {names:?}"
        );
        assert!(
            names.contains(&"alias_one.mod"),
            "alias_one's target should be fully scanned: {names:?}"
        );
        assert!(
            names.contains(&"alias_two.mod"),
            "alias_two's target should be fully scanned: {names:?}"
        );
    }

    // =========================================================================
    // Issue #405: ABI/platform-tagged .so/.pyd extension modules must be
    // recognized by their logical import name, not just plain foo.so/foo.pyd.
    // =========================================================================

    #[test]
    fn extension_module_stem_strips_recognized_abi_tags() {
        assert_eq!(extension_module_stem("foo.so", ".so"), Some("foo"));
        assert_eq!(
            extension_module_stem("alpha.cpython-312-x86_64-linux-gnu.so", ".so"),
            Some("alpha")
        );
        assert_eq!(extension_module_stem("beta.abi3.so", ".so"), Some("beta"));
        assert_eq!(
            extension_module_stem("gamma.cpython-312-darwin.so", ".so"),
            Some("gamma")
        );
        assert_eq!(
            extension_module_stem("delta.cp312-win_amd64.pyd", ".pyd"),
            Some("delta")
        );
        assert_eq!(extension_module_stem("plain.pyd", ".pyd"), Some("plain"));
        // Unrecognized "tag" (not a known ABI pattern) — the whole remainder
        // is treated as the stem, same as before #405.
        assert_eq!(extension_module_stem("foo.bar.so", ".so"), Some("foo.bar"));
        // Wrong extension entirely.
        assert_eq!(extension_module_stem("foo.py", ".so"), None);
    }

    #[test]
    fn test_scan_reports_logical_name_for_abi_tagged_extensions() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("mods")).unwrap();
        let mods = temp.path().join("mods");
        fs::write(mods.join("alpha.cpython-312-x86_64-linux-gnu.so"), b"").unwrap();
        fs::write(mods.join("beta.abi3.so"), b"").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(&mods);

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.contains(&"alpha"),
            "expected logical name 'alpha', not the ABI-tagged filename stem: {names:?}"
        );
        assert!(
            names.contains(&"beta"),
            "expected logical name 'beta': {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("cpython") || n.contains("abi3")),
            "ABI tag must not leak into the reported module name: {names:?}"
        );
        let alpha = modules.iter().find(|m| m.name == "alpha").unwrap();
        assert_eq!(alpha.module_type, ModuleType::Extension);
    }

    #[test]
    fn test_scan_reports_logical_name_for_nested_package_extension() {
        let temp = TempDir::new().unwrap();
        let pkg = temp.path().join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("__init__.py"), "").unwrap();
        fs::write(pkg.join("_core.cpython-312-darwin.so"), b"").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let modules = finder.scan_directory(temp.path());

        let names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
        assert!(
            names.contains(&"pkg._core"),
            "expected nested logical name 'pkg._core': {names:?}"
        );
    }

    #[test]
    fn test_find_module_locates_abi_tagged_extension() {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("alpha.cpython-312-x86_64-linux-gnu.so"),
            b"",
        )
        .unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("alpha");

        let module = result
            .module
            .expect("find_module should locate the ABI-tagged extension");
        assert_eq!(module.module_type, ModuleType::Extension);
        assert_eq!(
            module.path,
            temp.path().join("alpha.cpython-312-x86_64-linux-gnu.so")
        );
    }

    #[test]
    fn test_find_module_locates_abi3_extension() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("beta.abi3.so"), b"").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("beta");

        let module = result
            .module
            .expect("find_module should locate the abi3-tagged extension");
        assert_eq!(module.module_type, ModuleType::Extension);
    }

    // =========================================================================
    // Issue #406: a concrete module/package must not be masked by a sibling
    // namespace-package directory of the same name.
    // =========================================================================

    #[test]
    fn test_find_module_prefers_regular_module_over_sibling_namespace_dir() {
        let temp = TempDir::new().unwrap();

        // foo/ (no __init__.py -- would-be namespace dir) AND foo.py side by side.
        let foo_dir = temp.path().join("foo");
        fs::create_dir_all(&foo_dir).unwrap();
        fs::write(foo_dir.join("arbitrary_file.txt"), "").unwrap();
        fs::write(temp.path().join("foo.py"), "# real module").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("foo");

        let module = result
            .module
            .expect("find_module should locate foo.py, matching CPython");
        assert_eq!(
            module.module_type,
            ModuleType::Module,
            "foo.py must win over the sibling foo/ namespace directory"
        );
        assert!(
            module.path.ends_with("foo.py"),
            "path was {:?}",
            module.path
        );
    }

    #[test]
    fn test_find_module_prefers_regular_package_over_sibling_module() {
        let temp = TempDir::new().unwrap();

        // foo/__init__.py (regular package) AND foo.py side by side.
        let foo_dir = temp.path().join("foo");
        fs::create_dir_all(&foo_dir).unwrap();
        fs::write(foo_dir.join("__init__.py"), "# pkg").unwrap();
        fs::write(temp.path().join("foo.py"), "# shadowed module").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("foo");

        // CPython's FileFinder checks each loader in a fixed order per path
        // entry; the package (directory) importer runs before the source
        // (module) importer, so foo/__init__.py wins over foo.py here.
        let module = result.module.expect("find_module should locate foo");
        assert_eq!(
            module.module_type,
            ModuleType::Package,
            "foo/__init__.py must win over a sibling foo.py"
        );
    }

    #[test]
    fn test_find_module_namespace_only_directory_still_discoverable() {
        let temp = TempDir::new().unwrap();

        let ns_dir = temp.path().join("foo");
        fs::create_dir_all(&ns_dir).unwrap();
        // No __init__.py, no sibling foo.py -- pure namespace package.

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("foo");

        let module = result
            .module
            .expect("namespace-only directory should still be discoverable");
        assert_eq!(module.module_type, ModuleType::NamespacePackage);
    }

    #[test]
    fn test_find_module_concrete_match_in_later_path_beats_earlier_namespace_dir() {
        let path_a = TempDir::new().unwrap();
        let path_b = TempDir::new().unwrap();

        // path_a/foo/ is a namespace-only directory (checked first).
        fs::create_dir_all(path_a.path().join("foo")).unwrap();
        // path_b/foo.py is a concrete module (checked second).
        fs::write(path_b.path().join("foo.py"), "# real module").unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![path_a.path().to_path_buf(), path_b.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("foo");

        let module = result.module.expect("find_module should locate foo");
        assert_eq!(
            module.module_type,
            ModuleType::Module,
            "a concrete module in a later search path must not be shadowed by \
             a namespace directory found earlier (PEP 420 semantics): {:?}",
            module
        );
        assert!(
            module.path.ends_with("foo.py"),
            "path was {:?}",
            module.path
        );
    }

    #[test]
    fn test_find_module_falls_back_to_namespace_dir_when_no_search_path_has_concrete_match() {
        let path_a = TempDir::new().unwrap();
        let path_b = TempDir::new().unwrap();

        // Both search paths only contribute namespace portions -- no path
        // entry has a concrete foo.py/foo/__init__.py anywhere.
        fs::create_dir_all(path_a.path().join("foo")).unwrap();
        fs::create_dir_all(path_b.path().join("foo")).unwrap();

        let config = ModuleFinderConfig {
            enabled: true,
            search_paths: vec![path_a.path().to_path_buf(), path_b.path().to_path_buf()],
            ..Default::default()
        };
        let finder = ModuleFinder::new(config);
        let result = finder.find_module("foo");

        let module = result
            .module
            .expect("should fall back to the namespace candidate");
        assert_eq!(module.module_type, ModuleType::NamespacePackage);
    }

    // =========================================================================
    // Issue #407: adding a search path must not leave a previously cached
    // negative (not-found) lookup stale.
    // =========================================================================

    #[test]
    fn test_add_search_path_invalidates_cached_negative_lookup() {
        let path_a = TempDir::new().unwrap();
        let path_b = TempDir::new().unwrap();
        fs::write(path_b.path().join("foo.py"), "# real module").unwrap();

        let mut finder = ModuleFinder::new(ModuleFinderConfig {
            enabled: true,
            search_paths: vec![path_a.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        });

        // Miss under the initial search path list -- caches None.
        let miss = finder.find_module("foo");
        assert!(miss.module.is_none());
        assert_eq!(
            finder.cache_size(),
            1,
            "the negative result should be cached"
        );

        // path_b (which has foo.py) is added after the miss was cached.
        finder.add_search_path(path_b.path().to_path_buf());

        let hit = finder.find_module("foo");
        assert!(
            hit.module.is_some(),
            "adding a search path must invalidate the stale cached miss so foo.py \
             becomes discoverable, not stay permanently \"not found\""
        );
        assert_eq!(hit.module.unwrap().module_type, ModuleType::Module);
    }

    #[test]
    fn test_add_search_path_invalidates_unrelated_cached_positive_lookups_too() {
        let path_a = TempDir::new().unwrap();
        let path_b = TempDir::new().unwrap();
        fs::write(path_a.path().join("bar.py"), "# bar").unwrap();

        let mut finder = ModuleFinder::new(ModuleFinderConfig {
            enabled: true,
            search_paths: vec![path_a.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        });

        let hit = finder.find_module("bar");
        assert!(hit.module.is_some());
        assert_eq!(finder.cache_size(), 1);

        // Whole-cache invalidation (the documented policy) also clears
        // still-valid unrelated positive entries; a fresh lookup still finds
        // bar.py correctly afterward.
        finder.add_search_path(path_b.path().to_path_buf());
        assert_eq!(
            finder.cache_size(),
            0,
            "add_search_path should clear the whole cache"
        );

        let hit_again = finder.find_module("bar");
        assert!(hit_again.module.is_some());
    }

    #[test]
    fn test_add_search_path_duplicate_does_not_invalidate_cache() {
        let path_a = TempDir::new().unwrap();
        fs::write(path_a.path().join("bar.py"), "# bar").unwrap();

        let mut finder = ModuleFinder::new(ModuleFinderConfig {
            enabled: true,
            search_paths: vec![path_a.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        });

        finder.find_module("bar");
        assert_eq!(finder.cache_size(), 1);

        // Re-adding the same path changes nothing about the effective
        // configuration, so the cache is left alone.
        finder.add_search_path(path_a.path().to_path_buf());
        assert_eq!(
            finder.cache_size(),
            1,
            "a no-op add_search_path call must not clear still-valid cache entries"
        );
    }

    #[test]
    fn test_clear_cache_still_works_directly() {
        let temp = TempDir::new().unwrap();
        create_test_module_structure(temp.path());

        let finder = ModuleFinder::new(ModuleFinderConfig {
            enabled: true,
            search_paths: vec![temp.path().to_path_buf()],
            cache_enabled: true,
            ..Default::default()
        });

        finder.find_module("foo");
        assert_eq!(finder.cache_size(), 1);
        finder.clear_cache();
        assert_eq!(finder.cache_size(), 0);
    }
}
