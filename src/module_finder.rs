//! Rust-based module finder for accelerated Python import resolution.
//!
//! This module provides a high-performance module finder that can replace
//! Python's default `sys.meta_path` entry for import resolution. It uses
//! parallel filesystem scanning to find modules quickly.
//!
//! The module finder is opt-in and guarded by a flag to allow fallback
//! to CPython's native import system when needed.

use std::collections::HashMap;
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
    pub fn add_search_path(&mut self, path: PathBuf) {
        if !self.config.search_paths.contains(&path) {
            self.config.search_paths.push(path);
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

        // Search in each path
        for search_path in &self.config.search_paths {
            if !search_path.exists() {
                continue;
            }

            searched_paths.push(search_path.clone());

            if let Some(module_info) = self.find_in_path(search_path, &module_parts) {
                // Cache the result
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
    fn find_in_path(&self, search_path: &Path, module_parts: &[&str]) -> Option<ModuleInfo> {
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

        // Check for package (directory with __init__.py)
        let package_dir = current_path.join(last_part);
        if package_dir.is_dir() {
            let init_py = package_dir.join("__init__.py");
            if init_py.exists() {
                return Some(ModuleInfo {
                    name: module_name,
                    path: init_py,
                    module_type: ModuleType::Package,
                    search_path: search_path.to_path_buf(),
                });
            }

            // Check for namespace package (PEP 420)
            // A directory without __init__.py is a namespace package
            return Some(ModuleInfo {
                name: module_name,
                path: package_dir,
                module_type: ModuleType::NamespacePackage,
                search_path: search_path.to_path_buf(),
            });
        }

        // Check for module files
        for ext in &self.config.extensions {
            let module_file = current_path.join(format!("{}{}", last_part, ext));
            if module_file.is_file() {
                let module_type = if ext == ".so" || ext == ".pyd" {
                    ModuleType::Extension
                } else {
                    ModuleType::Module
                };

                return Some(ModuleInfo {
                    name: module_name,
                    path: module_file,
                    module_type,
                    search_path: search_path.to_path_buf(),
                });
            }
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
        self.scan_directory_inner(dir, dir, "", true)
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
    fn scan_directory_inner(
        &self,
        base_path: &Path,
        dir: &Path,
        prefix: &str,
        parallel: bool,
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
            let effective_is_dir;
            let effective_is_file;
            if raw_ft.is_symlink() {
                let Ok(meta) = path.metadata() else { continue };
                effective_is_dir = meta.is_dir();
                effective_is_file = meta.is_file();
            } else {
                effective_is_dir = raw_ft.is_dir();
                effective_is_file = raw_ft.is_file();
            }

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
                    if let Some(stem) = file_name.strip_suffix(ext.as_str()) {
                        if stem == "__init__" {
                            break; // already emitted as package above
                        }
                        let module_name = if prefix.is_empty() {
                            stem.to_string()
                        } else {
                            format!("{}.{}", prefix, stem)
                        };
                        let module_type = if ext == ".so" || ext == ".pyd" {
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
        }

        // Dispatch subdirectory traversal: parallel only at the top-level call so
        // that the total number of live threads stays bounded by the top-level
        // subdirectory count (≤ PARALLEL_SUBDIR_THRESHOLD or the dir's width).
        if parallel && subdirs.len() > PARALLEL_SUBDIR_THRESHOLD && self.config.threads > 1 {
            let sub_results: Vec<Vec<ModuleInfo>> = thread::scope(|s| {
                let handles: Vec<_> = subdirs
                    .iter()
                    .map(|(path, name)| {
                        // Recursive calls use parallel=false to prevent unbounded spawning.
                        s.spawn(|| self.scan_directory_inner(base_path, path, name, false))
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
                modules.extend(self.scan_directory_inner(base_path, path, name, false));
            }
        }

        modules
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
}
