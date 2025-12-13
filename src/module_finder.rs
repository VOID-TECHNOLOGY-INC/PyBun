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

    /// Scan a directory in parallel and return all discovered modules.
    ///
    /// This is useful for pre-populating the cache or analyzing a package.
    pub fn scan_directory(&self, dir: &Path) -> Vec<ModuleInfo> {
        if !dir.is_dir() {
            return Vec::new();
        }

        let mut modules = Vec::new();
        self.scan_directory_recursive(dir, dir, "", &mut modules);
        modules
    }

    /// Recursively scan a directory for modules.
    fn scan_directory_recursive(
        &self,
        base_path: &Path,
        current_dir: &Path,
        prefix: &str,
        modules: &mut Vec<ModuleInfo>,
    ) {
        let Ok(entries) = std::fs::read_dir(current_dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };

            // Skip hidden files and __pycache__
            if file_name.starts_with('.') || file_name == "__pycache__" {
                continue;
            }

            if path.is_dir() {
                let module_name = if prefix.is_empty() {
                    file_name.clone()
                } else {
                    format!("{}.{}", prefix, file_name)
                };

                let init_py = path.join("__init__.py");
                if init_py.exists() {
                    modules.push(ModuleInfo {
                        name: module_name.clone(),
                        path: init_py,
                        module_type: ModuleType::Package,
                        search_path: base_path.to_path_buf(),
                    });
                }

                // Recurse into subdirectory
                self.scan_directory_recursive(base_path, &path, &module_name, modules);
            } else if path.is_file() {
                for ext in &self.config.extensions {
                    if file_name.ends_with(ext) {
                        let stem = file_name.strip_suffix(ext).unwrap();
                        if stem == "__init__" {
                            continue; // Already handled as package
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

    /// Parallel scan of multiple directories.
    ///
    /// Uses the configured number of threads to scan directories in parallel.
    pub fn parallel_scan(&self, directories: &[PathBuf]) -> Vec<ModuleInfo> {
        if directories.is_empty() {
            return Vec::new();
        }

        // For small number of directories, just scan sequentially
        if directories.len() <= 2 || self.config.threads <= 1 {
            return directories
                .iter()
                .flat_map(|d| self.scan_directory(d))
                .collect();
        }

        // Parallel scan using threads
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
}
