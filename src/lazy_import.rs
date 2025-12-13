//! Lazy import injection module.
//!
//! This module provides lazy import functionality to reduce Python startup time
//! by deferring module imports until they are actually used.
//!
//! ## Configuration
//! - Allowlist: Modules that are allowed to be lazily imported
//! - Denylist: Modules that must be eagerly imported (e.g., stdlib essentials)
//! - Fallback: CPython's native import system when lazy import fails

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Configuration for lazy import behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LazyImportConfig {
    /// Whether lazy imports are enabled.
    pub enabled: bool,
    /// Modules that should be lazily imported (if empty, all modules except denylist).
    pub allowlist: HashSet<String>,
    /// Modules that must be eagerly imported (stdlib essentials, etc.).
    pub denylist: HashSet<String>,
    /// Whether to fall back to CPython import on lazy import failure.
    pub fallback_to_cpython: bool,
    /// Log lazy import operations for diagnostics.
    pub log_imports: bool,
    /// Path to configuration file (for external config).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<PathBuf>,
}

impl Default for LazyImportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowlist: HashSet::new(),
            denylist: default_denylist(),
            fallback_to_cpython: true,
            log_imports: false,
            config_file: None,
        }
    }
}

/// Default denylist - modules that should never be lazily imported.
fn default_denylist() -> HashSet<String> {
    [
        // Core Python runtime
        "sys",
        "builtins",
        "importlib",
        "importlib.abc",
        "importlib.machinery",
        "importlib.util",
        "_frozen_importlib",
        "_frozen_importlib_external",
        // Critical stdlib modules
        "os",
        "os.path",
        "io",
        "abc",
        "types",
        "functools",
        "collections",
        "collections.abc",
        "warnings",
        "contextlib",
        "typing",
        // Modules with side effects
        "signal",
        "threading",
        "multiprocessing",
        "atexit",
        "gc",
        "traceback",
        "logging",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// A lazy module proxy that defers actual import until attribute access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LazyModule {
    /// The module name.
    pub name: String,
    /// Whether the module has been loaded.
    pub loaded: bool,
    /// Time of first access (for diagnostics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_access_ms: Option<u64>,
}

impl LazyModule {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            loaded: false,
            first_access_ms: None,
        }
    }
}

/// Result of checking if a module should be lazily imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LazyImportDecision {
    /// Module should be lazily imported.
    Lazy,
    /// Module should be eagerly imported.
    Eager,
    /// Module matches denylist - must be eager.
    Denied,
}

impl LazyImportConfig {
    /// Create a new config with lazy imports enabled and default settings.
    pub fn with_defaults() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Check if a module should be lazily imported.
    pub fn should_lazy_import(&self, module_name: &str) -> LazyImportDecision {
        if !self.enabled {
            return LazyImportDecision::Eager;
        }

        // Check denylist first (highest priority)
        if self.is_denied(module_name) {
            return LazyImportDecision::Denied;
        }

        // If allowlist is non-empty, only those modules can be lazy
        if !self.allowlist.is_empty() {
            if self.is_allowed(module_name) {
                return LazyImportDecision::Lazy;
            }
            return LazyImportDecision::Eager;
        }

        // Default: all non-denied modules are lazy
        LazyImportDecision::Lazy
    }

    /// Check if a module is in the denylist.
    pub fn is_denied(&self, module_name: &str) -> bool {
        // Check exact match
        if self.denylist.contains(module_name) {
            return true;
        }

        // Check if any parent is denied (e.g., "os" denies "os.path")
        let parts: Vec<&str> = module_name.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[..i].join(".");
            if self.denylist.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Check if a module is in the allowlist.
    pub fn is_allowed(&self, module_name: &str) -> bool {
        // Check exact match
        if self.allowlist.contains(module_name) {
            return true;
        }

        // Check if any parent is allowed
        let parts: Vec<&str> = module_name.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[..i].join(".");
            if self.allowlist.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Add a module to the allowlist.
    pub fn allow(&mut self, module_name: impl Into<String>) {
        self.allowlist.insert(module_name.into());
    }

    /// Add a module to the denylist.
    pub fn deny(&mut self, module_name: impl Into<String>) {
        self.denylist.insert(module_name.into());
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse config: {}", e))
    }

    /// Save configuration to a TOML file.
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize config: {}", e))?;
        std::fs::write(path, content).map_err(|e| format!("failed to write config file: {}", e))
    }
}

/// Statistics about lazy import usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LazyImportStats {
    /// Total modules that were lazily imported.
    pub lazy_imports: usize,
    /// Total modules that were eagerly imported.
    pub eager_imports: usize,
    /// Modules denied from lazy import.
    pub denied_imports: usize,
    /// Failed lazy imports (that fell back to CPython).
    pub fallback_imports: usize,
    /// Total time saved by lazy imports (estimated, in ms).
    pub estimated_time_saved_ms: u64,
}

impl LazyImportStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_lazy(&mut self) {
        self.lazy_imports += 1;
    }

    pub fn record_eager(&mut self) {
        self.eager_imports += 1;
    }

    pub fn record_denied(&mut self) {
        self.denied_imports += 1;
    }

    pub fn record_fallback(&mut self) {
        self.fallback_imports += 1;
    }
}

/// Generate Python code for lazy import injection.
///
/// This generates a Python module that can be imported early in the Python
/// startup to enable lazy imports.
pub fn generate_lazy_import_python_code(config: &LazyImportConfig) -> String {
    let denylist_py: String = config
        .denylist
        .iter()
        .map(|m| format!("    \"{}\",", m))
        .collect::<Vec<_>>()
        .join("\n");

    let allowlist_py: String = if config.allowlist.is_empty() {
        "None  # All modules allowed".to_string()
    } else {
        format!(
            "{{\n{}\n}}",
            config
                .allowlist
                .iter()
                .map(|m| format!("    \"{}\",", m))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };

    format!(
        r#""""
PyBun Lazy Import Module

This module provides lazy import functionality to reduce startup time.
Generated by PyBun - do not edit manually.
"""

import sys
import importlib
import importlib.abc
import importlib.util

# Configuration
_ENABLED = {enabled}
_FALLBACK = {fallback}
_LOG_IMPORTS = {log_imports}

_DENYLIST = {{
{denylist_py}
}}

_ALLOWLIST = {allowlist_py}


class LazyModule:
    """A proxy object that defers module import until first attribute access."""
    
    __slots__ = ('_name', '_module', '_loading')
    
    def __init__(self, name):
        object.__setattr__(self, '_name', name)
        object.__setattr__(self, '_module', None)
        object.__setattr__(self, '_loading', False)
    
    def _load(self):
        if object.__getattribute__(self, '_loading'):
            # Prevent infinite recursion
            raise ImportError(f"Circular lazy import detected for {{self._name}}")
        
        object.__setattr__(self, '_loading', True)
        try:
            if _LOG_IMPORTS:
                print(f"[pybun] Loading lazy module: {{self._name}}")
            module = importlib.import_module(self._name)
            object.__setattr__(self, '_module', module)
            return module
        finally:
            object.__setattr__(self, '_loading', False)
    
    def __getattr__(self, name):
        module = object.__getattribute__(self, '_module')
        if module is None:
            module = self._load()
        return getattr(module, name)
    
    def __setattr__(self, name, value):
        if name in ('_name', '_module', '_loading'):
            object.__setattr__(self, name, value)
        else:
            module = object.__getattribute__(self, '_module')
            if module is None:
                module = self._load()
            setattr(module, name, value)
    
    def __repr__(self):
        module = object.__getattribute__(self, '_module')
        if module is None:
            return f"<lazy module '{{self._name}}' (not loaded)>"
        return repr(module)


class LazyFinder(importlib.abc.MetaPathFinder):
    """Meta path finder that returns lazy loaders for eligible modules."""
    
    def find_spec(self, fullname, path, target=None):
        if not _ENABLED:
            return None
        
        # Check denylist
        if fullname in _DENYLIST:
            return None
        
        # Check parent modules in denylist
        parts = fullname.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[:i])
            if parent in _DENYLIST:
                return None
        
        # Check allowlist if specified
        if _ALLOWLIST is not None:
            if fullname not in _ALLOWLIST:
                # Check parent modules
                allowed = False
                for i in range(1, len(parts)):
                    parent = '.'.join(parts[:i])
                    if parent in _ALLOWLIST:
                        allowed = True
                        break
                if not allowed:
                    return None
        
        # Create a lazy loader spec
        return importlib.machinery.ModuleSpec(
            fullname,
            LazyLoader(fullname),
            is_package=False
        )


class LazyLoader(importlib.abc.Loader):
    """Loader that creates lazy module proxies."""
    
    def __init__(self, name):
        self.name = name
    
    def create_module(self, spec):
        return LazyModule(self.name)
    
    def exec_module(self, module):
        # Lazy modules don't execute until accessed
        pass


def install():
    """Install the lazy import finder."""
    if _ENABLED:
        # Insert at the beginning, before other finders
        sys.meta_path.insert(0, LazyFinder())
        if _LOG_IMPORTS:
            print("[pybun] Lazy import finder installed")


def is_lazy(module):
    """Check if a module is a lazy proxy."""
    return isinstance(module, LazyModule)


def force_load(module):
    """Force a lazy module to load immediately."""
    if isinstance(module, LazyModule):
        module._load()
        return module._module
    return module


# Auto-install if this module is imported
install()
"#,
        enabled = if config.enabled { "True" } else { "False" },
        fallback = if config.fallback_to_cpython {
            "True"
        } else {
            "False"
        },
        log_imports = if config.log_imports { "True" } else { "False" },
        denylist_py = denylist_py,
        allowlist_py = allowlist_py,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_disabled() {
        let config = LazyImportConfig::default();
        assert!(!config.enabled);
        assert!(config.fallback_to_cpython);
        assert!(!config.denylist.is_empty());
    }

    #[test]
    fn test_with_defaults_enabled() {
        let config = LazyImportConfig::with_defaults();
        assert!(config.enabled);
    }

    #[test]
    fn test_default_denylist_contains_core_modules() {
        let denylist = default_denylist();
        assert!(denylist.contains("sys"));
        assert!(denylist.contains("os"));
        assert!(denylist.contains("importlib"));
        assert!(denylist.contains("builtins"));
    }

    #[test]
    fn test_should_lazy_import_when_disabled() {
        let config = LazyImportConfig::default();
        assert_eq!(
            config.should_lazy_import("numpy"),
            LazyImportDecision::Eager
        );
    }

    #[test]
    fn test_should_lazy_import_denied_module() {
        let config = LazyImportConfig::with_defaults();
        assert_eq!(config.should_lazy_import("sys"), LazyImportDecision::Denied);
        assert_eq!(config.should_lazy_import("os"), LazyImportDecision::Denied);
    }

    #[test]
    fn test_should_lazy_import_allowed_module() {
        let config = LazyImportConfig::with_defaults();
        assert_eq!(config.should_lazy_import("numpy"), LazyImportDecision::Lazy);
        assert_eq!(
            config.should_lazy_import("pandas"),
            LazyImportDecision::Lazy
        );
    }

    #[test]
    fn test_submodule_denied_by_parent() {
        let config = LazyImportConfig::with_defaults();
        // os is in denylist, so os.path should be denied
        assert_eq!(
            config.should_lazy_import("os.path"),
            LazyImportDecision::Denied
        );
    }

    #[test]
    fn test_allowlist_mode() {
        let mut config = LazyImportConfig::with_defaults();
        config.allow("numpy");
        config.allow("pandas");

        // Allowed modules
        assert_eq!(config.should_lazy_import("numpy"), LazyImportDecision::Lazy);
        assert_eq!(
            config.should_lazy_import("numpy.core"),
            LazyImportDecision::Lazy
        );
        assert_eq!(
            config.should_lazy_import("pandas"),
            LazyImportDecision::Lazy
        );

        // Not in allowlist
        assert_eq!(
            config.should_lazy_import("scipy"),
            LazyImportDecision::Eager
        );
    }

    #[test]
    fn test_is_denied() {
        let config = LazyImportConfig::with_defaults();
        assert!(config.is_denied("sys"));
        assert!(config.is_denied("os"));
        assert!(config.is_denied("os.path")); // Parent is denied
        assert!(!config.is_denied("numpy"));
    }

    #[test]
    fn test_is_allowed_with_empty_allowlist() {
        let config = LazyImportConfig::with_defaults();
        // Empty allowlist means nothing is explicitly allowed
        assert!(!config.is_allowed("numpy"));
    }

    #[test]
    fn test_is_allowed_with_allowlist() {
        let mut config = LazyImportConfig::with_defaults();
        config.allow("numpy");

        assert!(config.is_allowed("numpy"));
        assert!(config.is_allowed("numpy.core"));
        assert!(!config.is_allowed("pandas"));
    }

    #[test]
    fn test_lazy_import_stats() {
        let mut stats = LazyImportStats::new();
        stats.record_lazy();
        stats.record_lazy();
        stats.record_eager();
        stats.record_denied();
        stats.record_fallback();

        assert_eq!(stats.lazy_imports, 2);
        assert_eq!(stats.eager_imports, 1);
        assert_eq!(stats.denied_imports, 1);
        assert_eq!(stats.fallback_imports, 1);
    }

    #[test]
    fn test_lazy_module_creation() {
        let module = LazyModule::new("numpy");
        assert_eq!(module.name, "numpy");
        assert!(!module.loaded);
        assert!(module.first_access_ms.is_none());
    }

    #[test]
    fn test_generate_python_code() {
        let config = LazyImportConfig::with_defaults();
        let code = generate_lazy_import_python_code(&config);

        assert!(code.contains("class LazyModule"));
        assert!(code.contains("class LazyFinder"));
        assert!(code.contains("class LazyLoader"));
        assert!(code.contains("_ENABLED = True"));
        assert!(code.contains("sys"));
    }

    #[test]
    fn test_generate_python_code_with_allowlist() {
        let mut config = LazyImportConfig::with_defaults();
        config.allow("numpy");

        let code = generate_lazy_import_python_code(&config);
        assert!(code.contains("numpy"));
    }

    #[test]
    fn test_config_serialization() {
        let config = LazyImportConfig::with_defaults();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: LazyImportConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.fallback_to_cpython, deserialized.fallback_to_cpython);
    }

    #[test]
    fn test_add_and_deny_modules() {
        let mut config = LazyImportConfig::with_defaults();

        config.allow("mymodule");
        assert!(config.allowlist.contains("mymodule"));

        config.deny("dangerous_module");
        assert!(config.denylist.contains("dangerous_module"));
    }
}
