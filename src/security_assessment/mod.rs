//! Read-only security assessment inputs, independent of legacy audit behavior.

pub mod http;
pub mod inventory;
pub mod model;
pub mod osv;
pub mod qualification;
pub mod source;

pub use inventory::{InventoryRequest, observe_inventory};
pub use model::*;
pub use source::{AuthorizedQuery, DisclosureGrant, SourcePolicy, SourceRule, normalize_name};
