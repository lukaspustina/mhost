pub mod discover;
pub mod lints;
pub mod name_builder;
pub mod ordinal;
pub mod rdata_format;
pub mod record_type_info;
pub mod records;
pub mod reference_data;
pub mod rendering;
#[cfg(any(feature = "app-cli", feature = "app-tui"))]
pub mod resolver_args;
pub mod styles;
pub mod subdomain_spec;
