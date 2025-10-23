//! # Path Security
//!
//! A comprehensive path validation and sanitization library to prevent path traversal attacks.
//!
//! ## Features
//!
//! - **Path Traversal Prevention**: Validates paths to ensure they don't escape base directories
//! - **Encoding Attack Protection**: Detects URL, UTF-8, Unicode, and other encoding tricks
//! - **Project Name Validation**: Ensures project names are safe for filesystem use
//! - **Filename Sanitization**: Validates filenames for suspicious patterns
//! - **Cross-Platform**: Handles both Unix and Windows path conventions including NTFS streams, UNC paths
//! - **Zero Dependencies**: Only depends on `anyhow` for error handling
//!
//! ## Usage
//!
//! ```rust
//! use path_security::{validate_path, validate_project_name, validate_filename};
//! use std::path::Path;
//!
//! # fn main() -> anyhow::Result<()> {
//! # use tempfile::TempDir;
//! # let temp_dir = TempDir::new()?;
//! # let base_dir = temp_dir.path();
//! // Validate a path against a base directory
//! let user_path = Path::new("user/document.pdf");
//! // Note: In production, base_dir would be your actual upload directory
//! # std::fs::create_dir(base_dir.join("user"))?;
//! let safe_path = validate_path(user_path, base_dir)?;
//!
//! // Validate a project name
//! let project_name = validate_project_name("my-awesome-project")?;
//!
//! // Validate a filename
//! let filename = validate_filename("report.pdf")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Guarantees
//!
//! - Blocks `..` directory traversal sequences (including encoded variants)
//! - Rejects absolute paths
//! - Prevents null byte injection
//! - Blocks environment variable expansion patterns
//! - Validates against OS reserved names (Windows)
//! - Detects URL encoding attacks (single and double encoding)
//! - Prevents UTF-8 overlong encoding attacks
//! - Blocks Unicode homoglyphs and zero-width characters
//! - Detects Windows-specific attacks (NTFS streams, UNC paths, trailing dots/spaces)
//! - Validates path separator variations and mixed separators
//! - Ensures paths resolve within base directory using canonicalization

pub mod attacks;
pub mod constants;
pub mod encoding;
pub mod validation;

// Re-export main functions
pub use validation::*;

// Re-export constants for advanced usage
pub use constants::*;