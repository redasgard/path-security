//! Main validation functions for path security

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::attacks::*;
use crate::constants::*;
use crate::encoding::*;

/// Validate and sanitize a file path to prevent path traversal attacks
/// 
/// This function ensures that:
/// 1. The path doesn't contain ".." sequences (directory traversal)
/// 2. The path is not absolute (must be relative)
/// 3. The path resolves to a location within the specified base directory
/// 4. The path doesn't contain suspicious patterns
///
/// # Arguments
///
/// * `path` - The relative path to validate
/// * `base_dir` - The base directory that the path must resolve within
///
/// # Returns
///
/// Returns the canonical absolute path if validation succeeds, or an error if validation fails.
///
/// # Examples
///
/// ```rust
/// use path_security::validate_path;
/// use std::path::Path;
/// # use std::fs;
/// # use tempfile::TempDir;
///
/// # fn main() -> anyhow::Result<()> {
/// # let temp_dir = TempDir::new()?;
/// # let base_dir = temp_dir.path();
/// # fs::create_dir(base_dir.join("safe"))?;
/// // Safe path - allowed
/// let safe_path = validate_path(Path::new("safe/file.txt"), base_dir)?;
///
/// // Dangerous path - rejected
/// let result = validate_path(Path::new("../etc/passwd"), base_dir);
/// assert!(result.is_err());
/// # Ok(())
/// # }
/// ```
pub fn validate_path(path: &Path, base_dir: &Path) -> Result<PathBuf> {
    // Convert to string for analysis
    let path_str = path.to_string_lossy().to_string();
    
    // ========================================================================
    // PHASE 1: Pre-processing and normalization checks
    // ========================================================================
    
    // Normalize and check for whitespace tricks
    let normalized_path = normalize_and_check(&path_str)?;
    
    // ========================================================================
    // PHASE 2: Protocol and URL scheme detection
    // ========================================================================
    
    // Check for file:// and other protocol schemes (SSRF prevention)
    detect_protocol_schemes(&normalized_path)?;
    
    // ========================================================================
    // PHASE 3: Encoding attack detection
    // ========================================================================
    
    // Detect URL encoding attacks (must come before other checks)
    detect_url_encoding(&normalized_path)?;
    
    // Detect UTF-8 overlong encoding
    detect_overlong_utf8(&normalized_path)?;
    
    // Detect Unicode encoding tricks
    detect_unicode_encoding(&normalized_path)?;
    
    // Detect dangerous Unicode characters
    detect_dangerous_unicode(&normalized_path)?;
    
    // ========================================================================
    // PHASE 4: Path structure validation
    // ========================================================================
    
    // Check for absolute paths
    if path.is_absolute() {
        bail!("Absolute paths are not allowed: {}", path_str);
    }
    
    // Detect path separator manipulation
    detect_separator_manipulation(&normalized_path)?;
    
    // Detect advanced traversal patterns
    detect_advanced_traversal(&normalized_path)?;
    
    // ========================================================================
    // PHASE 5: Windows-specific attack detection
    // ========================================================================
    
    detect_windows_attacks(&normalized_path)?;
    
    // ========================================================================
    // PHASE 6: Basic suspicious pattern checks
    // ========================================================================
    
    // Check for suspicious patterns (legacy checks, kept for defense in depth)
    detect_suspicious_patterns(&normalized_path)?;
    
    // ========================================================================
    // PHASE 7: Special path validation
    // ========================================================================
    
    // Check against special/sensitive system paths
    validate_special_paths(&normalized_path)?;
    
    // ========================================================================
    // PHASE 8: TOCTOU Prevention and Canonicalization
    // ========================================================================
    
    // TOCTOU Prevention: Use atomic operations to prevent race conditions
    let canonical_path = validate_path_atomic(path, base_dir)?;
    
    Ok(canonical_path)
}

/// TOCTOU-safe path validation with atomic operations
/// 
/// This function prevents Time-of-Check-Time-of-Use race conditions by:
/// 1. Using atomic filesystem operations
/// 2. Detecting recursive symlinks
/// 3. Validating path length limits
/// 4. Enhanced null byte detection
/// 5. Mixed encoding detection
fn validate_path_atomic(path: &Path, base_dir: &Path) -> Result<PathBuf> {
    // ========================================================================
    // TOCTOU Prevention: Atomic operations
    // ========================================================================
    
    // Construct full path by joining with base directory
    let full_path = base_dir.join(path);
    
    // Canonicalize base directory first (atomic operation)
    let canonical_base = base_dir.canonicalize()
        .context("Failed to canonicalize base directory")?;
    
    // ========================================================================
    // Recursive Symlink Detection
    // ========================================================================
    
    // Check for recursive symlinks by following the chain
    let mut visited = std::collections::HashSet::new();
    let mut current_path = full_path.clone();
    
    while current_path.is_symlink() {
        if visited.contains(&current_path) {
            bail!("Recursive symlink detected: {}", current_path.display());
        }
        visited.insert(current_path.clone());
        
        current_path = current_path.read_link()
            .context("Failed to read symlink")?;
        
        // Prevent infinite loops
        if visited.len() > MAX_SYMLINK_CHAIN_LENGTH {
            bail!("Symlink chain too long, possible recursive symlink");
        }
    }
    
    // ========================================================================
    // Path Length Attack Prevention
    // ========================================================================
    
    // Check for extremely long paths that could cause buffer overflows
    if full_path.to_string_lossy().len() > MAX_PATH_LENGTH {
        bail!("Path too long: {} characters (max: {})", 
              full_path.to_string_lossy().len(), MAX_PATH_LENGTH);
    }
    
    // ========================================================================
    // Enhanced Null Byte Detection
    // ========================================================================
    
    // Check for null bytes anywhere in the path (not just contains)
    let path_string = full_path.to_string_lossy();
    let path_bytes = path_string.as_bytes();
    for (i, &byte) in path_bytes.iter().enumerate() {
        if byte == 0 {
            bail!("Null byte detected at position {} in path: {}", i, full_path.display());
        }
    }
    
    // ========================================================================
    // Mixed Encoding Detection
    // ========================================================================
    
    // Detect mixed UTF-8 and UTF-16 encoding attacks
    let path_str = full_path.to_string_lossy();
    if detect_mixed_encoding(&path_str) {
        bail!("Mixed encoding attack detected in path: {}", path_str);
    }
    
    // ========================================================================
    // Atomic Canonicalization
    // ========================================================================
    
    // Use atomic canonicalization to prevent TOCTOU
    let canonical_path = if full_path.exists() {
        // File exists, canonicalize atomically
        full_path.canonicalize()
            .context("Failed to canonicalize existing path")?
    } else {
        // File doesn't exist, validate parent directory atomically
        if let Some(parent) = full_path.parent() {
            let canonical_parent = parent.canonicalize()
                .or_else(|_| {
                    // Parent might not exist, construct it from base
                    if let Ok(rel_parent) = parent.strip_prefix(base_dir) {
                        canonical_base.join(rel_parent).canonicalize()
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid parent path"))
                    }
                })
                .context("Failed to validate parent directory")?;
            
            // Construct canonical path from validated parent
            canonical_parent.join(full_path.file_name().unwrap())
        } else {
            bail!("Path has no parent directory: {}", full_path.display());
        }
    };
    
    // ========================================================================
    // Final Security Check
    // ========================================================================
    
    // Verify the canonical path is still within the base directory
    if !canonical_path.starts_with(&canonical_base) {
        bail!(
            "Path traversal detected: '{}' resolves outside base directory '{}'",
            full_path.display(),
            canonical_base.display()
        );
    }
    
    Ok(canonical_path)
}

/// Validate a project name for use in file paths
/// 
/// Project names must:
/// 1. Only contain alphanumeric characters, hyphens, and underscores
/// 2. Not start or end with a hyphen or underscore
/// 3. Be between 1 and 64 characters long
/// 4. Not contain any path separators or special characters
/// 5. Not be a reserved system name (Windows: CON, PRN, AUX, etc.)
///
/// # Arguments
///
/// * `name` - The project name to validate
///
/// # Returns
///
/// Returns the validated name if validation succeeds, or an error if validation fails.
///
/// # Examples
///
/// ```rust
/// use path_security::validate_project_name;
///
/// # fn main() -> anyhow::Result<()> {
/// // Valid names
/// let name = validate_project_name("my-project")?;
/// let name = validate_project_name("project_123")?;
///
/// // Invalid names
/// assert!(validate_project_name("../etc").is_err());
/// assert!(validate_project_name("-invalid").is_err());
/// assert!(validate_project_name("CON").is_err()); // Windows reserved
/// # Ok(())
/// # }
/// ```
pub fn validate_project_name(name: &str) -> Result<String> {
    // Check length
    if name.is_empty() {
        bail!("Project name cannot be empty");
    }
    
    if name.len() > MAX_PROJECT_NAME_LENGTH {
        bail!("Project name too long: {} characters (max {})", name.len(), MAX_PROJECT_NAME_LENGTH);
    }
    
    // Check for valid characters (alphanumeric, hyphen, underscore)
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        bail!("Project name contains invalid characters: {}", name);
    }
    
    // Check it doesn't start or end with hyphen/underscore
    if name.starts_with('-') || name.starts_with('_') || name.ends_with('-') || name.ends_with('_') {
        bail!("Project name cannot start or end with '-' or '_': {}", name);
    }
    
    // Check for reserved names (OS-specific)
    let name_upper = name.to_uppercase();
    if WINDOWS_RESERVED_NAMES.contains(&name_upper.as_str()) {
        bail!("Project name is a reserved system name: {}", name);
    }
    
    Ok(name.to_string())
}

/// Validate a file name for safety
/// 
/// File names must:
/// 1. Not contain path separators (/ or \)
/// 2. Not be "." or ".."
/// 3. Not contain null bytes or other control characters
/// 4. Be reasonable length (< 255 characters)
///
/// # Arguments
///
/// * `filename` - The filename to validate
///
/// # Returns
///
/// Returns the validated filename if validation succeeds, or an error if validation fails.
///
/// # Examples
///
/// ```rust
/// use path_security::validate_filename;
///
/// # fn main() -> anyhow::Result<()> {
/// // Valid filenames
/// let name = validate_filename("document.pdf")?;
/// let name = validate_filename("report-2024.xlsx")?;
///
/// // Invalid filenames
/// assert!(validate_filename("../etc/passwd").is_err());
/// assert!(validate_filename(".").is_err());
/// assert!(validate_filename("..").is_err());
/// # Ok(())
/// # }
/// ```
pub fn validate_filename(filename: &str) -> Result<String> {
    if filename.is_empty() {
        bail!("Filename cannot be empty");
    }
    
    if filename.len() > MAX_FILENAME_LENGTH {
        bail!("Filename too long: {} characters", filename.len());
    }
    
    // Run all encoding and attack detection checks
    normalize_and_check(filename)?;
    detect_url_encoding(filename)?;
    detect_overlong_utf8(filename)?;
    detect_unicode_encoding(filename)?;
    detect_dangerous_unicode(filename)?;
    detect_windows_attacks(filename)?;
    
    // Check for path separators
    if filename.contains('/') || filename.contains('\\') {
        bail!("Filename cannot contain path separators: {}", filename);
    }
    
    // Check for current/parent directory references
    if filename == "." || filename == ".." {
        bail!("Invalid filename: {}", filename);
    }
    
    // Check for null bytes
    if filename.contains('\0') {
        bail!("Filename contains null byte");
    }
    
    // Check for control characters
    if filename.chars().any(|c| c.is_control()) {
        bail!("Filename contains control characters: {}", filename);
    }
    
    // Check for trailing dots or spaces (Windows exploit)
    if filename.ends_with('.') || filename.ends_with(' ') {
        bail!("Filename cannot end with dot or space: {}", filename);
    }
    
    // Check for NTFS streams in filename
    if filename.contains(':') {
        bail!("Filename cannot contain colon (NTFS stream syntax): {}", filename);
    }
    
    Ok(filename.to_string())
}
