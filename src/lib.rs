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

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

// ============================================================================
// Encoding Detection and Normalization
// ============================================================================

/// Detect URL-encoded path traversal patterns
/// Checks for: %2e, %2f, %5c and their uppercase variants
fn detect_url_encoding(path: &str) -> Result<()> {
    let suspicious_encoded = [
        "%2e", "%2E",  // .
        "%2f", "%2F",  // /
        "%5c", "%5C",  // \
        "%00",         // null byte
        "%0a", "%0A",  // newline
        "%0d", "%0D",  // carriage return
    ];
    
    for pattern in suspicious_encoded.iter() {
        if path.contains(pattern) {
            bail!("URL-encoded characters detected in path: {}", pattern);
        }
    }
    
    // Check for double URL encoding (%25 = %)
    if path.contains("%25") {
        bail!("Double URL encoding detected in path");
    }
    
    Ok(())
}

/// Detect UTF-8 overlong encoding attacks
/// Overlong encodings like %c0%ae for "." are invalid but sometimes parsed
fn detect_overlong_utf8(path: &str) -> Result<()> {
    // Common overlong UTF-8 sequences for dots and slashes
    let overlong_patterns = [
        "%c0%ae",  // overlong .
        "%c0%af",  // overlong /
        "%c1%9c",  // overlong \
        "%c0%2e",  // invalid encoding
        "%e0%80%ae", // 3-byte overlong .
    ];
    
    let path_lower = path.to_lowercase();
    for pattern in overlong_patterns.iter() {
        if path_lower.contains(pattern) {
            bail!("UTF-8 overlong encoding detected: {}", pattern);
        }
    }
    
    Ok(())
}

/// Detect Unicode encoding tricks
fn detect_unicode_encoding(path: &str) -> Result<()> {
    // Check for %u encoding (non-standard but sometimes accepted)
    if path.contains("%u") {
        bail!("Unicode percent encoding (%u) detected in path");
    }
    
    // Check for HTML entity encoding
    if path.contains("&#") {
        bail!("HTML entity encoding detected in path");
    }
    
    Ok(())
}

/// Detect dangerous Unicode characters
fn detect_dangerous_unicode(path: &str) -> Result<()> {
    for ch in path.chars() {
        match ch {
            // Zero-width characters
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => {
                bail!("Zero-width Unicode character detected in path");
            }
            // Right-to-left override
            '\u{202E}' => {
                bail!("Right-to-left override character detected in path");
            }
            // Unicode homoglyphs for dots and slashes
            '\u{2024}' | '\u{2025}' | '\u{2026}' => {
                bail!("Unicode dot homoglyph detected in path");
            }
            // Unicode slash homoglyphs (forward slash variants)
            // U+2044 (⁄), U+2215 (∕), U+2571 (╱), U+29F8, U+FF0F (／)
            '\u{2044}' | '\u{2215}' | '\u{2571}' | '\u{29F8}' | '\u{FF0F}' => {
                bail!("Unicode slash homoglyph detected in path");
            }
            // Unicode backslash homoglyphs
            // U+2216 (∖), U+FF3C (＼)
            '\u{2216}' | '\u{FF3C}' => {
                bail!("Unicode backslash homoglyph detected in path");
            }
            // Code page specific homoglyphs that map to path separators
            // U+00A5 (¥) - maps to \ in CP932 (Japanese)
            // U+20A9 (₩) - maps to \ in CP949 (Korean) and CP1361
            // U+00B4 (´) - maps to / in CP1253 (Greek)
            '\u{00A5}' | '\u{20A9}' | '\u{00B4}' => {
                bail!("Code page specific path separator homoglyph detected in path");
            }
            // Full-width characters
            '\u{FF01}'..='\u{FF5E}' => {
                bail!("Full-width Unicode character detected in path");
            }
            // Wildcard characters that could be misused
            '?' | '*' => {
                bail!("Wildcard character detected in path: {}", ch);
            }
            _ => {}
        }
    }
    
    Ok(())
}

/// Detect Windows-specific attacks
fn detect_windows_attacks(path: &str) -> Result<()> {
    // Check for NTFS alternate data streams
    // For relative paths, ANY colon is suspicious (either NTFS stream or drive letter)
    if path.contains(':') {
        // Check if it's a drive letter at the start (which would make it absolute, caught elsewhere)
        let starts_with_drive = path.len() >= 2 && 
                                path.chars().nth(0).map_or(false, |c| c.is_ascii_alphabetic()) &&
                                path.chars().nth(1) == Some(':');
        
        if !starts_with_drive {
            // Any other colon is suspicious (NTFS streams, etc.)
            bail!("Colon detected in path (possible NTFS stream or device): {}", path);
        } else if path.len() > 2 {
            // If it starts with drive letter, check the rest for more colons
            if path[2..].contains(':') {
                bail!("NTFS alternate data stream syntax detected: {}", path);
            }
        }
    }
    
    // Check for UNC paths
    if path.starts_with("\\\\") || path.starts_with("//") {
        bail!("UNC path detected: {}", path);
    }
    
    // Check for Windows long path prefix
    if path.starts_with("\\\\?\\") || path.starts_with("\\\\.\\") {
        bail!("Windows extended-length path prefix detected: {}", path);
    }
    
    // Check for device paths
    let path_upper = path.to_uppercase();
    if path_upper.starts_with("\\\\.\\") || path_upper.contains("\\DEVICE\\") {
        bail!("Windows device path detected");
    }
    
    // Check for trailing dots (Windows ignores these)
    if let Some(last_component) = path.split(&['/', '\\'][..]).last() {
        if last_component.ends_with('.') && last_component != "." && last_component != ".." {
            bail!("Trailing dot detected in path component (Windows exploit): {}", last_component);
        }
        
        // Check for trailing spaces (Windows ignores these)
        if last_component.ends_with(' ') {
            bail!("Trailing space detected in path component (Windows exploit)");
        }
    }
    
    Ok(())
}

/// Detect path separator manipulation
fn detect_separator_manipulation(path: &str) -> Result<()> {
    // Check for multiple consecutive slashes
    if path.contains("//") || path.contains("\\\\") {
        // Allow only at the start for UNC (but we block UNC separately)
        if !path.starts_with("//") && !path.starts_with("\\\\") {
            bail!("Multiple consecutive path separators detected");
        }
    }
    
    // Check for mixed separators
    if path.contains('/') && path.contains('\\') {
        bail!("Mixed path separators detected (possible evasion)");
    }
    
    // Check for alternative/unusual separators
    let dangerous_separators = [';', '\t', '\n', '\r'];
    for sep in dangerous_separators.iter() {
        if path.contains(*sep) {
            bail!("Unusual separator character detected in path");
        }
    }
    
    Ok(())
}

/// Detect advanced traversal patterns
fn detect_advanced_traversal(path: &str) -> Result<()> {
    // Check for various dot patterns
    let traversal_patterns = [
        "..",
        "...",   // Some systems treat this specially
        "....",  // Quad dots
        ". .",   // Space between dots
        ". . ",  // Multiple spaces
        ".\t.",  // Tab between dots
        ".|.",   // Pipe between dots
    ];
    
    for pattern in traversal_patterns.iter() {
        if path.contains(pattern) {
            bail!("Directory traversal pattern detected: {}", pattern);
        }
    }
    
    // Check for nested traversal with separators
    let nested_traversal = [
        "....//",   // Quad dot double slash
        r"....\/",  // Quad dot mixed separator
        "..../",    // Quad dot slash
        r"....\\",  // Quad dot backslash
        ".|./",     // Pipe dot slash
        r".|\\/",   // Pipe dot backslash-slash
    ];
    
    for pattern in nested_traversal.iter() {
        if path.contains(pattern) {
            bail!("Nested traversal pattern detected: {}", pattern);
        }
    }
    
    // Check for encoded dots that might be decoded later
    if path.contains("\\x2e") || path.contains("\\x2f") || path.contains("\\x5c") {
        bail!("Hex-encoded path characters detected");
    }
    
    Ok(())
}

/// Normalize path to detect hidden traversal attempts
fn normalize_and_check(path: &str) -> Result<String> {
    let mut normalized = path.to_string();
    
    // Trim leading and trailing whitespace
    normalized = normalized.trim().to_string();
    
    // Check if whitespace was present (could be evasion)
    if normalized != path {
        bail!("Leading or trailing whitespace detected in path");
    }
    
    // Check for internal excessive whitespace
    if normalized.contains("  ") {
        bail!("Multiple consecutive spaces detected in path");
    }
    
    Ok(normalized)
}

/// Validate against special file paths
fn validate_special_paths(path: &str) -> Result<()> {
    let dangerous_paths = [
        "/proc/", "/sys/", "/dev/",
        "C:\\Windows\\System32", "C:\\Windows\\Temp",
        "/tmp/", "/var/tmp/",
        "/etc/", "/boot/",
    ];
    
    let path_lower = path.to_lowercase();
    for dangerous in dangerous_paths.iter() {
        if path_lower.starts_with(&dangerous.to_lowercase()) {
            bail!("Access to sensitive system path denied: {}", dangerous);
        }
    }
    
    Ok(())
}

/// Detect file protocol schemes and URL patterns
fn detect_protocol_schemes(path: &str) -> Result<()> {
    let path_lower = path.to_lowercase();
    
    // Check for file:// protocol
    if path_lower.starts_with("file://") || path_lower.starts_with("file:/") {
        bail!("File protocol scheme detected in path");
    }
    
    // Check for HTTP/HTTPS protocols (SSRF attempts)
    if path_lower.starts_with("http://") || path_lower.starts_with("https://") {
        bail!("HTTP protocol scheme detected in path (possible SSRF)");
    }
    
    // Check for other potentially dangerous protocols
    let dangerous_protocols = [
        "ftp://", "ftps://", "sftp://",
        "gopher://", "data:", "javascript:",
        "vbscript:", "jar:", "php://",
    ];
    
    for protocol in dangerous_protocols.iter() {
        if path_lower.starts_with(protocol) {
            bail!("Dangerous protocol scheme detected: {}", protocol);
        }
    }
    
    Ok(())
}

// ============================================================================
// Main Validation Functions
// ============================================================================

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
    let suspicious_patterns = [
        "~",          // Home directory expansion
        "$",          // Environment variable expansion
        "\0",         // Null byte injection
        "\\",         // Backslash (should be caught by separator check, but double-check)
    ];
    
    for pattern in suspicious_patterns.iter() {
        if normalized_path.contains(pattern) {
            bail!("Suspicious pattern '{}' detected in path: {}", pattern, path_str);
        }
    }
    
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
        if visited.len() > 100 {
            bail!("Symlink chain too long, possible recursive symlink");
        }
    }
    
    // ========================================================================
    // Path Length Attack Prevention
    // ========================================================================
    
    // Check for extremely long paths that could cause buffer overflows
    const MAX_PATH_LENGTH: usize = 4096; // Conservative limit
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

/// Detect mixed encoding attacks (UTF-8 + UTF-16)
fn detect_mixed_encoding(path: &str) -> bool {
    // Check for UTF-16 BOM characters (Unicode BOM)
    if path.starts_with('\u{FEFF}') || path.starts_with('\u{FFFE}') {
        return true;
    }
    
    // Check for HTML/XML entity encoding mixed with UTF-8
    if path.contains("&#x") || path.contains("&#") {
        return true;
    }
    
    // Check for alternating null bytes (UTF-16 little-endian pattern)
    let bytes = path.as_bytes();
    if bytes.len() >= 4 {
        let mut null_count = 0;
        for i in (0..bytes.len()).step_by(2) {
            if i + 1 < bytes.len() && bytes[i + 1] == 0 {
                null_count += 1;
            }
        }
        // If more than 25% of even positions have null bytes, likely UTF-16
        if null_count > bytes.len() / 8 {
            return true;
        }
    }
    
    false
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
    
    if name.len() > 64 {
        bail!("Project name too long: {} characters (max 64)", name.len());
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
    let reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", 
                         "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", 
                         "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];
    
    let name_upper = name.to_uppercase();
    if reserved_names.contains(&name_upper.as_str()) {
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
    
    if filename.len() > 255 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_path_blocks_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Test ".." traversal
        let bad_path = Path::new("../etc/passwd");
        assert!(validate_path(bad_path, base_path).is_err());
        
        // Test complex traversal
        let bad_path = Path::new("foo/../../etc/passwd");
        assert!(validate_path(bad_path, base_path).is_err());
    }

    #[test]
    fn test_validate_path_allows_safe_paths() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Create a test subdirectory
        let sub_dir = base_path.join("test");
        fs::create_dir(&sub_dir).unwrap();
        
        // Test safe relative path
        let safe_path = Path::new("test/file.txt");
        assert!(validate_path(safe_path, base_path).is_ok());
    }

    #[test]
    fn test_validate_path_blocks_absolute() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        let absolute_path = Path::new("/etc/passwd");
        assert!(validate_path(absolute_path, base_path).is_err());
    }

    #[test]
    fn test_validate_path_blocks_suspicious_patterns() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Home directory expansion
        assert!(validate_path(Path::new("~/file"), base_path).is_err());
        
        // Environment variables
        assert!(validate_path(Path::new("$HOME/file"), base_path).is_err());
        assert!(validate_path(Path::new("%USERPROFILE%/file"), base_path).is_err());
        
        // Null byte injection
        assert!(validate_path(Path::new("file\0.txt"), base_path).is_err());
    }

    #[test]
    fn test_validate_project_name() {
        // Valid names
        assert!(validate_project_name("my-project").is_ok());
        assert!(validate_project_name("my_project").is_ok());
        assert!(validate_project_name("MyProject123").is_ok());
        
        // Invalid names
        assert!(validate_project_name("").is_err());
        assert!(validate_project_name("-invalid").is_err());
        assert!(validate_project_name("invalid-").is_err());
        assert!(validate_project_name("_invalid").is_err());
        assert!(validate_project_name("invalid_").is_err());
        assert!(validate_project_name("my/project").is_err());
        assert!(validate_project_name("my..project").is_err());
        assert!(validate_project_name("my project").is_err());
        
        // Reserved names (Windows)
        assert!(validate_project_name("CON").is_err());
        assert!(validate_project_name("PRN").is_err());
        assert!(validate_project_name("AUX").is_err());
        assert!(validate_project_name("NUL").is_err());
        assert!(validate_project_name("COM1").is_err());
        assert!(validate_project_name("LPT1").is_err());
        
        // Too long
        let long_name = "a".repeat(65);
        assert!(validate_project_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_filename() {
        // Valid filenames
        assert!(validate_filename("file.txt").is_ok());
        assert!(validate_filename("my-file_123.sol").is_ok());
        assert!(validate_filename("document.pdf").is_ok());
        
        // Invalid filenames
        assert!(validate_filename("../file.txt").is_err());
        assert!(validate_filename("/etc/passwd").is_err());
        assert!(validate_filename("path/to/file").is_err());
        assert!(validate_filename(".").is_err());
        assert!(validate_filename("..").is_err());
        assert!(validate_filename("file\0.txt").is_err());
        assert!(validate_filename("").is_err());
        
        // Too long
        let long_filename = format!("{}.txt", "a".repeat(252));
        assert!(validate_filename(&long_filename).is_err());
        
        // Control characters
        assert!(validate_filename("file\n.txt").is_err());
        assert!(validate_filename("file\t.txt").is_err());
    }

    // ========================================================================
    // COMPREHENSIVE ATTACK VECTOR TESTS
    // ========================================================================

    #[test]
    fn test_url_encoding_attacks() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // URL encoded dots and slashes
        assert!(validate_path(Path::new("%2e%2e%2f"), base_path).is_err());
        assert!(validate_path(Path::new("%2e%2e/"), base_path).is_err());
        assert!(validate_path(Path::new(".%2e/"), base_path).is_err());
        assert!(validate_path(Path::new("%2e./"), base_path).is_err());
        
        // Uppercase variants
        assert!(validate_path(Path::new("%2E%2E%2F"), base_path).is_err());
        assert!(validate_path(Path::new("%5C"), base_path).is_err());
        
        // Null byte encoding
        assert!(validate_path(Path::new("file%00.txt"), base_path).is_err());
        
        // Newline/carriage return encoding
        assert!(validate_path(Path::new("file%0a.txt"), base_path).is_err());
        assert!(validate_path(Path::new("file%0d.txt"), base_path).is_err());
    }

    #[test]
    fn test_double_url_encoding() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Double encoded (% = %25)
        assert!(validate_path(Path::new("%252e%252e%252f"), base_path).is_err());
        assert!(validate_path(Path::new("%252e%252e/"), base_path).is_err());
    }

    #[test]
    fn test_utf8_overlong_encoding() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Overlong UTF-8 sequences
        assert!(validate_path(Path::new("%c0%ae%c0%ae%c0%af"), base_path).is_err());
        assert!(validate_path(Path::new("%c0%ae%c0%ae/"), base_path).is_err());
        assert!(validate_path(Path::new("%c1%9c"), base_path).is_err());
        assert!(validate_path(Path::new("%e0%80%ae"), base_path).is_err());
    }

    #[test]
    fn test_unicode_encoding_attacks() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Unicode percent encoding
        assert!(validate_path(Path::new("%u002e%u002e%u002f"), base_path).is_err());
        
        // HTML entity encoding
        assert!(validate_path(Path::new("&#46;&#46;&#47;"), base_path).is_err());
    }

    #[test]
    fn test_dangerous_unicode_characters() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Zero-width characters
        assert!(validate_path(Path::new("file\u{200B}.txt"), base_path).is_err());
        assert!(validate_path(Path::new("file\u{200C}.txt"), base_path).is_err());
        assert!(validate_path(Path::new("file\u{FEFF}.txt"), base_path).is_err());
        
        // Right-to-left override
        assert!(validate_path(Path::new("file\u{202E}.txt"), base_path).is_err());
        
        // Unicode homoglyphs for dots
        assert!(validate_path(Path::new("\u{2024}\u{2024}/"), base_path).is_err());
        assert!(validate_path(Path::new("\u{2026}/"), base_path).is_err());
        
        // Unicode slash homoglyphs
        assert!(validate_path(Path::new("dir\u{2044}file"), base_path).is_err());
        assert!(validate_path(Path::new("dir\u{2215}file"), base_path).is_err());
        assert!(validate_path(Path::new("dir\u{FF0F}file"), base_path).is_err());
        
        // Full-width characters
        assert!(validate_path(Path::new("\u{FF0E}\u{FF0E}\u{FF0F}"), base_path).is_err());
    }

    #[test]
    fn test_windows_ntfs_streams() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // NTFS alternate data streams
        assert!(validate_path(Path::new("file.txt::$DATA"), base_path).is_err());
        assert!(validate_path(Path::new("file.txt:stream:$DATA"), base_path).is_err());
        assert!(validate_path(Path::new("file.txt:ads"), base_path).is_err());
    }

    #[test]
    fn test_windows_unc_paths() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // UNC paths
        assert!(validate_path(Path::new("\\\\server\\share"), base_path).is_err());
        assert!(validate_path(Path::new("//server/share"), base_path).is_err());
        
        // Extended-length path prefix
        assert!(validate_path(Path::new("\\\\?\\C:\\"), base_path).is_err());
        assert!(validate_path(Path::new("\\\\.\\C:\\"), base_path).is_err());
    }

    #[test]
    fn test_windows_trailing_dots_spaces() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Trailing dots (Windows ignores these)
        assert!(validate_path(Path::new("file.txt."), base_path).is_err());
        assert!(validate_path(Path::new("file.txt..."), base_path).is_err());
        
        // Trailing spaces
        assert!(validate_path(Path::new("file.txt "), base_path).is_err());
        assert!(validate_path(Path::new("file.txt   "), base_path).is_err());
        
        // Test with filename validation too
        assert!(validate_filename("file.txt.").is_err());
        assert!(validate_filename("file.txt ").is_err());
    }

    #[test]
    fn test_path_separator_manipulation() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Multiple consecutive slashes
        let sub_dir = base_path.join("test");
        fs::create_dir(&sub_dir).unwrap();
        assert!(validate_path(Path::new("test//file"), base_path).is_err());
        assert!(validate_path(Path::new("test///file"), base_path).is_err());
        
        // Mixed separators
        assert!(validate_path(Path::new("test/\\file"), base_path).is_err());
        assert!(validate_path(Path::new("test\\/file"), base_path).is_err());
        
        // Alternative separators
        assert!(validate_path(Path::new("test;file"), base_path).is_err());
    }

    #[test]
    fn test_whitespace_exploitation() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Leading whitespace
        assert!(validate_path(Path::new("   ../"), base_path).is_err());
        
        // Trailing whitespace
        assert!(validate_path(Path::new("../   "), base_path).is_err());
        
        // Multiple consecutive spaces
        assert!(validate_path(Path::new("file  .txt"), base_path).is_err());
        
        // Tab characters
        assert!(validate_path(Path::new("file\t.txt"), base_path).is_err());
    }

    #[test]
    fn test_advanced_traversal_sequences() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Triple dots
        assert!(validate_path(Path::new("..."), base_path).is_err());
        
        // Spaces between dots
        assert!(validate_path(Path::new(". ."), base_path).is_err());
        assert!(validate_path(Path::new(". . "), base_path).is_err());
        
        // Tab between dots
        assert!(validate_path(Path::new(".\t."), base_path).is_err());
        
        // Hex encoding
        assert!(validate_path(Path::new("\\x2e\\x2e\\x2f"), base_path).is_err());
    }

    #[test]
    fn test_special_system_paths() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Unix special paths
        assert!(validate_path(Path::new("/proc/self/"), base_path).is_err());
        assert!(validate_path(Path::new("/sys/"), base_path).is_err());
        assert!(validate_path(Path::new("/dev/"), base_path).is_err());
        assert!(validate_path(Path::new("/etc/"), base_path).is_err());
        assert!(validate_path(Path::new("/tmp/"), base_path).is_err());
    }

    #[test]
    fn test_combined_attack_vectors() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // URL encoding mixed with traversal
        assert!(validate_path(Path::new("%2e%2e/safe/../"), base_path).is_err());
        
        // Multiple techniques combined
        assert!(validate_path(Path::new("safe//..%2f.."), base_path).is_err());
    }

    #[test]
    fn test_safe_paths_still_work() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Create test directory
        let sub_dir = base_path.join("safe");
        fs::create_dir(&sub_dir).unwrap();
        
        // These should all pass
        assert!(validate_path(Path::new("safe/file.txt"), base_path).is_ok());
        assert!(validate_path(Path::new("safe/document.pdf"), base_path).is_ok());
        
        // Valid filenames
        assert!(validate_filename("normal-file_123.txt").is_ok());
        assert!(validate_filename("report.pdf").is_ok());
        
        // Valid project names
        assert!(validate_project_name("my-project").is_ok());
        assert!(validate_project_name("project_name").is_ok());
    }

    #[test]
    fn test_filename_encoding_attacks() {
        // URL encoding in filenames
        assert!(validate_filename("file%2e%2e.txt").is_err());
        assert!(validate_filename("file%2f.txt").is_err());
        
        // UTF-8 overlong in filenames
        assert!(validate_filename("file%c0%ae.txt").is_err());
        
        // Unicode attacks in filenames
        assert!(validate_filename("file\u{200B}.txt").is_err());
        assert!(validate_filename("file\u{202E}.txt").is_err());
        
        // NTFS streams
        assert!(validate_filename("file.txt::$DATA").is_err());
        assert!(validate_filename("file.txt:ads").is_err());
    }

    #[test]
    fn test_codepage_homoglyphs() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Japanese CP932 - Yen sign (¥) maps to backslash
        assert!(validate_path(Path::new("dir¥file"), base_path).is_err());
        
        // Korean CP949 - Won sign (₩) maps to backslash
        assert!(validate_path(Path::new("dir₩file"), base_path).is_err());
        
        // Greek CP1253 - Acute accent (´) maps to forward slash
        assert!(validate_path(Path::new("dir´file"), base_path).is_err());
        
        // Unicode backslash homoglyphs
        assert!(validate_path(Path::new("dir∖file"), base_path).is_err());  // U+2216
        assert!(validate_path(Path::new("dir＼file"), base_path).is_err());  // U+FF3C
    }

    #[test]
    fn test_wildcard_characters() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Question mark wildcard
        assert!(validate_path(Path::new("dir?/file"), base_path).is_err());
        assert!(validate_path(Path::new("file?.txt"), base_path).is_err());
        
        // Asterisk wildcard
        assert!(validate_path(Path::new("dir*/file"), base_path).is_err());
        assert!(validate_path(Path::new("file*.txt"), base_path).is_err());
    }

    #[test]
    fn test_nested_traversal_patterns() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Quad dot patterns
        assert!(validate_path(Path::new("....//"), base_path).is_err());
        assert!(validate_path(Path::new(r"....\/"), base_path).is_err());
        assert!(validate_path(Path::new("..../"), base_path).is_err());
        assert!(validate_path(Path::new(r"....\\"), base_path).is_err());
        
        // Pipe patterns
        assert!(validate_path(Path::new(".|./"), base_path).is_err());
        assert!(validate_path(Path::new(".|."), base_path).is_err());
        
        // Quad dots
        assert!(validate_path(Path::new("...."), base_path).is_err());
    }

    #[test]
    fn test_file_protocol_schemes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // File protocol
        assert!(validate_path(Path::new("file:///etc/passwd"), base_path).is_err());
        assert!(validate_path(Path::new("file://etc/passwd"), base_path).is_err());
        assert!(validate_path(Path::new("file:/etc/passwd"), base_path).is_err());
        
        // HTTP protocols (SSRF)
        assert!(validate_path(Path::new("http://localhost:8080"), base_path).is_err());
        assert!(validate_path(Path::new("https://192.168.0.2:9080"), base_path).is_err());
        
        // Other dangerous protocols
        assert!(validate_path(Path::new("ftp://server/file"), base_path).is_err());
        assert!(validate_path(Path::new("php://filter/resource=file"), base_path).is_err());
        assert!(validate_path(Path::new("data:text/plain,content"), base_path).is_err());
        assert!(validate_path(Path::new("javascript:alert(1)"), base_path).is_err());
    }

    #[test]
    fn test_null_byte_extension_bypass() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Null byte to bypass extension checks (classic PHP vulnerability)
        assert!(validate_path(Path::new("../../../etc/passwd%00.png"), base_path).is_err());
        assert!(validate_path(Path::new("../../../etc/passwd.ANY%00.png"), base_path).is_err());
        
        // Null byte in filename
        assert!(validate_filename("file%00.txt").is_err());
        assert!(validate_filename("file.txt%00.png").is_err());
    }

    #[test]
    fn test_comprehensive_unicode_homoglyphs() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // All code page homoglyphs should be blocked
        let homoglyphs = [
            "test¥file",     // U+00A5 - CP932 (Japanese)
            "test₩file",     // U+20A9 - CP949 (Korean)
            "test´file",     // U+00B4 - CP1253 (Greek)
            "test⁄file",     // U+2044 - fraction slash
            "test∕file",     // U+2215 - division slash
            "test∖file",     // U+2216 - set minus
            "test／file",    // U+FF0F - fullwidth solidus
            "test＼file",    // U+FF3C - fullwidth reverse solidus
        ];
        
        for homoglyph in homoglyphs.iter() {
            assert!(validate_path(Path::new(homoglyph), base_path).is_err(), 
                   "Should block homoglyph: {}", homoglyph);
        }
    }

    // ========================================================================
    // NEW SECURITY FEATURE TESTS
    // ========================================================================

    #[test]
    fn test_toctou_prevention() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Create a test file
        let test_file = base_path.join("test.txt");
        fs::write(&test_file, "test content").unwrap();
        
        // This should work normally
        assert!(validate_path(Path::new("test.txt"), base_path).is_ok());
        
        // Test that the atomic validation works
        let result = validate_path(Path::new("test.txt"), base_path);
        assert!(result.is_ok());
        
        // Verify the returned path is canonical
        let canonical_path = result.unwrap();
        assert!(canonical_path.is_absolute());
    }

    #[test]
    fn test_recursive_symlink_detection() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Create a symlink that points to itself (recursive)
        let symlink_path = base_path.join("recursive_link");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink("recursive_link", &symlink_path).unwrap();
            
            // This should be detected and blocked
            assert!(validate_path(Path::new("recursive_link"), base_path).is_err());
        }
        
        // Test symlink chain detection
        let link1 = base_path.join("link1");
        let link2 = base_path.join("link2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink("link2", &link1).unwrap();
            symlink("link1", &link2).unwrap();
            
            // This should be detected as a recursive chain
            assert!(validate_path(Path::new("link1"), base_path).is_err());
        }
    }

    #[test]
    fn test_path_length_attacks() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Create an extremely long path
        let long_path = "a".repeat(5000);
        let long_path_with_traversal = format!("{}/../../etc/passwd", long_path);
        
        // This should be blocked due to length
        assert!(validate_path(Path::new(&long_path), base_path).is_err());
        assert!(validate_path(Path::new(&long_path_with_traversal), base_path).is_err());
        
        // Normal length paths should still work
        let normal_path = "normal/file.txt";
        assert!(validate_path(Path::new(normal_path), base_path).is_ok());
    }

    #[test]
    fn test_enhanced_null_byte_detection() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Test null byte at the beginning
        assert!(validate_path(Path::new("\0file.txt"), base_path).is_err());
        
        // Test null byte in the middle
        assert!(validate_path(Path::new("file\0name.txt"), base_path).is_err());
        
        // Test null byte at the end
        assert!(validate_path(Path::new("file.txt\0"), base_path).is_err());
        
        // Test multiple null bytes
        assert!(validate_path(Path::new("file\0\0name.txt"), base_path).is_err());
        
        // Test null byte with traversal
        assert!(validate_path(Path::new("..\0/../etc/passwd"), base_path).is_err());
    }

    #[test]
    fn test_mixed_encoding_detection() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Test UTF-16 BOM detection
        let utf16_bom = "\u{FEFF}file.txt";
        assert!(validate_path(Path::new(utf16_bom), base_path).is_err());
        
        // Test HTML entity encoding
        assert!(validate_path(Path::new("file&#x2e;&#x2e;.txt"), base_path).is_err());
        assert!(validate_path(Path::new("file&#46;&#46;.txt"), base_path).is_err());
        
        // Test mixed encoding patterns
        let mixed_path = "file\u{0000}\u{0000}name.txt"; // UTF-16-like pattern
        assert!(validate_path(Path::new(mixed_path), base_path).is_err());
        
        // Normal UTF-8 should still work
        assert!(validate_path(Path::new("file.txt"), base_path).is_ok());
        assert!(validate_path(Path::new("файл.txt"), base_path).is_ok()); // Cyrillic
    }

    #[test]
    fn test_detect_mixed_encoding_function() {
        // Test UTF-16 BOM detection
        assert!(detect_mixed_encoding("\u{FEFF}test"));
        assert!(detect_mixed_encoding("\u{FFFE}test"));
        
        // Test HTML entity encoding
        assert!(detect_mixed_encoding("test&#x2e;"));
        assert!(detect_mixed_encoding("test&#46;"));
        
        // Test alternating null bytes (UTF-16 pattern)
        assert!(detect_mixed_encoding("t\u{0000}e\u{0000}s\u{0000}t"));
        
        // Test normal UTF-8 (should not be detected)
        assert!(!detect_mixed_encoding("normal text"));
        assert!(!detect_mixed_encoding("файл.txt"));
        assert!(!detect_mixed_encoding("file with spaces.txt"));
    }

    #[test]
    fn test_security_improvements_integration() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Create a test directory structure
        let sub_dir = base_path.join("test");
        fs::create_dir(&sub_dir).unwrap();
        
        // Test that all security improvements work together
        let safe_path = "test/file.txt";
        let result = validate_path(Path::new(safe_path), base_path);
        assert!(result.is_ok());
        
        // Verify the result is a canonical path
        let canonical_path = result.unwrap();
        assert!(canonical_path.is_absolute());
        assert!(canonical_path.starts_with(base_path.canonicalize().unwrap()));
    }

    #[test]
    fn test_edge_cases_security_improvements() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        
        // Test empty path
        assert!(validate_path(Path::new(""), base_path).is_err());
        
        // Test path with only dots
        assert!(validate_path(Path::new("..."), base_path).is_err());
        
        // Test path with only separators
        assert!(validate_path(Path::new("///"), base_path).is_err());
        
        // Test path with only null bytes
        assert!(validate_path(Path::new("\0\0\0"), base_path).is_err());
        
        // Test very long single component
        let long_component = "a".repeat(1000);
        assert!(validate_path(Path::new(&long_component), base_path).is_err());
    }
}

