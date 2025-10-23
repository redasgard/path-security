//! Attack pattern detection for path security

use anyhow::{bail, Result};

use crate::constants::*;

/// Detect Windows-specific attacks
pub fn detect_windows_attacks(path: &str) -> Result<()> {
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
pub fn detect_separator_manipulation(path: &str) -> Result<()> {
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
    for sep in DANGEROUS_SEPARATORS.iter() {
        if path.contains(*sep) {
            bail!("Unusual separator character detected in path");
        }
    }
    
    Ok(())
}

/// Detect advanced traversal patterns
pub fn detect_advanced_traversal(path: &str) -> Result<()> {
    // Check for various dot patterns
    for pattern in TRAVERSAL_PATTERNS.iter() {
        if path.contains(pattern) {
            bail!("Directory traversal pattern detected: {}", pattern);
        }
    }
    
    // Check for nested traversal with separators
    for pattern in NESTED_TRAVERSAL_PATTERNS.iter() {
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

/// Validate against special file paths
pub fn validate_special_paths(path: &str) -> Result<()> {
    let path_lower = path.to_lowercase();
    for dangerous in SYSTEM_PATHS.iter() {
        if path_lower.starts_with(&dangerous.to_lowercase()) {
            bail!("Access to sensitive system path denied: {}", dangerous);
        }
    }
    
    Ok(())
}

/// Detect file protocol schemes and URL patterns
pub fn detect_protocol_schemes(path: &str) -> Result<()> {
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
    for protocol in DANGEROUS_PROTOCOLS.iter() {
        if path_lower.starts_with(protocol) {
            bail!("Dangerous protocol scheme detected: {}", protocol);
        }
    }
    
    Ok(())
}

/// Detect suspicious patterns
pub fn detect_suspicious_patterns(path: &str) -> Result<()> {
    for pattern in SUSPICIOUS_PATTERNS.iter() {
        if path.contains(pattern) {
            bail!("Suspicious pattern '{}' detected in path: {}", pattern, path);
        }
    }
    
    Ok(())
}
