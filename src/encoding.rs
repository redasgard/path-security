//! Encoding detection and normalization for path security

use anyhow::{bail, Result};

use crate::constants::*;

/// Detect URL-encoded path traversal patterns
/// Checks for: %2e, %2f, %5c and their uppercase variants
pub fn detect_url_encoding(path: &str) -> Result<()> {
    for pattern in SUSPICIOUS_ENCODED_PATTERNS.iter() {
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
pub fn detect_overlong_utf8(path: &str) -> Result<()> {
    let path_lower = path.to_lowercase();
    for pattern in OVERLONG_UTF8_PATTERNS.iter() {
        if path_lower.contains(pattern) {
            bail!("UTF-8 overlong encoding detected: {}", pattern);
        }
    }
    
    Ok(())
}

/// Detect Unicode encoding tricks
pub fn detect_unicode_encoding(path: &str) -> Result<()> {
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
pub fn detect_dangerous_unicode(path: &str) -> Result<()> {
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

/// Detect mixed encoding attacks (UTF-8 + UTF-16)
pub fn detect_mixed_encoding(path: &str) -> bool {
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

/// Normalize path to detect hidden traversal attempts
pub fn normalize_and_check(path: &str) -> Result<String> {
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
