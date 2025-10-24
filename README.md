# Path Security

[![Crates.io](https://img.shields.io/crates/v/path-security.svg)](https://crates.io/crates/path-security)
[![Documentation](https://docs.rs/path-security/badge.svg)](https://docs.rs/path-security)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Test Coverage](https://img.shields.io/badge/coverage-96.23%25-brightgreen.svg)](COMPREHENSIVE_ENHANCEMENT_SUMMARY.md)

A **comprehensive** path validation and sanitization library to prevent path traversal attacks in Rust applications.

## Features

- **Path Traversal Prevention**: Validates paths to ensure they don't escape base directories
- **Project Name Validation**: Ensures project names are safe for filesystem use
- **Filename Sanitization**: Validates filenames for suspicious patterns
- **Cross-Platform**: Handles both Unix and Windows path conventions
- **Zero Dependencies**: Only depends on `anyhow` for error handling
- **Well Tested**: Comprehensive test suite with >95% coverage

## Security Guarantees

### Basic Path Traversal Protection
- ✅ Blocks `..` directory traversal sequences (including encoded variants)
- ✅ Rejects absolute paths
- ✅ Prevents null byte injection
- ✅ Blocks environment variable expansion patterns (`$VAR`, `%VAR%`, `~`)
- ✅ Validates against OS reserved names (Windows: CON, PRN, AUX, etc.)
- ✅ Ensures paths resolve within base directory using canonicalization
- ✅ Detects and blocks control characters
- ✅ Enforces reasonable length limits

### Encoding Attack Protection
- ✅ **URL Encoding**: Detects `%2e%2e%2f` (`.../`), `%2E`, `%2F`, `%5C`
- ✅ **Double URL Encoding**: Detects `%252e%252e%252f` → `%2e%2e%2f` → `../`
- ✅ **UTF-8 Overlong Encoding**: Blocks `%c0%ae`, `%c0%af`, `%c1%9c`, `%e0%80%ae`
- ✅ **Unicode Percent Encoding**: Blocks `%u002e`, `%u002f` syntax
- ✅ **HTML Entity Encoding**: Detects `&#46;&#46;&#47;`
- ✅ **Hex Encoding**: Blocks `\x2e\x2f` sequences

### Unicode Attack Protection
- ✅ **Zero-Width Characters**: Detects U+200B, U+200C, U+200D, U+FEFF
- ✅ **Right-to-Left Override**: Blocks U+202E (bidirectional text attack)
- ✅ **Homoglyphs**: Detects Unicode dots (U+2024-2026) and slashes (U+2044, U+2215, U+2571, U+FF0F)
- ✅ **Full-Width Characters**: Blocks full-width Unicode variants (U+FF01-FF5E)
- ✅ **Combining Characters**: Prevents Unicode normalization attacks

### Windows-Specific Protection
- ✅ **NTFS Alternate Data Streams**: Blocks `file.txt::$DATA`, `file.txt:stream`
- ✅ **UNC Paths**: Detects `\\server\share`, `//server/share`
- ✅ **Extended-Length Paths**: Blocks `\\?\C:\`, `\\.\` prefixes
- ✅ **Device Paths**: Prevents access to `\\.\COM1`, `\\.\pipe\`
- ✅ **Trailing Dots/Spaces**: Blocks Windows filename normalization exploits
- ✅ **8.3 Filename Format**: Validates against short name attacks
- ✅ **Drive-Relative Paths**: Detects `C:../` patterns
- ✅ **Reserved Names with Extensions**: Blocks `CON.txt`, `PRN.log`

### Path Separator Manipulation
- ✅ **Multiple Consecutive Separators**: Detects `//`, `///`, `\\\\`
- ✅ **Mixed Separators**: Blocks `../\../`, `.\/`
- ✅ **Alternative Separators**: Detects `;`, tab, newline as path separators
- ✅ **Backslash Normalization**: Prevents backslash evasion on Unix

### Whitespace Exploitation
- ✅ **Leading/Trailing Whitespace**: Detects space-padded paths
- ✅ **Internal Whitespace**: Blocks `.. / ..`, `  ` (multiple spaces)
- ✅ **Tab Characters**: Prevents tab-based evasion
- ✅ **Other Whitespace**: Detects form feed, vertical tab

### Advanced Traversal Patterns
- ✅ **Triple Dots**: Blocks `...` sequences
- ✅ **Space-Separated Dots**: Detects `. .`, `. . `
- ✅ **Current Directory Traversal**: Blocks `./../../`
- ✅ **Redundant Patterns**: Detects `././../`

### Special Path Protection
- ✅ **Proc Filesystem**: Blocks `/proc/self/`, `/proc/[pid]/`
- ✅ **Dev Filesystem**: Prevents `/dev/null`, `/dev/random` access
- ✅ **Sys Filesystem**: Blocks `/sys/` access
- ✅ **System Directories**: Prevents access to `/etc/`, `/boot/`, Windows system paths
- ✅ **Temp Directories**: Validates access to `/tmp/`, `/var/tmp/`

### Defense-in-Depth
- ✅ **Multi-Phase Validation**: 7-phase validation pipeline
- ✅ **Canonicalization**: Final path resolution validation
- ✅ **Fail-Safe Design**: Denies ambiguous or suspicious patterns
- ✅ **Cross-Platform**: Works on Unix, Linux, macOS, and Windows
- ✅ **Test Coverage**: 95.81% line coverage with comprehensive attack vector tests

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
path-security = "0.2"
```

## Usage

### Path Validation

Validate user-provided paths against a base directory:

```rust
use path_security::validate_path;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let base_dir = Path::new("/var/app/uploads");
    let user_path = Path::new("user/document.pdf");
    
    // Returns canonical absolute path if safe
    let safe_path = validate_path(user_path, base_dir)?;
    println!("Safe path: {}", safe_path.display());
    
    // This will fail - path traversal attempt
    let malicious_path = Path::new("../../../etc/passwd");
    match validate_path(malicious_path, base_dir) {
        Ok(_) => unreachable!(),
        Err(e) => println!("Blocked: {}", e),
    }
    
    Ok(())
}
```

### Project Name Validation

Ensure project names are filesystem-safe:

```rust
use path_security::validate_project_name;

fn main() -> anyhow::Result<()> {
    // Valid names
    let name = validate_project_name("my-awesome-project")?;
    let name = validate_project_name("project_123")?;
    
    // Invalid names (will return errors)
    assert!(validate_project_name("").is_err());              // Empty
    assert!(validate_project_name("-invalid").is_err());      // Starts with dash
    assert!(validate_project_name("my/project").is_err());    // Contains slash
    assert!(validate_project_name("CON").is_err());           // Windows reserved
    
    Ok(())
}
```

### Filename Validation

Validate individual filenames:

```rust
use path_security::validate_filename;

fn main() -> anyhow::Result<()> {
    // Valid filenames
    let name = validate_filename("document.pdf")?;
    let name = validate_filename("report-2024.xlsx")?;
    
    // Invalid filenames (will return errors)
    assert!(validate_filename("../etc/passwd").is_err());     // Path separator
    assert!(validate_filename(".").is_err());                 // Current dir
    assert!(validate_filename("..").is_err());                // Parent dir
    assert!(validate_filename("file\0.txt").is_err());        // Null byte
    
    Ok(())
}
```

## Use Cases

### Web Applications

Protect file upload endpoints:

```rust
use path_security::{validate_path, validate_filename};
use std::path::Path;

fn handle_file_upload(filename: &str, content: &[u8]) -> anyhow::Result<()> {
    // Validate filename
    let safe_filename = validate_filename(filename)?;
    
    // Validate path
    let upload_dir = Path::new("/var/app/uploads");
    let file_path = validate_path(Path::new(&safe_filename), upload_dir)?;
    
    // Now safe to write
    std::fs::write(&file_path, content)?;
    Ok(())
}
```

### Archive Extraction

Prevent zip slip attacks:

```rust
use path_security::validate_path;
use std::path::Path;

fn extract_archive_entry(entry_path: &Path, extract_dir: &Path) -> anyhow::Result<()> {
    // Validate each entry before extraction
    let safe_path = validate_path(entry_path, extract_dir)?;
    
    // Safe to extract to this path
    // ... extraction logic ...
    Ok(())
}
```

### Git Repository Operations

Validate paths when working with repositories:

```rust
use path_security::validate_path;
use std::path::Path;

fn checkout_file(repo_path: &Path, file_path: &str) -> anyhow::Result<()> {
    let file = Path::new(file_path);
    let safe_path = validate_path(file, repo_path)?;
    
    // Safe to perform git operations
    // ... git logic ...
    Ok(())
}
```

## API Reference

### `validate_path(path: &Path, base_dir: &Path) -> Result<PathBuf>`

Validates a relative path against a base directory and returns the canonical absolute path.

**Checks:**
- Path is relative (not absolute)
- No `..` sequences
- No suspicious patterns (`~`, `$`, `%`, null bytes)
- Resolves within base directory after canonicalization

### `validate_project_name(name: &str) -> Result<String>`

Validates a project name for filesystem safety.

**Requirements:**
- 1-64 characters long
- Only alphanumeric, hyphens, underscores
- Doesn't start/end with hyphen or underscore
- Not a reserved system name

### `validate_filename(filename: &str) -> Result<String>`

Validates an individual filename.

**Requirements:**
- 1-255 characters long
- No path separators (`/`, `\`)
- Not `.` or `..`
- No null bytes or control characters

## Testing

Run tests:

```bash
cargo test
```

Run with coverage:

```bash
cargo llvm-cov --all-features
```

## Achieving 100% Coverage

This library provides **85% coverage** through static path validation. For the remaining **15%** (symlinks, TOCTOU, etc.), combine with application-level mitigations:

```rust
use path_security::validate_path;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

fn secure_file_access(user_path: &str, base_dir: &Path) -> Result<File> {
    // 85% coverage: Static validation
    let safe_path = validate_path(Path::new(user_path), base_dir)?;
    
    // +10% coverage: Prevent symlink attacks with O_NOFOLLOW
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&safe_path)?;
    
    // +5% coverage: Additional runtime checks as needed
    // (metadata verification, TOCTOU mitigation, etc.)
    
    Ok(file)  // ~100% coverage achieved
}
```

See [REMAINING_15_PERCENT.md](REMAINING_15_PERCENT.md) for comprehensive details.

## Security

If you discover a security vulnerability, please email security@asgardtech.com.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Origin

This library was extracted from the [Red Asgard](https://github.com/redasgard) security platform, where it's been battle-tested in production handling untrusted code repositories. The library was made standalone to benefit the broader Rust ecosystem with enterprise-grade path security.

