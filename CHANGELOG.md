# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Deprecated
- Nothing yet

### Removed
- Nothing yet

### Fixed
- Nothing yet

### Security
- Nothing yet

## [0.2.0] - 2024-10-23

### Added
- Comprehensive path validation with 62+ attack patterns
- URL encoding protection (single & double encoding)
- UTF-8 overlong encoding protection
- Unicode attack protection (homoglyphs, zero-width characters, RTL override)
- Windows-specific exploit protection (NTFS streams, UNC paths, trailing dots/spaces)
- Cross-platform support (Windows, Linux, macOS)
- Zero dependencies (only anyhow for error handling)
- Comprehensive test suite with 95.81% coverage
- Language bindings for C, Go, Java, Node.js, and Python
- Extensive documentation and examples

### Security
- Protection against 62+ path traversal attack patterns
- Defense against URL encoding attacks (%2e%2e%2f, %252e%252e%252f)
- Protection against UTF-8 overlong encoding attacks
- Unicode homoglyph and zero-width character detection
- Windows NTFS alternate data stream protection
- UNC path and extended-length path protection
- Multi-phase validation pipeline for defense in depth

## [0.1.0] - 2024-10-15

### Added
- Initial release
- Basic path validation functionality
- Project name validation
- Filename sanitization
- Cross-platform OS reserved name checking
- Basic test suite

### Security
- Protection against basic path traversal attacks
- Windows reserved name validation
- Null byte injection prevention
- Basic encoding attack protection

---

## Release Notes

### Version 0.2.0 - Major Security Enhancement

This release represents a significant security enhancement with comprehensive protection against 62+ path traversal attack patterns. The library now provides enterprise-grade path security suitable for production use.

**Key Features:**
- **62+ Attack Patterns**: Most comprehensive path validation available
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Zero Dependencies**: Only essential error handling
- **High Performance**: Optimized for production use
- **Language Bindings**: Available for multiple programming languages

**Security Improvements:**
- URL encoding protection (single and double encoding)
- UTF-8 overlong encoding protection
- Unicode attack protection (homoglyphs, zero-width characters)
- Windows-specific exploit protection
- Multi-phase validation pipeline

**Testing:**
- 21 comprehensive tests
- 95.81% test coverage
- Real attack vector testing
- Cross-platform compatibility testing

### Version 0.1.0 - Initial Release

The initial release provided basic path validation functionality with cross-platform support and essential security features.

**Features:**
- Basic path traversal prevention
- Project name validation
- Filename sanitization
- Cross-platform support
- Basic test suite

---

## Migration Guide

### From 0.1.x to 0.2.x

The API remains backward compatible, but new security features are available:

```rust
// Old usage (still works)
use path_security::validate_path;

// New usage (recommended)
use path_security::{validate_path, validate_project_name, validate_filename};
```

### Breaking Changes

None in this release.

### Deprecations

None in this release.

---

## Security Advisories

### SA-2024-001: Path Traversal Protection Enhancement

**Date**: 2024-10-23  
**Severity**: Low  
**Description**: Enhanced path traversal protection with 62+ attack patterns  
**Impact**: Improved security against advanced path traversal attacks  
**Resolution**: Upgrade to version 0.2.0 or later  

---

## Contributors

Thank you to all contributors who have helped make this project better:

- **Red Asgard** - Project maintainer and primary developer
- **Security Researchers** - For identifying attack vectors and testing
- **Community Contributors** - For bug reports and feature requests

---

## Links

- [GitHub Repository](https://github.com/redasgard/path-security)
- [Crates.io](https://crates.io/crates/path-security)
- [Documentation](https://docs.rs/path-security)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.