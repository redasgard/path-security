# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING**: Renamed library from `valkra-path-security` to `path-security` for broader ecosystem adoption
- **BREAKING**: Crate name changed from `valkra_path_security` to `path_security`
- Updated repository URL to `https://github.com/asgardtech/path-security`
- Updated all documentation and examples to use new name

## [0.2.0] - 2025-10-23

### 🚀 Major Security Enhancements

This release represents a comprehensive security overhaul, increasing attack vector coverage from ~20% to **80%+**.

### Added

#### Encoding Attack Protection (8 new types)
- URL encoding detection (`%2e%2e%2f`, `%2E`, `%2F`, `%5C`)
- Double URL encoding detection (`%252e%252e%252f`)
- UTF-8 overlong encoding detection (`%c0%ae`, `%c0%af`, `%c1%9c`, `%e0%80%ae`)
- Unicode percent encoding detection (`%u002e`, `%u002f`)
- HTML entity encoding detection (`&#46;&#46;&#47;`)
- Hex encoding detection (`\x2e\x2f`)
- Null byte encoding detection (`%00`)
- Control character encoding detection (`%0a`, `%0d`)

#### Unicode Attack Protection (5 new types)
- Zero-width character detection (U+200B, U+200C, U+200D, U+FEFF)
- Right-to-left override detection (U+202E)
- Unicode homoglyph detection (dots: U+2024-2026, slashes: U+2044, U+2215, U+2571, U+FF0F)
- Full-width character detection (U+FF01-FF5E)
- Combining character validation

#### Windows-Specific Protection (8 new types)
- NTFS alternate data stream detection (`file.txt::$DATA`, `file.txt:stream`)
- UNC path detection (`\\server\share`, `//server/share`)
- Extended-length path prefix detection (`\\?\`, `\\.\`)
- Device path detection (`\\.\COM1`, `\\.\pipe\`)
- Trailing dot detection (`file.txt.`, `file.txt...`)
- Trailing space detection (`file.txt   `)
- Drive-relative path detection (`C:../`)
- Reserved names with extensions (`CON.txt`, `PRN.log`)

#### Path Manipulation Protection (4 new types)
- Multiple consecutive separator detection (`//`, `///`, `\\\\`)
- Mixed separator detection (`../\../`, `.\/`)
- Alternative separator detection (`;`, `\t`, `\n`, `\r`)
- Backslash normalization on Unix

#### Whitespace Exploitation Protection (4 new types)
- Leading/trailing whitespace detection
- Internal whitespace pattern detection
- Tab character detection
- Other whitespace character detection

#### Advanced Traversal Protection (4 new types)
- Triple dot detection (`...`)
- Space-separated dot detection (`. .`, `. . `)
- Current directory traversal detection (`./../../`)
- Redundant pattern detection (`././../`)

#### Special Path Protection (5 new types)
- Proc filesystem blocking (`/proc/self/`, `/proc/[pid]/`)
- Dev filesystem blocking (`/dev/null`, `/dev/random`)
- Sys filesystem blocking (`/sys/`)
- System directory blocking (`/etc/`, `/boot/`, Windows system paths)
- Temp directory validation (`/tmp/`, `/var/tmp/`)

### Enhanced

- **`validate_path()`**: Now uses 7-phase validation pipeline
  1. Pre-processing and normalization
  2. Encoding attack detection
  3. Path structure validation
  4. Windows-specific attack detection
  5. Basic suspicious pattern checks
  6. Special path validation
  7. Canonicalization and final validation

- **`validate_filename()`**: Enhanced with comprehensive encoding and attack detection
  - Now runs all encoding checks
  - Additional Windows-specific validations
  - Stricter colon and special character handling

### Testing

- Added 14 new comprehensive test functions
- Total test count: 21 tests (up from 7)
- Test coverage: **95.81% line coverage** (up from ~70%)
- Added `examples/attack_vectors.rs` demonstrating protection against 62 attack patterns
- **100% effectiveness**: All 62 tested attack patterns blocked

### Documentation

- Enhanced README with categorized security guarantees
- Added `PATH_TRAVERSAL_COVERAGE_ANALYSIS.md` with detailed gap analysis
- Added `COMPREHENSIVE_ENHANCEMENT_SUMMARY.md` with full impact assessment
- Added comprehensive attack vector demonstration example
- Updated inline documentation with security details

### Changed

- Library description updated to reflect comprehensive coverage
- More descriptive error messages for different attack types
- Stricter validation (some ambiguous patterns now rejected for security)

### Performance

- Minimal performance impact (all checks are efficient string operations)
- Early rejection strategy (most attacks caught in first few phases)
- No additional external dependencies

## [0.1.0] - 2025-10-17

### Added

- Initial release with basic path traversal protection
- `validate_path()` function with canonicalization
- `validate_project_name()` function
- `validate_filename()` function
- Basic protection against:
  - `..` directory traversal
  - Absolute paths
  - Null byte injection
  - Environment variables (`$VAR`, `%VAR%`, `~`)
  - Windows reserved names (CON, PRN, AUX, etc.)
  - Control characters
- Cross-platform support (Unix/Windows)
- Comprehensive test suite
- Documentation and examples

[0.2.0]: https://github.com/asgardtech/valkra-path-security/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/asgardtech/valkra-path-security/releases/tag/v0.1.0

