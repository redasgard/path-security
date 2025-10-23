# Path Security Documentation

Comprehensive path validation and sanitization library to prevent path traversal attacks in Rust applications.

## Documentation Structure

- **[Architecture](./architecture.md)** - Validation pipeline design
- **[Getting Started](./getting-started.md)** - Quick start guide
- **[User Guide](./user-guide.md)** - Comprehensive usage patterns
- **[API Reference](./api-reference.md)** - Detailed API documentation
- **[Attack Vectors](./attack-vectors.md)** - All covered attacks
- **[Security Model](./security-model.md)** - Security guarantees
- **[Testing Guide](./testing.md)** - Testing your integration
- **[FAQ](./faq.md)** - Frequently asked questions

## Quick Links

- [Why Path Security?](./why-path-security.md)
- [Use Cases](./use-cases.md)
- [Attack Examples](./attack-examples.md)
- [Best Practices](./best-practices.md)

## Overview

Path Security provides comprehensive validation against 85%+ of path traversal techniques including encoding attacks, Unicode tricks, Windows-specific exploits, and advanced evasion methods.

### Key Features

- ✅ **Path Traversal Prevention**: Blocks `..` and variants
- ✅ **Encoding Attack Protection**: URL, UTF-8, Unicode encoding
- ✅ **Unicode Attack Protection**: Homoglyphs, zero-width, RTL
- ✅ **Windows-Specific Protection**: NTFS streams, UNC paths, trailing dots
- ✅ **Cross-Platform**: Unix, Linux, macOS, Windows
- ✅ **96%+ Test Coverage**: 86 attack pattern tests

### Quick Example

```rust
use path_security::{validate_path, validate_project_name, validate_filename};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let base_dir = Path::new("/var/app/uploads");
    
    // Validate path
    let user_path = Path::new("user/document.pdf");
    let safe_path = validate_path(user_path, base_dir)?;
    
    // Validate project name
    let project = validate_project_name("my-project")?;
    
    // Validate filename
    let filename = validate_filename("report.pdf")?;
    
    println!("✓ All validations passed");
    Ok(())
}
```

## Security Coverage

**Protected Against:**
- Path traversal (`..`, `../..`, etc.)
- URL encoding (`%2e%2e%2f`)
- UTF-8 overlong encoding
- Unicode homoglyphs
- Zero-width characters
- Windows NTFS streams
- UNC paths
- Trailing dots/spaces
- And 70+ more attack vectors

## Support

- **GitHub**: https://github.com/redasgard/path-security
- **Email**: hello@redasgard.com
- **Security Issues**: security@redasgard.com

## License

MIT License - See [LICENSE](../LICENSE)

