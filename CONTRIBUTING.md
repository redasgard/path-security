# Contributing to Path Security

Thank you for your interest in contributing to Path Security! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Security](#security)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.70+ (latest stable recommended)
- Git
- Basic understanding of path traversal attacks and security

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/path-security.git
   cd path-security
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/redasgard/path-security.git
   ```

## How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Check the documentation** in the `docs/` folder
3. **Verify the issue** with the latest version

When creating an issue, include:

- **Clear description** of the problem
- **Steps to reproduce** (if applicable)
- **Expected vs actual behavior**
- **Environment details** (OS, Rust version)
- **Minimal code example** (if applicable)

### Suggesting Enhancements

For feature requests:

1. **Check existing issues** and roadmap
2. **Describe the use case** clearly
3. **Explain the benefit** to users
4. **Consider implementation complexity**

### Pull Requests

#### Before You Start

1. **Open an issue first** for significant changes
2. **Discuss the approach** with maintainers
3. **Ensure the change aligns** with project goals

#### PR Process

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our guidelines

3. **Test thoroughly**:
   ```bash
   cargo test
   cargo test --features tracing
   cargo clippy
   cargo fmt
   ```

4. **Update documentation** if needed

5. **Commit with clear messages**:
   ```bash
   git commit -m "Add support for Windows long path validation"
   ```

6. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```

#### PR Requirements

- **All tests pass** (CI will check)
- **Code is formatted** (`cargo fmt`)
- **No clippy warnings** (`cargo clippy`)
- **Documentation updated** if needed
- **Clear commit messages**
- **PR description** explains the change

## Development Setup

### Project Structure

```
path-security/
├── src/                 # Source code
│   ├── lib.rs          # Main library interface
│   ├── validation.rs   # Core validation logic
│   ├── attacks.rs      # Attack pattern definitions
│   ├── encoding.rs     # Encoding attack detection
│   └── constants.rs    # Constants and patterns
├── tests/              # Integration tests
├── examples/           # Usage examples
├── docs/               # Documentation
└── bindings/           # Language bindings
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with coverage
cargo llvm-cov --all-features

# Run specific test
cargo test test_path_traversal_prevention

# Run examples
cargo run --example basic_usage
cargo run --example attack_vectors
```

### Code Style

We follow standard Rust conventions:

- **Format code**: `cargo fmt`
- **Check linting**: `cargo clippy`
- **Use meaningful names**
- **Add documentation** for public APIs
- **Write tests** for new functionality

## Testing

### Test Categories

1. **Unit Tests**: Test individual functions
2. **Integration Tests**: Test complete workflows
3. **Attack Vector Tests**: Test against known attacks
4. **Edge Case Tests**: Test boundary conditions

### Adding Tests

When adding new functionality:

1. **Write unit tests** for each function
2. **Add integration tests** for workflows
3. **Test attack vectors** if security-related
4. **Test edge cases** and error conditions

Example test structure:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_validation_feature() {
        // Test the happy path
        let result = validate_path(Path::new("safe/file.txt"), Path::new("/base"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_attack_prevention() {
        // Test attack prevention
        let result = validate_path(Path::new("../../../etc/passwd"), Path::new("/base"));
        assert!(result.is_err());
    }
}
```

## Security

### Security Considerations

Path Security is a security-critical library. When contributing:

1. **Understand attack vectors** before making changes
2. **Test against known attacks** in `examples/attack_vectors.rs`
3. **Consider edge cases** and boundary conditions
4. **Review security implications** of changes

### Security Testing

```bash
# Run attack vector examples
cargo run --example attack_vectors

# Test specific attack patterns
cargo test test_unicode_attacks
cargo test test_encoding_attacks
cargo test test_windows_attacks
```

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead:
1. Email security@redasgard.com
2. Include detailed description
3. Include steps to reproduce
4. Wait for response before disclosure

## Documentation

### Documentation Standards

- **Public APIs** must have doc comments
- **Examples** in doc comments should be runnable
- **Security implications** should be documented
- **Performance characteristics** should be noted

### Documentation Structure

```
docs/
├── README.md              # Main documentation
├── getting-started.md      # Quick start guide
├── api-reference.md       # Complete API docs
├── attack-vectors.md      # Security documentation
├── best-practices.md      # Usage guidelines
└── faq.md                 # Frequently asked questions
```

### Writing Documentation

1. **Use clear, concise language**
2. **Include practical examples**
3. **Explain security implications**
4. **Link to related resources**
5. **Keep it up to date**

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

Before releasing:

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in Cargo.toml
- [ ] Security review completed
- [ ] Performance benchmarks updated

### Release Steps

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md**
3. **Create release PR**
4. **Review and merge**
5. **Tag release** on GitHub
6. **Publish to crates.io**

## Areas for Contribution

### High Priority

- **New attack patterns**: Research and implement new attack vectors
- **Performance improvements**: Optimize validation algorithms
- **Language bindings**: Improve existing bindings or add new ones
- **Documentation**: Improve examples and guides

### Medium Priority

- **Error handling**: Better error messages and types
- **Configuration**: More flexible validation options
- **Logging**: Better debugging and monitoring
- **Testing**: More comprehensive test coverage

### Low Priority

- **CLI tools**: Command-line utilities
- **IDE integration**: Editor plugins
- **Visualization**: Attack pattern visualization tools

## Getting Help

### Resources

- **Documentation**: Check the `docs/` folder
- **Examples**: Look at `examples/` folder
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions

### Contact

- **Email**: hello@redasgard.com
- **GitHub**: [@redasgard](https://github.com/redasgard)
- **Security**: security@redasgard.com

## Recognition

Contributors will be:

- **Listed in CONTRIBUTORS.md**
- **Mentioned in release notes** for significant contributions
- **Credited in documentation** for major features

Thank you for contributing to Path Security! 🛡️
