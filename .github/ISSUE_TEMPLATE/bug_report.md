---
name: Bug Report
about: Create a report to help us improve path-security
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description
A clear and concise description of what the bug is.

## To Reproduce
Steps to reproduce the behavior:
1. Go to '...'
2. Call function '...'
3. Pass arguments '...'
4. See error

## Expected Behavior
A clear and concise description of what you expected to happen.

## Actual Behavior
A clear and concise description of what actually happened.

## Code Example
```rust
// Minimal code example that reproduces the issue
use path_security::validate_path;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let base_dir = Path::new("/var/app/uploads");
    let user_path = Path::new("your/malicious/path");
    
    // This should fail but doesn't (or vice versa)
    let result = validate_path(user_path, base_dir)?;
    println!("Result: {:?}", result);
    Ok(())
}
```

## Environment
- **OS**: [e.g. Ubuntu 22.04, Windows 11, macOS 13.0]
- **Rust Version**: [e.g. 1.70.0]
- **path-security Version**: [e.g. 0.2.0]
- **Architecture**: [e.g. x86_64, aarch64]

## Security Considerations
- [ ] This bug could be a security vulnerability
- [ ] This bug involves path traversal attacks
- [ ] This bug involves encoding attacks
- [ ] This bug involves Unicode attacks
- [ ] This bug involves Windows-specific attacks

## Additional Context
Add any other context about the problem here.

## Checklist
- [ ] I have searched existing issues to avoid duplicates
- [ ] I have provided a minimal code example
- [ ] I have included environment details
- [ ] I have considered security implications
- [ ] I have read the [CONTRIBUTING.md](CONTRIBUTING.md) guide
