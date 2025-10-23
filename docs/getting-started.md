# Getting Started - Path Security

## Overview

This guide will help you get started with the Path Security module, from installation to your first validation.

## Installation

### Prerequisites

- Rust 1.70+ (for development)
- 64-bit architecture (x86_64, ARM64)
- 4GB RAM minimum (8GB recommended)
- 1GB disk space

### Install Path Security

```bash
# Add to Cargo.toml
[dependencies]
path-security = "0.1.0"

# Or install via cargo
cargo add path-security
```

### Verify Installation

```rust
use path_security::{PathValidator, ValidationResult};

fn main() {
    let validator = PathValidator::new();
    println!("Path Security installed successfully!");
}
```

## Quick Start

### Basic Path Validation

```rust
use path_security::{PathValidator, ValidationResult};

fn main() {
    // Create a new path validator
    let validator = PathValidator::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true);

    // Validate a safe path
    let safe_path = "/safe/path/to/file.txt";
    match validator.validate_path(safe_path) {
        Ok(validated_path) => {
            println!("✅ Path is valid: {}", validated_path);
        }
        Err(error) => {
            eprintln!("❌ Path validation failed: {}", error);
        }
    }

    // Validate a potentially dangerous path
    let dangerous_path = "../../../etc/passwd";
    match validator.validate_path(dangerous_path) {
        Ok(validated_path) => {
            println!("✅ Path is valid: {}", validated_path);
        }
        Err(error) => {
            println!("❌ Path validation failed: {}", error);
        }
    }
}
```

### Project Name Validation

```rust
use path_security::{PathValidator, ValidationResult};

fn main() {
    let validator = PathValidator::new()
        .with_project_name_validation(true)
        .with_traversal_detection(true)
        .with_encoding_detection(true);

    // Validate a safe project name
    let safe_name = "my-safe-project";
    match validator.validate_project_name(safe_name) {
        Ok(validated_name) => {
            println!("✅ Project name is valid: {}", validated_name);
        }
        Err(error) => {
            eprintln!("❌ Project name validation failed: {}", error);
        }
    }

    // Validate a potentially dangerous project name
    let dangerous_name = "../../../etc/passwd";
    match validator.validate_project_name(dangerous_name) {
        Ok(validated_name) => {
            println!("✅ Project name is valid: {}", validated_name);
        }
        Err(error) => {
            println!("❌ Project name validation failed: {}", error);
        }
    }
}
```

### Filename Validation

```rust
use path_security::{PathValidator, ValidationResult};

fn main() {
    let validator = PathValidator::new()
        .with_filename_validation(true)
        .with_traversal_detection(true)
        .with_encoding_detection(true);

    // Validate a safe filename
    let safe_filename = "safe-file.txt";
    match validator.validate_filename(safe_filename) {
        Ok(validated_filename) => {
            println!("✅ Filename is valid: {}", validated_filename);
        }
        Err(error) => {
            eprintln!("❌ Filename validation failed: {}", error);
        }
    }

    // Validate a potentially dangerous filename
    let dangerous_filename = "../../../etc/passwd";
    match validator.validate_filename(dangerous_filename) {
        Ok(validated_filename) => {
            println!("✅ Filename is valid: {}", validated_filename);
        }
        Err(error) => {
            println!("❌ Filename validation failed: {}", error);
        }
    }
}
```

## Basic Configuration

### Security Configuration

```rust
use path_security::{PathValidator, SecurityConfig};

fn main() {
    let security_config = SecurityConfig::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true)
        .with_project_name_validation(true)
        .with_filename_validation(true)
        .with_cross_platform_validation(true);

    let validator = PathValidator::new()
        .with_security_config(security_config);

    println!("Path Security configured with comprehensive security settings");
}
```

### Performance Configuration

```rust
use path_security::{PathValidator, PerformanceConfig};

fn main() {
    let performance_config = PerformanceConfig::new()
        .with_caching_enabled(true)
        .with_parallel_processing_enabled(true)
        .with_lazy_evaluation_enabled(true)
        .with_memory_optimization_enabled(true);

    let validator = PathValidator::new()
        .with_performance_config(performance_config);

    println!("Path Security configured with performance optimization");
}
```

### Monitoring Configuration

```rust
use path_security::{PathValidator, MonitoringConfig};

fn main() {
    let monitoring_config = MonitoringConfig::new()
        .with_security_monitoring(true)
        .with_performance_monitoring(true)
        .with_error_monitoring(true)
        .with_threat_monitoring(true);

    let validator = PathValidator::new()
        .with_monitoring_config(monitoring_config);

    println!("Path Security configured with comprehensive monitoring");
}
```

## Common Use Cases

### Web Application Security

```rust
use path_security::{PathValidator, WebSecurityConfig};

fn main() {
    let web_config = WebSecurityConfig::new()
        .with_web_security(true)
        .with_api_security(true)
        .with_file_upload_security(true)
        .with_path_validation(true);

    let validator = PathValidator::new()
        .with_web_security_config(web_config);

    // Validate user-uploaded file paths
    let user_path = "/uploads/user-file.txt";
    match validator.validate_path(user_path) {
        Ok(validated_path) => {
            println!("✅ User path is valid: {}", validated_path);
        }
        Err(error) => {
            println!("❌ User path validation failed: {}", error);
        }
    }
}
```

### File System Security

```rust
use path_security::{PathValidator, FileSystemSecurityConfig};

fn main() {
    let fs_config = FileSystemSecurityConfig::new()
        .with_file_system_security(true)
        .with_directory_traversal_protection(true)
        .with_file_access_control(true)
        .with_path_validation(true);

    let validator = PathValidator::new()
        .with_file_system_security_config(fs_config);

    // Validate file system paths
    let fs_path = "/var/log/application.log";
    match validator.validate_path(fs_path) {
        Ok(validated_path) => {
            println!("✅ File system path is valid: {}", validated_path);
        }
        Err(error) => {
            println!("❌ File system path validation failed: {}", error);
        }
    }
}
```

### API Security

```rust
use path_security::{PathValidator, APISecurityConfig};

fn main() {
    let api_config = APISecurityConfig::new()
        .with_api_security(true)
        .with_endpoint_security(true)
        .with_parameter_security(true)
        .with_path_validation(true);

    let validator = PathValidator::new()
        .with_api_security_config(api_config);

    // Validate API parameters
    let api_param = "file=document.pdf";
    match validator.validate_path(api_param) {
        Ok(validated_param) => {
            println!("✅ API parameter is valid: {}", validated_param);
        }
        Err(error) => {
            println!("❌ API parameter validation failed: {}", error);
        }
    }
}
```

## Advanced Configuration

### Custom Validation Rules

```rust
use path_security::{PathValidator, CustomValidator};

struct MyCustomValidator;

impl CustomValidator for MyCustomValidator {
    fn validate(&self, path: &str) -> Result<String, String> {
        // Implement your custom validation logic
        if path.contains("custom_pattern") {
            Err("Custom pattern detected".to_string())
        } else {
            Ok(path.to_string())
        }
    }
}

fn main() {
    let validator = PathValidator::new()
        .add_custom_validator(Box::new(MyCustomValidator));

    println!("Path Security configured with custom validation rules");
}
```

### Custom Detection Rules

```rust
use path_security::{PathValidator, CustomDetector};

struct MyCustomDetector;

impl CustomDetector for MyCustomDetector {
    fn detect(&self, path: &str) -> Result<bool, String> {
        // Implement your custom detection logic
        Ok(path.contains("custom_attack_pattern"))
    }
}

fn main() {
    let validator = PathValidator::new()
        .add_custom_detector(Box::new(MyCustomDetector));

    println!("Path Security configured with custom detection rules");
}
```

### Custom Sanitization Rules

```rust
use path_security::{PathValidator, CustomSanitizer};

struct MyCustomSanitizer;

impl CustomSanitizer for MyCustomSanitizer {
    fn sanitize(&self, path: &str) -> Result<String, String> {
        // Implement your custom sanitization logic
        let sanitized = path.replace("custom_pattern", "safe_replacement");
        Ok(sanitized)
    }
}

fn main() {
    let validator = PathValidator::new()
        .add_custom_sanitizer(Box::new(MyCustomSanitizer));

    println!("Path Security configured with custom sanitization rules");
}
```

## Error Handling

### Basic Error Handling

```rust
use path_security::{PathValidator, ValidationResult};

fn main() {
    let validator = PathValidator::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true);

    let path = "../../../etc/passwd";
    match validator.validate_path(path) {
        Ok(validated_path) => {
            println!("✅ Path is valid: {}", validated_path);
        }
        Err(error) => {
            match error {
                ValidationResult::TraversalDetected => {
                    println!("❌ Directory traversal detected");
                }
                ValidationResult::EncodingAttackDetected => {
                    println!("❌ Encoding attack detected");
                }
                ValidationResult::UnicodeAttackDetected => {
                    println!("❌ Unicode attack detected");
                }
                ValidationResult::InvalidCharacters => {
                    println!("❌ Invalid characters detected");
                }
                ValidationResult::PathTooLong => {
                    println!("❌ Path too long");
                }
                _ => {
                    println!("❌ Validation failed: {}", error);
                }
            }
        }
    }
}
```

### Advanced Error Handling

```rust
use path_security::{PathValidator, ErrorHandler, ValidationResult};

fn main() {
    let error_handler = ErrorHandler::new()
        .with_graceful_degradation(true)
        .with_error_recovery(true)
        .with_error_logging(true)
        .with_error_reporting(true);

    let validator = PathValidator::new()
        .with_error_handler(error_handler);

    let path = "../../../etc/passwd";
    match validator.validate_path(path) {
        Ok(validated_path) => {
            println!("✅ Path is valid: {}", validated_path);
        }
        Err(error) => {
            // Handle different types of errors
            match error {
                ValidationResult::TraversalDetected => {
                    println!("❌ Directory traversal detected - blocking access");
                }
                ValidationResult::EncodingAttackDetected => {
                    println!("❌ Encoding attack detected - blocking access");
                }
                ValidationResult::UnicodeAttackDetected => {
                    println!("❌ Unicode attack detected - blocking access");
                }
                ValidationResult::InvalidCharacters => {
                    println!("❌ Invalid characters detected - sanitizing path");
                }
                ValidationResult::PathTooLong => {
                    println!("❌ Path too long - truncating path");
                }
                _ => {
                    println!("❌ Validation failed: {}", error);
                }
            }
        }
    }
}
```

## Testing

### Unit Testing

```rust
use path_security::{PathValidator, ValidationResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_path_validation() {
        let validator = PathValidator::new()
            .with_traversal_detection(true)
            .with_encoding_detection(true)
            .with_unicode_detection(true);

        let safe_path = "/safe/path/to/file.txt";
        assert!(validator.validate_path(safe_path).is_ok());
    }

    #[test]
    fn test_dangerous_path_validation() {
        let validator = PathValidator::new()
            .with_traversal_detection(true)
            .with_encoding_detection(true)
            .with_unicode_detection(true);

        let dangerous_path = "../../../etc/passwd";
        assert!(validator.validate_path(dangerous_path).is_err());
    }

    #[test]
    fn test_encoding_attack_detection() {
        let validator = PathValidator::new()
            .with_traversal_detection(true)
            .with_encoding_detection(true)
            .with_unicode_detection(true);

        let encoding_attack = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd";
        assert!(validator.validate_path(encoding_attack).is_err());
    }

    #[test]
    fn test_unicode_attack_detection() {
        let validator = PathValidator::new()
            .with_traversal_detection(true)
            .with_encoding_detection(true)
            .with_unicode_detection(true);

        let unicode_attack = "..\u002f..\u002f..\u002fetc\u002fpasswd";
        assert!(validator.validate_path(unicode_attack).is_err());
    }
}
```

### Integration Testing

```rust
use path_security::{PathValidator, IntegrationTestConfig};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_web_application_integration() {
        let web_config = IntegrationTestConfig::new()
            .with_web_application_testing(true)
            .with_api_testing(true)
            .with_file_upload_testing(true);

        let validator = PathValidator::new()
            .with_integration_test_config(web_config);

        // Test web application scenarios
        let web_paths = vec![
            "/uploads/user-file.txt",
            "/static/css/style.css",
            "/api/v1/data.json",
        ];

        for path in web_paths {
            assert!(validator.validate_path(path).is_ok());
        }
    }

    #[test]
    fn test_file_system_integration() {
        let fs_config = IntegrationTestConfig::new()
            .with_file_system_testing(true)
            .with_directory_testing(true)
            .with_file_access_testing(true);

        let validator = PathValidator::new()
            .with_integration_test_config(fs_config);

        // Test file system scenarios
        let fs_paths = vec![
            "/var/log/application.log",
            "/tmp/temporary-file.txt",
            "/home/user/documents/file.pdf",
        ];

        for path in fs_paths {
            assert!(validator.validate_path(path).is_ok());
        }
    }
}
```

## Next Steps

### Learn More

- **Architecture**: Understand the Path Security architecture
- **API Reference**: Explore the complete API reference
- **Examples**: See more code examples and use cases
- **Best Practices**: Learn security and performance best practices
- **Advanced Topics**: Explore advanced configuration and customization

### Explore Features

- **Threat Detection**: Learn about advanced threat detection capabilities
- **Performance Optimization**: Optimize your Path Security implementation
- **Integration**: Integrate Path Security with your applications
- **Monitoring**: Set up comprehensive monitoring and alerting
- **Customization**: Implement custom validation and detection rules

### Get Support

- **Documentation**: Comprehensive documentation is available
- **Examples**: Code examples and tutorials are provided
- **Community**: Join the community for support and discussions
- **Issues**: Report issues and bugs on GitHub
- **Professional Support**: Commercial support is available

## Conclusion

You've successfully set up Path Security and learned the basics of path validation, project name validation, and filename validation. You've also learned about configuration, error handling, and testing.

Next steps:
1. Explore the comprehensive documentation
2. Try the examples and tutorials
3. Integrate Path Security with your applications
4. Implement custom validation and detection rules
5. Set up monitoring and alerting
6. Join the community for support and discussions
