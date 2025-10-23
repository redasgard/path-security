# User Guide - Path Security

## Overview

This comprehensive user guide provides detailed instructions for using the Path Security module effectively.

## Getting Started

### Installation

```bash
# Add to Cargo.toml
[dependencies]
path-security = "0.1.0"

# Or install via cargo
cargo add path-security
```

### Basic Usage

```rust
use path_security::{PathValidator, ValidationResult};

fn main() {
    let validator = PathValidator::new()
        .with_traversal_detection(true)
        .with_encoding_detection(true)
        .with_unicode_detection(true);

    let path = "/safe/path/to/file.txt";
    match validator.validate_path(path) {
        Ok(validated_path) => {
            println!("✅ Path is valid: {}", validated_path);
        }
        Err(error) => {
            eprintln!("❌ Path validation failed: {}", error);
        }
    }
}
```

## Path Validation

### Basic Path Validation

```rust
use path_security::{PathValidator, ValidationResult};

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
```

### Advanced Path Validation

```rust
use path_security::{PathValidator, AdvancedValidationConfig};

let advanced_config = AdvancedValidationConfig::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true)
    .with_project_name_validation(true)
    .with_filename_validation(true)
    .with_cross_platform_validation(true)
    .with_windows_specific_validation(true)
    .with_unix_specific_validation(true);

let validator = PathValidator::new()
    .with_advanced_validation_config(advanced_config);

// Validate various types of paths
let paths = vec![
    "/safe/path/to/file.txt",
    "C:\\Windows\\System32\\file.txt",
    "/usr/local/bin/script.sh",
    "../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\u002f..\u002f..\u002fetc\u002fpasswd",
];

for path in paths {
    match validator.validate_path(path) {
        Ok(validated_path) => {
            println!("✅ Path is valid: {}", validated_path);
        }
        Err(error) => {
            println!("❌ Path validation failed: {}", error);
        }
    }
}
```

## Project Name Validation

### Basic Project Name Validation

```rust
use path_security::{PathValidator, ProjectNameValidationConfig};

let project_config = ProjectNameValidationConfig::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true)
    .with_reserved_name_detection(true)
    .with_special_character_detection(true);

let validator = PathValidator::new()
    .with_project_name_validation_config(project_config);

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
```

### Advanced Project Name Validation

```rust
use path_security::{PathValidator, AdvancedProjectNameValidationConfig};

let advanced_project_config = AdvancedProjectNameValidationConfig::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true)
    .with_reserved_name_detection(true)
    .with_special_character_detection(true)
    .with_windows_reserved_names(true)
    .with_unix_reserved_names(true)
    .with_system_reserved_names(true);

let validator = PathValidator::new()
    .with_advanced_project_name_validation_config(advanced_project_config);

// Validate various types of project names
let project_names = vec![
    "my-safe-project",
    "project-with-dashes",
    "project_with_underscores",
    "project.with.dots",
    "../../../etc/passwd",
    "CON",
    "PRN",
    "AUX",
    "NUL",
];

for name in project_names {
    match validator.validate_project_name(name) {
        Ok(validated_name) => {
            println!("✅ Project name is valid: {}", validated_name);
        }
        Err(error) => {
            println!("❌ Project name validation failed: {}", error);
        }
    }
}
```

## Filename Validation

### Basic Filename Validation

```rust
use path_security::{PathValidator, FilenameValidationConfig};

let filename_config = FilenameValidationConfig::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true)
    .with_special_character_detection(true)
    .with_reserved_name_detection(true);

let validator = PathValidator::new()
    .with_filename_validation_config(filename_config);

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
```

### Advanced Filename Validation

```rust
use path_security::{PathValidator, AdvancedFilenameValidationConfig};

let advanced_filename_config = AdvancedFilenameValidationConfig::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true)
    .with_special_character_detection(true)
    .with_reserved_name_detection(true)
    .with_windows_special_characters(true)
    .with_unix_special_characters(true)
    .with_unicode_special_characters(true);

let validator = PathValidator::new()
    .with_advanced_filename_validation_config(advanced_filename_config);

// Validate various types of filenames
let filenames = vec![
    "safe-file.txt",
    "file_with_underscores.txt",
    "file.with.dots.txt",
    "file-with-dashes.txt",
    "../../../etc/passwd",
    "file<name>.txt",
    "file>name>.txt",
    "file|name>.txt",
    "file:name>.txt",
    "file\"name>.txt",
    "file*name>.txt",
    "file?name>.txt",
    "file\\name>.txt",
    "file/name>.txt",
];

for filename in filenames {
    match validator.validate_filename(filename) {
        Ok(validated_filename) => {
            println!("✅ Filename is valid: {}", validated_filename);
        }
        Err(error) => {
            println!("❌ Filename validation failed: {}", error);
        }
    }
}
```

## Security Configuration

### Comprehensive Security Configuration

```rust
use path_security::{PathValidator, ComprehensiveSecurityConfig};

let security_config = ComprehensiveSecurityConfig::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true)
    .with_project_name_validation(true)
    .with_filename_validation(true)
    .with_cross_platform_validation(true)
    .with_windows_specific_validation(true)
    .with_unix_specific_validation(true)
    .with_macos_specific_validation(true)
    .with_security_monitoring(true)
    .with_threat_monitoring(true)
    .with_anomaly_monitoring(true)
    .with_incident_monitoring(true);

let validator = PathValidator::new()
    .with_comprehensive_security_config(security_config);

println!("Path Security configured with comprehensive security settings");
```

### Threat-Specific Security Configuration

```rust
use path_security::{PathValidator, ThreatSpecificSecurityConfig};

let threat_config = ThreatSpecificSecurityConfig::new()
    .with_directory_traversal_protection(true)
    .with_encoding_attack_protection(true)
    .with_unicode_attack_protection(true)
    .with_project_name_attack_protection(true)
    .with_filename_attack_protection(true)
    .with_cross_platform_attack_protection(true)
    .with_windows_attack_protection(true)
    .with_unix_attack_protection(true)
    .with_macos_attack_protection(true);

let validator = PathValidator::new()
    .with_threat_specific_security_config(threat_config);

println!("Path Security configured with threat-specific security settings");
```

## Performance Configuration

### Performance Optimization

```rust
use path_security::{PathValidator, PerformanceOptimizationConfig};

let performance_config = PerformanceOptimizationConfig::new()
    .with_caching_enabled(true)
    .with_parallel_processing_enabled(true)
    .with_lazy_evaluation_enabled(true)
    .with_memory_optimization_enabled(true)
    .with_cpu_optimization_enabled(true)
    .with_io_optimization_enabled(true)
    .with_network_optimization_enabled(true);

let validator = PathValidator::new()
    .with_performance_optimization_config(performance_config);

println!("Path Security configured with performance optimization");
```

### Resource Management

```rust
use path_security::{PathValidator, ResourceManagementConfig};

let resource_config = ResourceManagementConfig::new()
    .with_memory_limit(1024 * 1024 * 1024) // 1GB
    .with_cpu_limit(80) // 80%
    .with_io_limit(1000) // 1000 IOPS
    .with_network_limit(100 * 1024 * 1024) // 100MB/s
    .with_memory_optimization(true)
    .with_cpu_optimization(true)
    .with_io_optimization(true)
    .with_network_optimization(true);

let validator = PathValidator::new()
    .with_resource_management_config(resource_config);

println!("Path Security configured with resource management");
```

## Monitoring Configuration

### Comprehensive Monitoring

```rust
use path_security::{PathValidator, ComprehensiveMonitoringConfig};

let monitoring_config = ComprehensiveMonitoringConfig::new()
    .with_security_monitoring(true)
    .with_performance_monitoring(true)
    .with_error_monitoring(true)
    .with_threat_monitoring(true)
    .with_anomaly_monitoring(true)
    .with_incident_monitoring(true)
    .with_forensic_monitoring(true)
    .with_audit_monitoring(true);

let validator = PathValidator::new()
    .with_comprehensive_monitoring_config(monitoring_config);

println!("Path Security configured with comprehensive monitoring");
```

### Real-time Monitoring

```rust
use path_security::{PathValidator, RealTimeMonitoringConfig};

let real_time_config = RealTimeMonitoringConfig::new()
    .with_immediate_monitoring(true)
    .with_feedback_mechanism(true)
    .with_monitoring_reporting(true)
    .with_monitoring_logging(true)
    .with_monitoring_alerting(true)
    .with_monitoring_analysis(true);

let validator = PathValidator::new()
    .with_real_time_monitoring_config(real_time_config);

println!("Path Security configured with real-time monitoring");
```

## Error Handling

### Basic Error Handling

```rust
use path_security::{PathValidator, ValidationResult};

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
```

### Advanced Error Handling

```rust
use path_security::{PathValidator, AdvancedErrorHandler, ValidationResult};

let error_handler = AdvancedErrorHandler::new()
    .with_graceful_degradation(true)
    .with_error_recovery(true)
    .with_error_logging(true)
    .with_error_reporting(true)
    .with_error_analysis(true)
    .with_error_alerting(true);

let validator = PathValidator::new()
    .with_advanced_error_handler(error_handler);

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
                log_security_event("Directory traversal attempt blocked", error);
                alert_security_team("Potential security threat detected");
            }
            ValidationResult::EncodingAttackDetected => {
                println!("❌ Encoding attack detected - blocking access");
                log_security_event("Encoding attack attempt blocked", error);
                alert_security_team("Potential security threat detected");
            }
            ValidationResult::UnicodeAttackDetected => {
                println!("❌ Unicode attack detected - blocking access");
                log_security_event("Unicode attack attempt blocked", error);
                alert_security_team("Potential security threat detected");
            }
            ValidationResult::InvalidCharacters => {
                println!("❌ Invalid characters detected - sanitizing path");
                log_security_event("Invalid characters detected", error);
                sanitize_path(path);
            }
            ValidationResult::PathTooLong => {
                println!("❌ Path too long - truncating path");
                log_security_event("Path too long", error);
                truncate_path(path);
            }
            _ => {
                println!("❌ Validation failed: {}", error);
                log_security_event("Path validation failed", error);
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

## Best Practices

### Security Best Practices

1. **Always validate paths**: Never trust user input
2. **Use comprehensive validation**: Enable all security features
3. **Monitor security events**: Set up comprehensive monitoring
4. **Handle errors gracefully**: Implement proper error handling
5. **Keep security updated**: Regularly update security measures

### Performance Best Practices

1. **Enable caching**: Use caching for improved performance
2. **Optimize resources**: Configure resource limits appropriately
3. **Monitor performance**: Set up performance monitoring
4. **Test performance**: Regularly test performance characteristics
5. **Optimize algorithms**: Use efficient algorithms and data structures

### Configuration Best Practices

1. **Use secure defaults**: Always use secure default configurations
2. **Customize for your needs**: Configure security for your specific use case
3. **Test configurations**: Test your security configurations
4. **Monitor configurations**: Monitor configuration effectiveness
5. **Update configurations**: Regularly update security configurations

## Troubleshooting

### Common Issues

1. **Path validation failures**: Check path format and characters
2. **Performance issues**: Optimize configuration and resources
3. **Security events**: Monitor and analyze security events
4. **Configuration issues**: Verify configuration settings
5. **Integration issues**: Test integration with your application

### Debugging

```rust
use path_security::{PathValidator, DebugConfig};

let debug_config = DebugConfig::new()
    .with_debug_logging(true)
    .with_verbose_output(true)
    .with_error_details(true)
    .with_validation_trace(true)
    .with_performance_trace(true)
    .with_security_trace(true);

let validator = PathValidator::new()
    .with_debug_config(debug_config);

// Debug path validation
let path = "../../../etc/passwd";
match validator.validate_path(path) {
    Ok(validated_path) => {
        println!("✅ Path is valid: {}", validated_path);
    }
    Err(error) => {
        println!("❌ Path validation failed: {}", error);
        // Debug information will be logged
    }
}
```

## Conclusion

This user guide provides comprehensive instructions for using the Path Security module effectively. By following these guidelines, you can ensure that your applications are protected against path traversal attacks and other security vulnerabilities.

Key takeaways:

1. **Comprehensive Security**: Use all available security features
2. **Performance Optimization**: Configure for optimal performance
3. **Monitoring**: Set up comprehensive monitoring
4. **Error Handling**: Implement proper error handling
5. **Testing**: Test your security implementation
6. **Best Practices**: Follow security and performance best practices
7. **Troubleshooting**: Know how to debug and resolve issues
