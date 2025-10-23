# API Reference - Path Security

## Overview

This document provides comprehensive API reference for the Path Security module, including all public interfaces, types, and functions.

## Core Types

### PathValidator

The main path validation engine for security protection.

```rust
pub struct PathValidator {
    config: PathSecurityConfig,
    sanitizers: Vec<Box<dyn PathSanitizer>>,
    validators: Vec<Box<dyn PathValidator>>,
    detectors: Vec<Box<dyn AttackDetector>>,
}

impl PathValidator {
    /// Create a new path validator with default configuration
    pub fn new() -> Self
    
    /// Create a new path validator with custom configuration
    pub fn with_config(config: PathSecurityConfig) -> Self
    
    /// Add a path sanitizer to the validator
    pub fn add_sanitizer(&mut self, sanitizer: Box<dyn PathSanitizer>)
    
    /// Add a path validator to the validator
    pub fn add_validator(&mut self, validator: Box<dyn PathValidator>)
    
    /// Add an attack detector to the validator
    pub fn add_detector(&mut self, detector: Box<dyn AttackDetector>)
    
    /// Validate a path for security issues
    pub async fn validate_path(&self, path: &str) -> Result<PathValidationResult, PathSecurityError>
    
    /// Sanitize a path to remove security threats
    pub async fn sanitize_path(&self, path: &str) -> Result<String, PathSecurityError>
    
    /// Detect attacks in a path
    pub async fn detect_attacks(&self, path: &str) -> Result<Vec<Attack>, PathSecurityError>
}
```

### PathSecurityConfig

Configuration for the path security validator.

```rust
pub struct PathSecurityConfig {
    pub enable_traversal_detection: bool,
    pub enable_encoding_attack_detection: bool,
    pub enable_unicode_attack_detection: bool,
    pub enable_project_name_validation: bool,
    pub enable_filename_sanitization: bool,
    pub enable_cross_platform_compatibility: bool,
    pub enable_windows_attack_detection: bool,
    pub max_path_length: usize,
    pub allowed_characters: Vec<char>,
    pub blocked_patterns: Vec<Regex>,
    pub timeout_duration: Duration,
}

impl PathSecurityConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self
    
    /// Create a new configuration with custom values
    pub fn with_values(
        enable_traversal_detection: bool,
        enable_encoding_attack_detection: bool,
        enable_unicode_attack_detection: bool,
        enable_project_name_validation: bool,
        enable_filename_sanitization: bool,
        enable_cross_platform_compatibility: bool,
        enable_windows_attack_detection: bool,
        max_path_length: usize,
        allowed_characters: Vec<char>,
        blocked_patterns: Vec<Regex>,
        timeout_duration: Duration,
    ) -> Self
}
```

## Path Sanitization

### PathSanitizer Trait

Base trait for path sanitization.

```rust
#[async_trait]
pub trait PathSanitizer: Send + Sync {
    /// Sanitize a path to remove security threats
    async fn sanitize(&self, path: &str) -> Result<String, PathSecurityError>;
    
    /// Get the name of the sanitizer
    fn name(&self) -> &str;
    
    /// Get the priority of the sanitizer
    fn priority(&self) -> Priority;
    
    /// Check if the sanitizer is enabled
    fn is_enabled(&self) -> bool;
}
```

### TraversalSanitizer

Sanitizes path traversal attacks.

```rust
pub struct TraversalSanitizer {
    patterns: Vec<Regex>,
    config: TraversalSanitizerConfig,
}

impl TraversalSanitizer {
    /// Create a new traversal sanitizer
    pub fn new() -> Self
    
    /// Create a new sanitizer with custom patterns
    pub fn with_patterns(patterns: Vec<Regex>) -> Self
    
    /// Add a custom pattern
    pub fn add_pattern(&mut self, pattern: Regex)
    
    /// Remove a pattern
    pub fn remove_pattern(&mut self, pattern: &Regex)
    
    /// Get all patterns
    pub fn get_patterns(&self) -> &[Regex]
}

#[async_trait]
impl PathSanitizer for TraversalSanitizer {
    async fn sanitize(&self, path: &str) -> Result<String, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

### EncodingSanitizer

Sanitizes encoding attacks.

```rust
pub struct EncodingSanitizer {
    config: EncodingSanitizerConfig,
}

impl EncodingSanitizer {
    /// Create a new encoding sanitizer
    pub fn new() -> Self
    
    /// Create a new sanitizer with custom configuration
    pub fn with_config(config: EncodingSanitizerConfig) -> Self
    
    /// Sanitize URL encoding attacks
    pub fn sanitize_url_encoding(&self, path: &str) -> String
    
    /// Sanitize UTF-8 encoding attacks
    pub fn sanitize_utf8_encoding(&self, path: &str) -> String
    
    /// Sanitize Unicode encoding attacks
    pub fn sanitize_unicode_encoding(&self, path: &str) -> String
}

#[async_trait]
impl PathSanitizer for EncodingSanitizer {
    async fn sanitize(&self, path: &str) -> Result<String, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

### UnicodeSanitizer

Sanitizes Unicode attacks.

```rust
pub struct UnicodeSanitizer {
    config: UnicodeSanitizerConfig,
}

impl UnicodeSanitizer {
    /// Create a new Unicode sanitizer
    pub fn new() -> Self
    
    /// Create a new sanitizer with custom configuration
    pub fn with_config(config: UnicodeSanitizerConfig) -> Self
    
    /// Sanitize Unicode normalization attacks
    pub fn sanitize_normalization(&self, path: &str) -> String
    
    /// Sanitize Unicode encoding attacks
    pub fn sanitize_encoding(&self, path: &str) -> String
    
    /// Sanitize Unicode visual spoofing
    pub fn sanitize_visual_spoofing(&self, path: &str) -> String
}

#[async_trait]
impl PathSanitizer for UnicodeSanitizer {
    async fn sanitize(&self, path: &str) -> Result<String, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

## Path Validation

### PathValidator Trait

Base trait for path validation.

```rust
#[async_trait]
pub trait PathValidator: Send + Sync {
    /// Validate a path for security issues
    async fn validate(&self, path: &str) -> Result<PathValidationResult, PathSecurityError>;
    
    /// Get the name of the validator
    fn name(&self) -> &str;
    
    /// Get the priority of the validator
    fn priority(&self) -> Priority;
    
    /// Check if the validator is enabled
    fn is_enabled(&self) -> bool;
}
```

### ProjectNameValidator

Validates project names for security issues.

```rust
pub struct ProjectNameValidator {
    config: ProjectNameValidatorConfig,
}

impl ProjectNameValidator {
    /// Create a new project name validator
    pub fn new() -> Self
    
    /// Create a new validator with custom configuration
    pub fn with_config(config: ProjectNameValidatorConfig) -> Self
    
    /// Validate project name format
    pub fn validate_format(&self, name: &str) -> ValidationResult
    
    /// Validate project name characters
    pub fn validate_characters(&self, name: &str) -> ValidationResult
    
    /// Validate project name length
    pub fn validate_length(&self, name: &str) -> ValidationResult
}

#[async_trait]
impl PathValidator for ProjectNameValidator {
    async fn validate(&self, path: &str) -> Result<PathValidationResult, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

### FilenameValidator

Validates filenames for security issues.

```rust
pub struct FilenameValidator {
    config: FilenameValidatorConfig,
}

impl FilenameValidator {
    /// Create a new filename validator
    pub fn new() -> Self
    
    /// Create a new validator with custom configuration
    pub fn with_config(config: FilenameValidatorConfig) -> Self
    
    /// Validate filename format
    pub fn validate_format(&self, filename: &str) -> ValidationResult
    
    /// Validate filename characters
    pub fn validate_characters(&self, filename: &str) -> ValidationResult
    
    /// Validate filename length
    pub fn validate_length(&self, filename: &str) -> ValidationResult
}

#[async_trait]
impl PathValidator for FilenameValidator {
    async fn validate(&self, path: &str) -> Result<PathValidationResult, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

## Attack Detection

### AttackDetector Trait

Base trait for attack detection.

```rust
#[async_trait]
pub trait AttackDetector: Send + Sync {
    /// Detect attacks in a path
    async fn detect(&self, path: &str) -> Result<Vec<Attack>, PathSecurityError>;
    
    /// Get the name of the detector
    fn name(&self) -> &str;
    
    /// Get the priority of the detector
    fn priority(&self) -> Priority;
    
    /// Check if the detector is enabled
    fn is_enabled(&self) -> bool;
}
```

### TraversalDetector

Detects path traversal attacks.

```rust
pub struct TraversalDetector {
    patterns: Vec<Regex>,
    config: TraversalDetectorConfig,
}

impl TraversalDetector {
    /// Create a new traversal detector
    pub fn new() -> Self
    
    /// Create a new detector with custom patterns
    pub fn with_patterns(patterns: Vec<Regex>) -> Self
    
    /// Add a custom pattern
    pub fn add_pattern(&mut self, pattern: Regex)
    
    /// Remove a pattern
    pub fn remove_pattern(&mut self, pattern: &Regex)
    
    /// Get all patterns
    pub fn get_patterns(&self) -> &[Regex]
}

#[async_trait]
impl AttackDetector for TraversalDetector {
    async fn detect(&self, path: &str) -> Result<Vec<Attack>, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

### EncodingAttackDetector

Detects encoding attacks.

```rust
pub struct EncodingAttackDetector {
    config: EncodingAttackDetectorConfig,
}

impl EncodingAttackDetector {
    /// Create a new encoding attack detector
    pub fn new() -> Self
    
    /// Create a new detector with custom configuration
    pub fn with_config(config: EncodingAttackDetectorConfig) -> Self
    
    /// Detect URL encoding attacks
    pub fn detect_url_encoding(&self, path: &str) -> Vec<Attack>
    
    /// Detect UTF-8 encoding attacks
    pub fn detect_utf8_encoding(&self, path: &str) -> Vec<Attack>
    
    /// Detect Unicode encoding attacks
    pub fn detect_unicode_encoding(&self, path: &str) -> Vec<Attack>
}

#[async_trait]
impl AttackDetector for EncodingAttackDetector {
    async fn detect(&self, path: &str) -> Result<Vec<Attack>, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

### UnicodeAttackDetector

Detects Unicode attacks.

```rust
pub struct UnicodeAttackDetector {
    config: UnicodeAttackDetectorConfig,
}

impl UnicodeAttackDetector {
    /// Create a new Unicode attack detector
    pub fn new() -> Self
    
    /// Create a new detector with custom configuration
    pub fn with_config(config: UnicodeAttackDetectorConfig) -> Self
    
    /// Detect Unicode normalization attacks
    pub fn detect_normalization(&self, path: &str) -> Vec<Attack>
    
    /// Detect Unicode encoding attacks
    pub fn detect_encoding(&self, path: &str) -> Vec<Attack>
    
    /// Detect Unicode visual spoofing
    pub fn detect_visual_spoofing(&self, path: &str) -> Vec<Attack>
}

#[async_trait]
impl AttackDetector for UnicodeAttackDetector {
    async fn detect(&self, path: &str) -> Result<Vec<Attack>, PathSecurityError>
    fn name(&self) -> &str
    fn priority(&self) -> Priority
    fn is_enabled(&self) -> bool
}
```

## Data Types

### Attack

Represents a detected security attack.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attack {
    pub id: String,
    pub attack_type: AttackType,
    pub severity: Severity,
    pub description: String,
    pub location: AttackLocation,
    pub confidence: f64,
    pub metadata: HashMap<String, Value>,
    pub created_at: DateTime<Utc>,
}

impl Attack {
    /// Create a new attack
    pub fn new(
        id: String,
        attack_type: AttackType,
        severity: Severity,
        description: String,
        location: AttackLocation,
        confidence: f64,
    ) -> Self
    
    /// Get the attack ID
    pub fn id(&self) -> &str
    
    /// Get the attack type
    pub fn attack_type(&self) -> &AttackType
    
    /// Get the severity
    pub fn severity(&self) -> &Severity
    
    /// Get the description
    pub fn description(&self) -> &str
    
    /// Get the location
    pub fn location(&self) -> &AttackLocation
    
    /// Get the confidence
    pub fn confidence(&self) -> f64
    
    /// Get the metadata
    pub fn metadata(&self) -> &HashMap<String, Value>
    
    /// Set metadata
    pub fn set_metadata(&mut self, key: String, value: Value)
    
    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&Value>
}
```

### AttackType

Enumeration of attack types.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    PathTraversal,
    EncodingAttack,
    UnicodeAttack,
    ProjectNameAttack,
    FilenameAttack,
    CrossPlatformAttack,
    WindowsAttack,
    Other(String),
}

impl AttackType {
    /// Get the display name of the attack type
    pub fn display_name(&self) -> &str
    
    /// Get the description of the attack type
    pub fn description(&self) -> &str
    
    /// Check if this is a high-priority attack type
    pub fn is_high_priority(&self) -> bool
}
```

### Severity

Enumeration of attack severity levels.

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Get the numeric value of the severity
    pub fn value(&self) -> u8
    
    /// Get the display name of the severity
    pub fn display_name(&self) -> &str
    
    /// Check if this severity requires immediate action
    pub fn requires_immediate_action(&self) -> bool
}
```

### AttackLocation

Represents the location of an attack in the path.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackLocation {
    pub start: usize,
    pub end: usize,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl AttackLocation {
    /// Create a new attack location
    pub fn new(start: usize, end: usize) -> Self
    
    /// Create a new attack location with line and column
    pub fn with_position(start: usize, end: usize, line: usize, column: usize) -> Self
    
    /// Get the start position
    pub fn start(&self) -> usize
    
    /// Get the end position
    pub fn end(&self) -> usize
    
    /// Get the line number
    pub fn line(&self) -> Option<usize>
    
    /// Get the column number
    pub fn column(&self) -> Option<usize>
    
    /// Get the length of the attack
    pub fn length(&self) -> usize
}
```

### PathValidationResult

Result of path validation.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathValidationResult {
    pub is_valid: bool,
    pub attacks: Vec<Attack>,
    pub confidence: f64,
    pub validation_time: Duration,
    pub metadata: HashMap<String, Value>,
}

impl PathValidationResult {
    /// Create a new path validation result
    pub fn new(is_valid: bool, attacks: Vec<Attack>, confidence: f64, validation_time: Duration) -> Self
    
    /// Check if the path is valid
    pub fn is_valid(&self) -> bool
    
    /// Get all detected attacks
    pub fn attacks(&self) -> &[Attack]
    
    /// Get the confidence level
    pub fn confidence(&self) -> f64
    
    /// Get the validation time
    pub fn validation_time(&self) -> Duration
    
    /// Get the metadata
    pub fn metadata(&self) -> &HashMap<String, Value>
    
    /// Set metadata
    pub fn set_metadata(&mut self, key: String, value: Value)
    
    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&Value>
}
```

## Error Types

### PathSecurityError

Main error type for path security operations.

```rust
#[derive(Debug, thiserror::Error)]
pub enum PathSecurityError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Sanitization error: {0}")]
    Sanitization(String),
    
    #[error("Detection error: {0}")]
    Detection(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl PathSecurityError {
    /// Create a new configuration error
    pub fn configuration(msg: impl Into<String>) -> Self
    
    /// Create a new validation error
    pub fn validation(msg: impl Into<String>) -> Self
    
    /// Create a new sanitization error
    pub fn sanitization(msg: impl Into<String>) -> Self
    
    /// Create a new detection error
    pub fn detection(msg: impl Into<String>) -> Self
    
    /// Create a new timeout error
    pub fn timeout(msg: impl Into<String>) -> Self
    
    /// Create a new unknown error
    pub fn unknown(msg: impl Into<String>) -> Self
}
```

## Utility Functions

### Path Processing

```rust
/// Normalize a path for cross-platform compatibility
pub fn normalize_path(path: &str) -> String

/// Check if a path is safe
pub fn is_safe_path(path: &str) -> bool

/// Get the canonical path
pub fn canonicalize_path(path: &str) -> Result<String, PathSecurityError>

/// Join paths safely
pub fn join_paths(paths: &[&str]) -> Result<String, PathSecurityError>
```

### Character Processing

```rust
/// Sanitize characters in a path
pub fn sanitize_characters(path: &str) -> String

/// Check if characters are allowed
pub fn are_characters_allowed(path: &str, allowed: &[char]) -> bool

/// Remove dangerous characters
pub fn remove_dangerous_characters(path: &str) -> String

/// Normalize Unicode characters
pub fn normalize_unicode(path: &str) -> String
```

### Security Utilities

```rust
/// Calculate attack confidence
pub fn calculate_confidence(attacks: &[Attack]) -> f64

/// Merge attack lists
pub fn merge_attacks(attacks1: Vec<Attack>, attacks2: Vec<Attack>) -> Vec<Attack>

/// Filter attacks by severity
pub fn filter_attacks_by_severity(attacks: Vec<Attack>, min_severity: Severity) -> Vec<Attack>

/// Sort attacks by priority
pub fn sort_attacks_by_priority(attacks: Vec<Attack>) -> Vec<Attack>
```

## Configuration Types

### TraversalSanitizerConfig

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalSanitizerConfig {
    pub patterns: Vec<String>,
    pub case_sensitive: bool,
    pub enable_fuzzy_matching: bool,
    pub fuzzy_threshold: f64,
    pub max_patterns: usize,
}

impl TraversalSanitizerConfig {
    pub fn new() -> Self
    pub fn with_patterns(patterns: Vec<String>) -> Self
    pub fn with_case_sensitive(case_sensitive: bool) -> Self
    pub fn with_fuzzy_matching(enable: bool, threshold: f64) -> Self
}
```

### EncodingSanitizerConfig

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingSanitizerConfig {
    pub enable_url_encoding: bool,
    pub enable_utf8_encoding: bool,
    pub enable_unicode_encoding: bool,
    pub encoding_threshold: f64,
    pub normalization_threshold: f64,
}

impl EncodingSanitizerConfig {
    pub fn new() -> Self
    pub fn with_url_encoding(enable: bool, threshold: f64) -> Self
    pub fn with_utf8_encoding(enable: bool, threshold: f64) -> Self
    pub fn with_unicode_encoding(enable: bool, threshold: f64) -> Self
}
```

### UnicodeSanitizerConfig

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicodeSanitizerConfig {
    pub enable_normalization: bool,
    pub enable_encoding: bool,
    pub enable_visual_spoofing: bool,
    pub normalization_threshold: f64,
    pub encoding_threshold: f64,
    pub visual_spoofing_threshold: f64,
}

impl UnicodeSanitizerConfig {
    pub fn new() -> Self
    pub fn with_normalization(enable: bool, threshold: f64) -> Self
    pub fn with_encoding(enable: bool, threshold: f64) -> Self
    pub fn with_visual_spoofing(enable: bool, threshold: f64) -> Self
}
```

## Examples

### Basic Usage

```rust
use path_security::{PathValidator, PathSecurityConfig};

// Create a new path validator
let config = PathSecurityConfig::new()
    .with_traversal_detection(true)
    .with_encoding_attack_detection(true)
    .with_unicode_attack_detection(true);

let validator = PathValidator::with_config(config);

// Validate a path
let path = "/safe/path/to/file.txt";
let result = validator.validate_path(path).await?;

if result.is_valid() {
    println!("Path is safe");
} else {
    println!("Detected {} attacks", result.attacks().len());
    for attack in result.attacks() {
        println!("Attack: {} - {}", attack.attack_type(), attack.description());
    }
}
```

### Advanced Configuration

```rust
use path_security::{PathValidator, PathSecurityConfig, TraversalDetector, EncodingDetector};

// Create custom configuration
let config = PathSecurityConfig::new()
    .with_traversal_detection(true)
    .with_encoding_attack_detection(true)
    .with_unicode_attack_detection(true)
    .with_project_name_validation(true)
    .with_filename_sanitization(true)
    .with_cross_platform_compatibility(true)
    .with_windows_attack_detection(true)
    .with_max_path_length(4096)
    .with_timeout_duration(Duration::from_secs(30));

let mut validator = PathValidator::with_config(config);

// Add custom detectors
let traversal_detector = TraversalDetector::new()
    .with_patterns(vec![
        r"\.\.",
        r"\.\.",
        r"\.\.",
        r"\.\.",
    ]);

let encoding_detector = EncodingDetector::new()
    .with_url_encoding_detection(true)
    .with_utf8_encoding_detection(true)
    .with_unicode_encoding_detection(true);

validator.add_detector(Box::new(traversal_detector));
validator.add_detector(Box::new(encoding_detector));

// Validate path
let result = validator.validate_path("path/to/validate").await?;
```

### Error Handling

```rust
use path_security::{PathValidator, PathSecurityError};

let validator = PathValidator::new();

match validator.validate_path("path/to/validate").await {
    Ok(result) => {
        if result.is_valid() {
            println!("Path is valid");
        } else {
            println!("Path validation failed: {} attacks", result.attacks().len());
        }
    }
    Err(PathSecurityError::Configuration(msg)) => {
        eprintln!("Configuration error: {}", msg);
    }
    Err(PathSecurityError::Validation(msg)) => {
        eprintln!("Validation error: {}", msg);
    }
    Err(PathSecurityError::Timeout(msg)) => {
        eprintln!("Timeout error: {}", msg);
    }
    Err(e) => {
        eprintln!("Unknown error: {}", e);
    }
}
```
