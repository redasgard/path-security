# Attack Examples - Path Security

## Overview

This document provides comprehensive examples of path-based attacks and how the Path Security module protects against them. Each example includes the attack description, malicious payload, detection method, and protection mechanism.

## Path Traversal Attacks

### 1. Basic Directory Traversal

#### Attack Description
Basic directory traversal using `../` sequences to access files outside the intended directory.

#### Malicious Payload
```
../../../etc/passwd
../../../../var/log/system.log
../../../home/user/.ssh/id_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, TraversalDetector};

let detector = TraversalDetector::new()
    .with_patterns(vec![
        r"\.\.",
        r"\.\.",
        r"\.\.",
        r"\.\.",
    ]);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect traversal attacks
let result = validator.validate_path("../../../etc/passwd").await?;
if !result.is_valid() {
    println!("Directory traversal detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, TraversalSanitizer};

let sanitizer = TraversalSanitizer::new()
    .with_patterns(vec![
        r"\.\.",
        r"\.\.",
        r"\.\.",
        r"\.\.",
    ]);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize traversal attacks
let sanitized_path = validator.sanitize_path("../../../etc/passwd").await?;
println!("Sanitized path: {}", sanitized_path);
```

### 2. Encoded Directory Traversal

#### Attack Description
Directory traversal using URL encoding to bypass basic detection.

#### Malicious Payload
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fvar%2flog%2fsystem.log
%2e%2e%2f%2e%2e%2f%2e%2e%2fhome%2fuser%2f.ssh%2fid_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, EncodingAttackDetector};

let detector = EncodingAttackDetector::new()
    .with_url_encoding_detection(true)
    .with_utf8_encoding_detection(true)
    .with_unicode_encoding_detection(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect encoded traversal attacks
let result = validator.validate_path("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd").await?;
if !result.is_valid() {
    println!("Encoded traversal detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, EncodingSanitizer};

let sanitizer = EncodingSanitizer::new()
    .with_url_encoding_sanitization(true)
    .with_utf8_encoding_sanitization(true)
    .with_unicode_encoding_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize encoded traversal attacks
let sanitized_path = validator.sanitize_path("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd").await?;
println!("Sanitized path: {}", sanitized_path);
```

### 3. Double Encoding Traversal

#### Attack Description
Directory traversal using double URL encoding to bypass detection.

#### Malicious Payload
```
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fvar%252flog%252fsystem.log
%252e%252e%252f%252e%252e%252f%252e%252e%252fhome%252fuser%252f.ssh%252fid_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, EncodingAttackDetector};

let detector = EncodingAttackDetector::new()
    .with_double_encoding_detection(true)
    .with_nested_encoding_detection(true)
    .with_encoding_depth_analysis(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect double encoded traversal attacks
let result = validator.validate_path("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd").await?;
if !result.is_valid() {
    println!("Double encoded traversal detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, EncodingSanitizer};

let sanitizer = EncodingSanitizer::new()
    .with_double_encoding_sanitization(true)
    .with_nested_encoding_sanitization(true)
    .with_encoding_depth_analysis(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize double encoded traversal attacks
let sanitized_path = validator.sanitize_path("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd").await?;
println!("Sanitized path: {}", sanitized_path);
```

## Unicode Attacks

### 1. Unicode Normalization Attacks

#### Attack Description
Using Unicode normalization to bypass path validation by exploiting different Unicode representations of the same character.

#### Malicious Payload
```
..\u002f..\u002f..\u002fetc\u002fpasswd
..\u002f..\u002f..\u002fvar\u002flog\u002fsystem.log
..\u002f..\u002f..\u002fhome\u002fuser\u002f.ssh\u002fid_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, UnicodeAttackDetector};

let detector = UnicodeAttackDetector::new()
    .with_normalization_detection(true)
    .with_encoding_detection(true)
    .with_visual_spoofing_detection(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect Unicode normalization attacks
let result = validator.validate_path("..\u002f..\u002f..\u002fetc\u002fpasswd").await?;
if !result.is_valid() {
    println!("Unicode normalization attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, UnicodeSanitizer};

let sanitizer = UnicodeSanitizer::new()
    .with_normalization_sanitization(true)
    .with_encoding_sanitization(true)
    .with_visual_spoofing_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize Unicode normalization attacks
let sanitized_path = validator.sanitize_path("..\u002f..\u002f..\u002fetc\u002fpasswd").await?;
println!("Sanitized path: {}", sanitized_path);
```

### 2. Unicode Visual Spoofing

#### Attack Description
Using visually similar Unicode characters to bypass path validation.

#### Malicious Payload
```
..\u2215..\u2215..\u2215etc\u2215passwd
..\u2215..\u2215..\u2215var\u2215log\u2215system.log
..\u2215..\u2215..\u2215home\u2215user\u2215.ssh\u2215id_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, UnicodeAttackDetector};

let detector = UnicodeAttackDetector::new()
    .with_visual_spoofing_detection(true)
    .with_homoglyph_detection(true)
    .with_character_similarity_analysis(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect Unicode visual spoofing attacks
let result = validator.validate_path("..\u2215..\u2215..\u2215etc\u2215passwd").await?;
if !result.is_valid() {
    println!("Unicode visual spoofing attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, UnicodeSanitizer};

let sanitizer = UnicodeSanitizer::new()
    .with_visual_spoofing_sanitization(true)
    .with_homoglyph_sanitization(true)
    .with_character_similarity_analysis(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize Unicode visual spoofing attacks
let sanitized_path = validator.sanitize_path("..\u2215..\u2215..\u2215etc\u2215passwd").await?;
println!("Sanitized path: {}", sanitized_path);
```

### 3. Unicode Encoding Attacks

#### Attack Description
Using Unicode encoding to bypass path validation by exploiting different Unicode representations.

#### Malicious Payload
```
..\u002f..\u002f..\u002fetc\u002fpasswd
..\u002f..\u002f..\u002fvar\u002flog\u002fsystem.log
..\u002f..\u002f..\u002fhome\u002fuser\u002f.ssh\u002fid_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, UnicodeAttackDetector};

let detector = UnicodeAttackDetector::new()
    .with_encoding_detection(true)
    .with_unicode_escape_detection(true)
    .with_unicode_sequence_detection(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect Unicode encoding attacks
let result = validator.validate_path("..\u002f..\u002f..\u002fetc\u002fpasswd").await?;
if !result.is_valid() {
    println!("Unicode encoding attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, UnicodeSanitizer};

let sanitizer = UnicodeSanitizer::new()
    .with_encoding_sanitization(true)
    .with_unicode_escape_sanitization(true)
    .with_unicode_sequence_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize Unicode encoding attacks
let sanitized_path = validator.sanitize_path("..\u002f..\u002f..\u002fetc\u002fpasswd").await?;
println!("Sanitized path: {}", sanitized_path);
```

## Project Name Attacks

### 1. Malicious Project Names

#### Attack Description
Using malicious project names to exploit path validation vulnerabilities.

#### Malicious Payload
```
../../../etc/passwd
../../../../var/log/system.log
../../../home/user/.ssh/id_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, ProjectNameValidator};

let validator = ProjectNameValidator::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true);

let validator = PathValidator::new()
    .add_validator(Box::new(validator));

// Detect malicious project names
let result = validator.validate_path("../../../etc/passwd").await?;
if !result.is_valid() {
    println!("Malicious project name detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, ProjectNameSanitizer};

let sanitizer = ProjectNameSanitizer::new()
    .with_traversal_sanitization(true)
    .with_encoding_sanitization(true)
    .with_unicode_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize malicious project names
let sanitized_name = validator.sanitize_path("../../../etc/passwd").await?;
println!("Sanitized project name: {}", sanitized_name);
```

### 2. Reserved Name Attacks

#### Attack Description
Using reserved system names to exploit path validation vulnerabilities.

#### Malicious Payload
```
CON
PRN
AUX
NUL
COM1
COM2
COM3
COM4
COM5
COM6
COM7
COM8
COM9
LPT1
LPT2
LPT3
LPT4
LPT5
LPT6
LPT7
LPT8
LPT9
```

#### Detection Method
```rust
use path_security::{PathValidator, ReservedNameDetector};

let detector = ReservedNameDetector::new()
    .with_windows_reserved_names(true)
    .with_unix_reserved_names(true)
    .with_system_reserved_names(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect reserved name attacks
let result = validator.validate_path("CON").await?;
if !result.is_valid() {
    println!("Reserved name attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, ReservedNameSanitizer};

let sanitizer = ReservedNameSanitizer::new()
    .with_windows_reserved_names(true)
    .with_unix_reserved_names(true)
    .with_system_reserved_names(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize reserved name attacks
let sanitized_name = validator.sanitize_path("CON").await?;
println!("Sanitized name: {}", sanitized_name);
```

## Filename Attacks

### 1. Malicious Filenames

#### Attack Description
Using malicious filenames to exploit path validation vulnerabilities.

#### Malicious Payload
```
../../../etc/passwd
../../../../var/log/system.log
../../../home/user/.ssh/id_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, FilenameValidator};

let validator = FilenameValidator::new()
    .with_traversal_detection(true)
    .with_encoding_detection(true)
    .with_unicode_detection(true);

let validator = PathValidator::new()
    .add_validator(Box::new(validator));

// Detect malicious filenames
let result = validator.validate_path("../../../etc/passwd").await?;
if !result.is_valid() {
    println!("Malicious filename detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, FilenameSanitizer};

let sanitizer = FilenameSanitizer::new()
    .with_traversal_sanitization(true)
    .with_encoding_sanitization(true)
    .with_unicode_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize malicious filenames
let sanitized_filename = validator.sanitize_path("../../../etc/passwd").await?;
println!("Sanitized filename: {}", sanitized_filename);
```

### 2. Special Character Attacks

#### Attack Description
Using special characters in filenames to exploit path validation vulnerabilities.

#### Malicious Payload
```
file<name>.txt
file>name>.txt
file|name>.txt
file:name>.txt
file"name>.txt
file*name>.txt
file?name>.txt
file\name>.txt
file/name>.txt
```

#### Detection Method
```rust
use path_security::{PathValidator, SpecialCharacterDetector};

let detector = SpecialCharacterDetector::new()
    .with_windows_special_characters(true)
    .with_unix_special_characters(true)
    .with_unicode_special_characters(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect special character attacks
let result = validator.validate_path("file<name>.txt").await?;
if !result.is_valid() {
    println!("Special character attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, SpecialCharacterSanitizer};

let sanitizer = SpecialCharacterSanitizer::new()
    .with_windows_special_characters(true)
    .with_unix_special_characters(true)
    .with_unicode_special_characters(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize special character attacks
let sanitized_filename = validator.sanitize_path("file<name>.txt").await?;
println!("Sanitized filename: {}", sanitized_filename);
```

## Cross-Platform Attacks

### 1. Windows-Specific Attacks

#### Attack Description
Using Windows-specific path features to exploit path validation vulnerabilities.

#### Malicious Payload
```
C:\..\..\..\etc\passwd
C:\..\..\..\var\log\system.log
C:\..\..\..\home\user\.ssh\id_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, WindowsAttackDetector};

let detector = WindowsAttackDetector::new()
    .with_drive_letter_attacks(true)
    .with_unc_path_attacks(true)
    .with_windows_special_paths(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect Windows-specific attacks
let result = validator.validate_path("C:\\..\\..\\..\\etc\\passwd").await?;
if !result.is_valid() {
    println!("Windows-specific attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, WindowsSanitizer};

let sanitizer = WindowsSanitizer::new()
    .with_drive_letter_sanitization(true)
    .with_unc_path_sanitization(true)
    .with_windows_special_paths_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize Windows-specific attacks
let sanitized_path = validator.sanitize_path("C:\\..\\..\\..\\etc\\passwd").await?;
println!("Sanitized path: {}", sanitized_path);
```

### 2. Unix-Specific Attacks

#### Attack Description
Using Unix-specific path features to exploit path validation vulnerabilities.

#### Malicious Payload
```
../../../etc/passwd
../../../../var/log/system.log
../../../home/user/.ssh/id_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, UnixAttackDetector};

let detector = UnixAttackDetector::new()
    .with_absolute_path_attacks(true)
    .with_relative_path_attacks(true)
    .with_unix_special_paths(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect Unix-specific attacks
let result = validator.validate_path("../../../etc/passwd").await?;
if !result.is_valid() {
    println!("Unix-specific attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, UnixSanitizer};

let sanitizer = UnixSanitizer::new()
    .with_absolute_path_sanitization(true)
    .with_relative_path_sanitization(true)
    .with_unix_special_paths_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize Unix-specific attacks
let sanitized_path = validator.sanitize_path("../../../etc/passwd").await?;
println!("Sanitized path: {}", sanitized_path);
```

## Advanced Attack Techniques

### 1. Multi-Stage Attacks

#### Attack Description
Combining multiple attack techniques to bypass security measures.

#### Malicious Payload
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fvar%252flog%252fsystem.log
..\u002f..\u002f..\u002fhome\u002fuser\u002f.ssh\u002fid_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, MultiStageAttackDetector};

let detector = MultiStageAttackDetector::new()
    .with_encoding_combination_detection(true)
    .with_unicode_combination_detection(true)
    .with_traversal_combination_detection(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect multi-stage attacks
let result = validator.validate_path("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd").await?;
if !result.is_valid() {
    println!("Multi-stage attack detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, MultiStageSanitizer};

let sanitizer = MultiStageSanitizer::new()
    .with_encoding_combination_sanitization(true)
    .with_unicode_combination_sanitization(true)
    .with_traversal_combination_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize multi-stage attacks
let sanitized_path = validator.sanitize_path("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd").await?;
println!("Sanitized path: {}", sanitized_path);
```

### 2. Evasion Techniques

#### Attack Description
Using evasion techniques to bypass security measures.

#### Malicious Payload
```
..\u002f..\u002f..\u002fetc\u002fpasswd
..\u002f..\u002f..\u002fvar\u002flog\u002fsystem.log
..\u002f..\u002f..\u002fhome\u002fuser\u002f.ssh\u002fid_rsa
```

#### Detection Method
```rust
use path_security::{PathValidator, EvasionDetector};

let detector = EvasionDetector::new()
    .with_unicode_evasion_detection(true)
    .with_encoding_evasion_detection(true)
    .with_normalization_evasion_detection(true);

let validator = PathValidator::new()
    .add_detector(Box::new(detector));

// Detect evasion techniques
let result = validator.validate_path("..\u002f..\u002f..\u002fetc\u002fpasswd").await?;
if !result.is_valid() {
    println!("Evasion technique detected: {} attacks", result.attacks().len());
}
```

#### Protection Mechanism
```rust
use path_security::{PathValidator, EvasionSanitizer};

let sanitizer = EvasionSanitizer::new()
    .with_unicode_evasion_sanitization(true)
    .with_encoding_evasion_sanitization(true)
    .with_normalization_evasion_sanitization(true);

let validator = PathValidator::new()
    .add_sanitizer(Box::new(sanitizer));

// Sanitize evasion techniques
let sanitized_path = validator.sanitize_path("..\u002f..\u002f..\u002fetc\u002fpasswd").await?;
println!("Sanitized path: {}", sanitized_path);
```

## Best Practices

### 1. Defense in Depth

```rust
use path_security::{PathValidator, DefenseInDepth};

// Implement defense in depth
let defense_in_depth = DefenseInDepth::new()
    .with_multiple_detection_layers(true)
    .with_redundant_validation(true)
    .with_comprehensive_sanitization(true)
    .with_continuous_monitoring(true);

let validator = PathValidator::new()
    .with_defense_in_depth(defense_in_depth);
```

### 2. Comprehensive Coverage

```rust
use path_security::{PathValidator, ComprehensiveCoverage};

// Implement comprehensive coverage
let comprehensive_coverage = ComprehensiveCoverage::new()
    .with_all_attack_vectors(true)
    .with_all_encoding_types(true)
    .with_all_unicode_attacks(true)
    .with_all_platform_attacks(true);

let validator = PathValidator::new()
    .with_comprehensive_coverage(comprehensive_coverage);
```

### 3. Continuous Monitoring

```rust
use path_security::{PathValidator, ContinuousMonitoring};

// Implement continuous monitoring
let continuous_monitoring = ContinuousMonitoring::new()
    .with_real_time_monitoring(true)
    .with_threat_detection(true)
    .with_anomaly_detection(true)
    .with_incident_response(true);

let validator = PathValidator::new()
    .with_continuous_monitoring(continuous_monitoring);
```

## Conclusion

The Path Security module provides comprehensive protection against all known path-based attacks. By implementing multiple detection layers, sanitization mechanisms, and validation controls, it ensures that applications are protected from:

- **Path Traversal Attacks**: All forms of directory traversal
- **Encoding Attacks**: URL, UTF-8, and Unicode encoding attacks
- **Unicode Attacks**: Normalization, visual spoofing, and encoding attacks
- **Project Name Attacks**: Malicious project names and reserved names
- **Filename Attacks**: Malicious filenames and special characters
- **Cross-Platform Attacks**: Windows and Unix-specific attacks
- **Advanced Techniques**: Multi-stage and evasion attacks

The module's comprehensive approach ensures that applications are protected from current and emerging path-based security threats while maintaining high performance and usability.
