//! Basic usage examples for path-security

use path_security::{validate_path, validate_project_name, validate_filename};
use std::path::Path;
use tempfile::TempDir;

fn main() -> anyhow::Result<()> {
    println!("=== Path Security Examples ===\n");
    
    // Example 1: Path Validation
    println!("1. Path Validation");
    println!("-------------------");
    
    let temp_dir = TempDir::new()?;
    let base_dir = temp_dir.path();
    
    // Create a safe subdirectory
    std::fs::create_dir(base_dir.join("uploads"))?;
    
    // Safe path - will succeed
    let safe_path = Path::new("uploads/document.pdf");
    match validate_path(safe_path, base_dir) {
        Ok(canonical) => println!("✓ Safe path accepted: {}", canonical.display()),
        Err(e) => println!("✗ Path rejected: {}", e),
    }
    
    // Dangerous path - will fail
    let dangerous_path = Path::new("../../../etc/passwd");
    match validate_path(dangerous_path, base_dir) {
        Ok(_) => println!("✗ Dangerous path was incorrectly accepted!"),
        Err(e) => println!("✓ Dangerous path blocked: {}", e),
    }
    
    // Example 2: Project Name Validation
    println!("\n2. Project Name Validation");
    println!("---------------------------");
    
    let valid_names = vec![
        "my-project",
        "awesome_app",
        "Project123",
    ];
    
    for name in valid_names {
        match validate_project_name(name) {
            Ok(_) => println!("✓ Valid project name: '{}'", name),
            Err(e) => println!("✗ Invalid project name '{}': {}", name, e),
        }
    }
    
    let invalid_names = vec![
        "-bad-start",
        "bad-end_",
        "has/slash",
        "CON",  // Windows reserved
        "",
    ];
    
    for name in invalid_names {
        match validate_project_name(name) {
            Ok(_) => println!("✗ Invalid name incorrectly accepted: '{}'", name),
            Err(e) => println!("✓ Invalid name '{}' blocked: {}", name, e),
        }
    }
    
    // Example 3: Filename Validation
    println!("\n3. Filename Validation");
    println!("----------------------");
    
    let valid_files = vec![
        "document.pdf",
        "report-2024.xlsx",
        "my_file.txt",
    ];
    
    for filename in valid_files {
        match validate_filename(filename) {
            Ok(_) => println!("✓ Valid filename: '{}'", filename),
            Err(e) => println!("✗ Invalid filename '{}': {}", filename, e),
        }
    }
    
    let invalid_files = vec![
        "../passwd",
        ".",
        "..",
        "/etc/passwd",
        "file\0.txt",
    ];
    
    for filename in invalid_files {
        match validate_filename(filename) {
            Ok(_) => println!("✗ Invalid filename incorrectly accepted: '{}'", filename),
            Err(e) => println!("✓ Invalid filename blocked: {}", e),
        }
    }
    
    // Example 4: Real-world scenario - File upload handler
    println!("\n4. File Upload Handler");
    println!("----------------------");
    
    fn handle_upload(filename: &str, base_dir: &Path) -> anyhow::Result<()> {
        // Validate filename
        let safe_filename = validate_filename(filename)?;
        
        // Validate full path
        let safe_path = validate_path(Path::new(&safe_filename), base_dir)?;
        
        println!("✓ Upload accepted: {} -> {}", filename, safe_path.display());
        Ok(())
    }
    
    let upload_dir = base_dir.join("uploads");
    
    // Legitimate upload
    if let Err(e) = handle_upload("user-document.pdf", &upload_dir) {
        println!("✗ Upload failed: {}", e);
    }
    
    // Attack attempt
    if let Err(e) = handle_upload("../../../etc/passwd", &upload_dir) {
        println!("✓ Attack blocked: {}", e);
    }
    
    println!("\n=== All examples completed successfully ===");
    
    Ok(())
}

