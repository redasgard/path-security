//! Comprehensive demonstration of path traversal attack vectors that are blocked
//! 
//! This example demonstrates the library's protection against 80+ attack techniques

use path_security::{validate_path, validate_filename};
use std::path::Path;
use tempfile::TempDir;

fn main() -> anyhow::Result<()> {
    println!("=== Path Traversal Attack Vector Demonstration ===\n");
    println!("This demonstrates that path-security blocks advanced attacks\n");
    
    let temp_dir = TempDir::new()?;
    let base_dir = temp_dir.path();
    std::fs::create_dir(base_dir.join("safe"))?;
    
    let mut blocked = 0;
    let mut total = 0;
    
    macro_rules! test_attack {
        ($category:expr, $attacks:expr) => {
            println!("{}:", $category);
            println!("{}", "-".repeat($category.len() + 1));
            for attack in $attacks {
                total += 1;
                match validate_path(Path::new(attack), base_dir) {
                    Ok(_) => println!("  ✗ VULNERABILITY: '{}' was accepted!", attack),
                    Err(e) => {
                        blocked += 1;
                        println!("  ✓ Blocked: '{}' - {}", attack, e);
                    }
                }
            }
            println!();
        };
    }
    
    // 1. URL Encoding Attacks
    test_attack!(
        "1. URL Encoding Attacks",
        [
            "%2e%2e%2f",           // ../
            "%2e%2e/",             // ../
            ".%2e/",               // ../
            "%2e./",               // ../
            "%2E%2E%2F",           // ../ (uppercase)
            "%5C",                 // backslash
            "file%00.txt",         // null byte
            "file%0a.txt",         // newline
        ]
    );
    
    // 2. Double URL Encoding
    test_attack!(
        "2. Double URL Encoding",
        [
            "%252e%252e%252f",     // %2e%2e%2f -> ../
            "%252e%252e/",         // %2e%2e/ -> ../
        ]
    );
    
    // 3. UTF-8 Overlong Encoding
    test_attack!(
        "3. UTF-8 Overlong Encoding",
        [
            "%c0%ae%c0%ae%c0%af",  // overlong ../
            "%c0%ae%c0%ae/",       // overlong ../
            "%c1%9c",              // overlong backslash
            "%e0%80%ae",           // 3-byte overlong dot
        ]
    );
    
    // 4. Unicode Encoding Tricks
    test_attack!(
        "4. Unicode Encoding Tricks",
        [
            "%u002e%u002e%u002f",  // Unicode percent encoding
            "&#46;&#46;&#47;",     // HTML entity encoding
        ]
    );
    
    // 5. Dangerous Unicode Characters
    println!("5. Dangerous Unicode Characters:");
    println!("--------------------------------");
    let unicode_attacks = [
        ("Zero-width space", "file\u{200B}.txt"),
        ("Zero-width non-joiner", "file\u{200C}.txt"),
        ("BOM", "file\u{FEFF}.txt"),
        ("Right-to-left override", "file\u{202E}.txt"),
        ("Unicode dot homoglyph", "\u{2024}\u{2024}/"),
        ("Unicode slash homoglyph", "dir\u{2215}file"),
        ("Full-width dot", "\u{FF0E}\u{FF0E}\u{FF0F}"),
    ];
    for (name, attack) in unicode_attacks {
        total += 1;
        match validate_path(Path::new(attack), base_dir) {
            Ok(_) => println!("  ✗ VULNERABILITY: {} was accepted!", name),
            Err(e) => {
                blocked += 1;
                println!("  ✓ Blocked {}: {}", name, e);
            }
        }
    }
    println!();
    
    // 6. Windows NTFS Streams
    test_attack!(
        "6. Windows NTFS Alternate Data Streams",
        [
            "file.txt::$DATA",
            "file.txt:stream:$DATA",
            "file.txt:ads",
        ]
    );
    
    // 7. Windows UNC Paths
    test_attack!(
        "7. Windows UNC Paths",
        [
            "\\\\server\\share",
            "//server/share",
            "\\\\?\\C:\\",
            "\\\\.\\C:\\",
        ]
    );
    
    // 8. Windows Trailing Dots/Spaces
    test_attack!(
        "8. Windows Trailing Dots/Spaces Exploit",
        [
            "file.txt.",
            "file.txt...",
            "file.txt ",
            "file.txt   ",
        ]
    );
    
    // 9. Path Separator Manipulation
    test_attack!(
        "9. Path Separator Manipulation",
        [
            "test//file",
            "test///file",
            "test/\\file",
            "test\\/file",
            "test;file",
        ]
    );
    
    // 10. Whitespace Exploitation
    test_attack!(
        "10. Whitespace Exploitation",
        [
            "   ../",              // leading space
            "../   ",              // trailing space
            "file  .txt",          // double space
            "file\t.txt",          // tab
        ]
    );
    
    // 11. Advanced Traversal Sequences
    test_attack!(
        "11. Advanced Traversal Sequences",
        [
            "...",                 // triple dot
            ". .",                 // space between dots
            ". . ",                // multiple spaces
            ".\t.",                // tab between dots
            "\\x2e\\x2e\\x2f",     // hex encoding
        ]
    );
    
    // 12. Special System Paths
    test_attack!(
        "12. Special System Paths",
        [
            "/proc/self/",
            "/sys/",
            "/dev/",
            "/etc/",
            "/tmp/",
        ]
    );
    
    // 13. Filename-Specific Attacks
    println!("13. Filename-Specific Attacks:");
    println!("-------------------------------");
    let filename_attacks = [
        "file%2e%2e.txt",       // URL encoding
        "file%c0%ae.txt",       // UTF-8 overlong
        "file\u{200B}.txt",     // zero-width
        "file.txt::$DATA",      // NTFS stream
        "file.txt:ads",         // NTFS ADS
        "file.txt.",            // trailing dot
        "file.txt ",            // trailing space
    ];
    for attack in filename_attacks {
        total += 1;
        match validate_filename(attack) {
            Ok(_) => println!("  ✗ VULNERABILITY: filename '{}' was accepted!", attack),
            Err(e) => {
                blocked += 1;
                println!("  ✓ Blocked filename: '{}' - {}", attack, e);
            }
        }
    }
    println!();
    
    // 14. Combined Attack Vectors
    test_attack!(
        "14. Combined Attack Vectors",
        [
            "%2e%2e/safe/../",     // Mixed techniques
            "safe//..%2f..",       // Multiple techniques
        ]
    );
    
    // 15. Code Page Homoglyphs
    println!("15. Code Page Specific Homoglyphs:");
    println!("-----------------------------------");
    let codepage_attacks = [
        ("Japanese CP932 (¥)", "dir¥file"),
        ("Korean CP949 (₩)", "dir₩file"),
        ("Greek CP1253 (´)", "dir´file"),
        ("Unicode backslash (∖)", "dir∖file"),
        ("Fullwidth backslash (＼)", "dir＼file"),
    ];
    for (name, attack) in codepage_attacks {
        total += 1;
        match validate_path(Path::new(attack), base_dir) {
            Ok(_) => println!("  ✗ VULNERABILITY: {} was accepted!", name),
            Err(e) => {
                blocked += 1;
                println!("  ✓ Blocked {}: {}", name, e);
            }
        }
    }
    println!();
    
    // 16. Wildcard Characters
    test_attack!(
        "16. Wildcard Characters",
        [
            "dir?/file",           // Question mark
            "file?.txt",           // Question mark in filename
            "dir*/file",           // Asterisk
            "file*.txt",           // Asterisk in filename
        ]
    );
    
    // 17. Nested Traversal Patterns
    test_attack!(
        "17. Nested Traversal Patterns",
        [
            "....//",              // Quad dot double slash
            r"....\/",             // Quad dot mixed separator
            "..../",               // Quad dot slash
            ".|./",                // Pipe dot slash
            ".|.",                 // Pipe dot
            "....",                // Quad dots
        ]
    );
    
    // 18. File Protocol Schemes
    test_attack!(
        "18. File Protocol Schemes",
        [
            "file:///etc/passwd",      // File protocol
            "file:/etc/passwd",        // File protocol variant
            "http://localhost:8080",   // HTTP (SSRF)
            "https://192.168.0.2:9080", // HTTPS (SSRF)
            "ftp://server/file",       // FTP
            "php://filter/resource",   // PHP wrapper
            "data:text/plain,content", // Data URI
        ]
    );
    
    // 19. Null Byte Extension Bypass
    test_attack!(
        "19. Null Byte Extension Bypass",
        [
            "../../../etc/passwd%00.png",     // Classic PHP bypass
            "../../../etc/passwd.ANY%00.png", // With additional extension
        ]
    );
    
    // Summary
    println!("=== Summary ===");
    println!("Total attacks tested: {}", total);
    println!("Attacks blocked: {}", blocked);
    println!("Coverage: {:.1}%", (blocked as f64 / total as f64) * 100.0);
    
    if blocked == total {
        println!("\n✅ ALL ATTACKS BLOCKED - Library is secure!");
    } else {
        println!("\n⚠️  WARNING: {} attacks were not blocked!", total - blocked);
    }
    
    // Verify safe paths still work
    println!("\n=== Verifying Safe Paths Still Work ===");
    let safe_paths = ["safe/file.txt", "safe/document.pdf"];
    let mut safe_count = 0;
    for path in safe_paths {
        match validate_path(Path::new(path), base_dir) {
            Ok(_) => {
                safe_count += 1;
                println!("✓ Safe path '{}' accepted", path);
            }
            Err(e) => println!("✗ Safe path '{}' rejected: {}", path, e),
        }
    }
    
    if safe_count == safe_paths.len() {
        println!("\n✅ All safe paths work correctly!");
    }
    
    Ok(())
}

