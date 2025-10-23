#include <stdio.h>
#include <string.h>
#include "path_security.h"

int main() {
    printf("Testing Path Security C bindings...\n");
    
    char result[256];
    int ret;
    
    // Test safe paths
    const char* safe_paths[] = {
        "/safe/path/to/file.txt",
        "C:\\Windows\\System32\\file.txt",
        "/usr/local/bin/script.sh",
        NULL
    };
    
    printf("\nTesting safe paths:\n");
    for (int i = 0; safe_paths[i] != NULL; i++) {
        ret = path_security_validate_path(safe_paths[i], result, sizeof(result));
        if (ret == 0) {
            printf("✓ Safe path '%s' -> %s\n", safe_paths[i], result);
        } else {
            printf("✗ Safe path '%s' -> Error: %d\n", safe_paths[i], ret);
        }
    }
    
    // Test dangerous paths
    const char* dangerous_paths[] = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        NULL
    };
    
    printf("\nTesting dangerous paths:\n");
    for (int i = 0; dangerous_paths[i] != NULL; i++) {
        int is_traversal = path_security_detect_traversal(dangerous_paths[i]);
        ret = path_security_sanitize_path(dangerous_paths[i], result, sizeof(result));
        
        if (ret == 0) {
            printf("✓ Dangerous path '%s' -> Traversal: %d, Sanitized: %s\n", 
                   dangerous_paths[i], is_traversal, result);
        } else {
            printf("✗ Dangerous path '%s' -> Error: %d\n", dangerous_paths[i], ret);
        }
    }
    
    // Test filename sanitization
    printf("\nTesting filename sanitization:\n");
    const char* filenames[] = {
        "file/name?with*bad|chars.txt",
        "my_document.pdf",
        "script<script>alert(1)</script>.js",
        NULL
    };
    
    for (int i = 0; filenames[i] != NULL; i++) {
        ret = path_security_sanitize_filename(filenames[i], result, sizeof(result));
        if (ret == 0) {
            printf("✓ Filename '%s' -> %s\n", filenames[i], result);
        } else {
            printf("✗ Filename '%s' -> Error: %d\n", filenames[i], ret);
        }
    }
    
    // Test project name validation
    printf("\nTesting project name validation:\n");
    const char* project_names[] = {
        "my-safe-project",
        "../malicious-project",
        "valid_project_123",
        NULL
    };
    
    for (int i = 0; project_names[i] != NULL; i++) {
        ret = path_security_validate_project_name(project_names[i], result, sizeof(result));
        if (ret == 0) {
            printf("✓ Project name '%s' -> %s\n", project_names[i], result);
        } else {
            printf("✗ Project name '%s' -> Error: %d\n", project_names[i], ret);
        }
    }
    
    printf("\nC bindings test completed!\n");
    return 0;
}
