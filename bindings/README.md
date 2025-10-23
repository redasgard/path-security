# Path Security Language Bindings

This directory contains language bindings for the Path Security library, allowing you to use the Rust-based path security functionality from various programming languages.

## Available Bindings

### 1. Node.js (Neon)
- **Location**: `nodejs/`
- **Technology**: Neon (Rust ↔ Node.js)
- **Installation**: `cd nodejs && npm install`
- **Build**: `npm run build`
- **Test**: `npm test`

### 2. Python (PyO3)
- **Location**: `python/`
- **Technology**: PyO3 (Rust ↔ Python)
- **Installation**: `cd python && pip install maturin`
- **Build**: `maturin develop`
- **Test**: `python test.py`

### 3. C/C++ (FFI)
- **Location**: `c/`
- **Technology**: C Foreign Function Interface
- **Build**: `cd c && cargo build --release`
- **Test**: `cd c && gcc -o test test.c -Ltarget/release -lpath_security_c && ./test`

### 4. Go (CGO)
- **Location**: `go/`
- **Technology**: CGO (Go ↔ C)
- **Build**: `cd go && go build -buildmode=c-shared -o libpath_security_go.so path_security.go`
- **Test**: `cd go && go run test.go`

### 5. Java (JNI)
- **Location**: `java/`
- **Technology**: JNI (Java Native Interface)
- **Build**: `cd java/src/main/native && make`
- **Test**: `cd java && mvn compile exec:java -Dexec.mainClass=com.asgardtech.pathsecurity.PathSecurityTest`

## Quick Start

### Build All Bindings
```bash
./build.sh
```

### Test All Bindings
```bash
# Node.js
cd nodejs && npm test

# Python
cd python && python test.py

# C
cd c && gcc -o test test.c -Ltarget/release -lpath_security_c && ./test

# Go
cd go && go run test.go

# Java
cd java && mvn compile exec:java -Dexec.mainClass=com.asgardtech.pathsecurity.PathSecurityTest
```

## API Reference

All bindings provide the same core functionality:

### Functions
- `validatePath(path)` - Validates a file path for security issues
- `detectTraversal(path)` - Detects path traversal patterns
- `sanitizePath(path)` - Sanitizes a path by removing dangerous patterns

### Return Values
- **validatePath**: JSON string with validation results
- **detectTraversal**: Boolean indicating if traversal was detected
- **sanitizePath**: Sanitized path string

## Examples

### Node.js
```javascript
const { validatePath, detectTraversal, sanitizePath } = require('./native');

console.log(validatePath('/usr/local/bin/app')); // Valid path
console.log(detectTraversal('../../../etc/passwd')); // true
console.log(sanitizePath('/var/www/html/../app/config.json')); // Sanitized path
```

### Python
```python
from path_security_pyo3 import validate_path, detect_traversal, sanitize_path

print(validate_path('/usr/local/bin/app'))  # Valid path
print(detect_traversal('../../../etc/passwd'))  # True
print(sanitize_path('/var/www/html/../app/config.json'))  # Sanitized path
```

### C
```c
#include "path_security.h"

char result[256];
int ret = path_security_validate_path("/usr/local/bin/app", result, sizeof(result));
if (ret == 0) {
    printf("Validation result: %s\n", result);
}
```

### Go
```go
ps := NewPathSecurity()
result, err := ps.ValidatePath("/usr/local/bin/app")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Validation result:", result)
```

### Java
```java
PathSecurity ps = new PathSecurity();
String result = ps.validatePath("/usr/local/bin/app");
System.out.println("Validation result: " + result);
```

## Requirements

### System Requirements
- Rust 1.70+
- Cargo
- Platform-specific compilers (gcc, clang, etc.)

### Language-Specific Requirements
- **Node.js**: Node.js 16+, npm
- **Python**: Python 3.8+, pip
- **Go**: Go 1.21+
- **Java**: Java 11+, Maven

## Troubleshooting

### Common Issues

1. **Library not found**: Ensure the C library is built first
2. **Permission denied**: Check file permissions and library paths
3. **Build failures**: Verify all dependencies are installed

### Getting Help

- Check the individual binding directories for specific documentation
- Review the test files for usage examples
- Ensure all system dependencies are installed

## Contributing

When adding new bindings:

1. Create a new directory for the language
2. Implement the core functions (validatePath, detectTraversal, sanitizePath)
3. Add test files demonstrating usage
4. Update this README with the new binding information
5. Update the build script to include the new binding
