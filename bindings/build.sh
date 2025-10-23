#!/bin/bash

# Build script for all Path Security language bindings
set -e

echo "Building Path Security language bindings..."

# Build C library first (required for other bindings)
echo "Building C library..."
cd c
cargo build --release
cd ..

# Build Node.js bindings
echo "Building Node.js bindings..."
cd nodejs
npm install
npm run build
cd ..

# Build Python bindings
echo "Building Python bindings..."
cd python
cargo build --release
cd ..

# Build Go bindings (requires C library)
echo "Building Go bindings..."
cd go
# Copy C library for Go to link against
cp ../c/target/release/libpath_security_c.so .
go build -buildmode=c-shared -o libpath_security_go.so path_security.go
cd ..

# Build Java bindings
echo "Building Java bindings..."
cd java/src/main/native
make clean
make
cd ../../../..

echo "All bindings built successfully!"
echo ""
echo "To test the bindings:"
echo "  Node.js: cd nodejs && npm test"
echo "  Python:  cd python && python test.py"
echo "  C:       cd c && gcc -o test test.c -Ltarget/release -lpath_security_c && ./test"
echo "  Go:      cd go && go run test.go"
echo "  Java:    cd java && mvn compile exec:java -Dexec.mainClass=com.asgardtech.pathsecurity.PathSecurityTest"
