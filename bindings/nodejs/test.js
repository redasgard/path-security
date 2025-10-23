const { validatePath, detectTraversal, sanitizePath, sanitizeFilename, validateProjectName } = require('./native');

console.log('Testing Path Security Node.js bindings...');
console.log('==========================================');

// Test safe paths
console.log('\n1. Testing safe paths:');
const safePaths = [
    '/safe/path/to/file.txt',
    'C:\\Windows\\System32\\file.txt',
    '/usr/local/bin/script.sh'
];

safePaths.forEach(path => {
    const result = JSON.parse(validatePath(path));
    console.log(`Safe path "${path}" -> Valid: ${result.valid}`);
});

// Test dangerous paths
console.log('\n2. Testing dangerous paths:');
const dangerousPaths = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
];

dangerousPaths.forEach(path => {
    const traversalResult = JSON.parse(detectTraversal(path));
    const sanitizedResult = JSON.parse(sanitizePath(path));
    console.log(`Dangerous path "${path}" -> Traversal: ${traversalResult.is_traversal}, Sanitized: ${sanitizedResult.sanitized}`);
});

// Test filename sanitization
console.log('\n3. Testing filename sanitization:');
const filenames = [
    'file/name?with*bad|chars.txt',
    'my_document.pdf',
    'script<script>alert(1)</script>.js'
];

filenames.forEach(filename => {
    const result = JSON.parse(sanitizeFilename(filename));
    console.log(`Filename "${filename}" -> Sanitized: "${result.sanitized}"`);
});

// Test project name validation
console.log('\n4. Testing project name validation:');
const projectNames = [
    'my-safe-project',
    '../malicious-project',
    'valid_project_123'
];

projectNames.forEach(name => {
    const result = JSON.parse(validateProjectName(name));
    console.log(`Project name "${name}" -> Valid: ${result.valid}`);
});

console.log('\nNode.js bindings test completed!');
