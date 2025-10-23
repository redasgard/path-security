//! Constants for path security

// Path length limits
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_FILENAME_LENGTH: usize = 255;
pub const MAX_PROJECT_NAME_LENGTH: usize = 64;

// Symlink chain limits
pub const MAX_SYMLINK_CHAIN_LENGTH: usize = 100;

// Encoding detection thresholds
pub const UTF16_NULL_BYTE_THRESHOLD: f32 = 0.25; // 25% of even positions have null bytes

// Dangerous patterns
pub const SUSPICIOUS_ENCODED_PATTERNS: &[&str] = &[
    "%2e", "%2E",  // .
    "%2f", "%2F",  // /
    "%5c", "%5C",  // \
    "%00",         // null byte
    "%0a", "%0A",  // newline
    "%0d", "%0D",  // carriage return
];

pub const OVERLONG_UTF8_PATTERNS: &[&str] = &[
    "%c0%ae",  // overlong .
    "%c0%af",  // overlong /
    "%c1%9c",  // overlong \
    "%c0%2e",  // invalid encoding
    "%e0%80%ae", // 3-byte overlong .
];

pub const TRAVERSAL_PATTERNS: &[&str] = &[
    "..",
    "...",   // Some systems treat this specially
    "....",  // Quad dots
    ". .",   // Space between dots
    ". . ",  // Multiple spaces
    ".\t.",  // Tab between dots
    ".|.",   // Pipe between dots
];

pub const NESTED_TRAVERSAL_PATTERNS: &[&str] = &[
    "....//",   // Quad dot double slash
    "....\\/",  // Quad dot mixed separator
    "..../",    // Quad dot slash
    "....\\\\", // Quad dot backslash
    ".|./",     // Pipe dot slash
    ".|\\/",    // Pipe dot backslash-slash
];

pub const DANGEROUS_SEPARATORS: &[char] = &[';', '\t', '\n', '\r'];

pub const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", 
    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", 
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
];

pub const DANGEROUS_PROTOCOLS: &[&str] = &[
    "file://", "file:/",
    "http://", "https://",
    "ftp://", "ftps://", "sftp://",
    "gopher://", "data:", "javascript:",
    "vbscript:", "jar:", "php://",
];

pub const SYSTEM_PATHS: &[&str] = &[
    "/proc/", "/sys/", "/dev/",
    "C:\\Windows\\System32", "C:\\Windows\\Temp",
    "/tmp/", "/var/tmp/",
    "/etc/", "/boot/",
];

pub const SUSPICIOUS_PATTERNS: &[&str] = &[
    "~",          // Home directory expansion
    "$",          // Environment variable expansion
    "\0",         // Null byte injection
    "\\",         // Backslash (should be caught by separator check, but double-check)
];
