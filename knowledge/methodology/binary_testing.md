# Methodology: Native Binary & Process Security Assessment

## 1. When to Use
Activate this methodology when the target is a compiled native executable (`.exe`, `.elf`, `.so`, `.dll`), local CLI script, background daemon, or running process PID.

## 2. Key Hypotheses
- **H-BIN-01**: Binary terminates abnormally (SIGSEGV / exit code 139, abort / code 134) on boundary input lengths.
- **H-BIN-02**: Format string vulnerabilities allowing memory disclosure or crash via `%s%s%x` specifiers.
- **H-BIN-03**: Insecure file permissions (world-writable binary or configuration directory, SUID/SGID bit set).
- **H-BIN-04**: Daemon process binds administrative or debugging sockets to all network interfaces (`0.0.0.0`).
- **H-BIN-05**: Command injection via unsanitized argument concatenation in child process spawning.

## 3. Recommended Tools
- `process_probe`: Inspection of running PID, command line, open ports, files, and environment variables.
- `cli_fuzz`: Boundary argument injection, format strings, and crash monitoring.
- `permission_scan`: Filesystem permissions and SUID/SGID audit.

## 4. Evidence Criteria
- **Crash / DoS**: Subprocess exit code indicating signal termination (-11, 139) with captured stderr stack trace.
- **Insecure Permissions**: `stat` mode bits demonstrating `S_ISUID`, `S_ISGID`, or `S_IWOTH`.
- **Exposed Socket**: Verified network socket bound to non-loopback address by process.
- **PoC Format**: Working shell command with binary path and offending argument (`cli_poc`).

## 5. Common False Positives
- Expected non-zero exit codes (e.g. exit code 1 or 2 for invalid usage/help flag).
- Temporary files with default umask permissions in isolated user directories.
- Crash dumps in development binaries with debug assertions intentionally triggered.
