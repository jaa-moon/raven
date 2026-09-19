# Secrets checklist
Hardcoded passwords, API keys, private keys and tokens in source and config. Ignore placeholders, environment variable references and test fixtures. Rotate any real credential found; never print secret values.

# Dependency checklist
Compare declared dependency versions to advisories. Declared version below the fixed version is a lead; confirm whether the vulnerable feature is used.

# Configuration checklist
Debug flags, permissive CORS, disabled TLS verification, default secrets, world writable files, exposed admin interfaces in deployment configuration.
