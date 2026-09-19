# Source code security checklist
Search for dynamic evaluation (eval, exec), shell invocation (shell=True, os.system), unsafe deserialization (pickle, yaml.load), string built SQL, disabled TLS verification, debug mode, weak hashing. A pattern is a lead, not a vulnerability: reachability from untrusted input must be established.

# Input validation checklist
Trace user controlled input to sinks: SQL, OS commands, file paths, templates, HTTP redirects, deserializers. Validate on the server side with allow lists.
