# Lesson: placeholder secrets
Context: source repositories with sample configuration.
Observation: pattern based secret scanners match values such as changeme, your_api_key or os.environ lookups.
Lesson: a matched secret pattern is not a leaked credential.
Recommended validation: re-read the cited line, reject placeholders and environment references, downgrade test and example files.
