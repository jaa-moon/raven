from typing import List

class FrameworkDetector:
    """
    Analyzes project dependencies and key file signatures to identify
    the web framework in use.
    """
    DEPENDENCY_MAP = {
        "flask": "Flask",
        "django": "Django",
        "fastapi": "FastAPI",
        "express": "Express",
        "next": "NextJS",
        "react": "React"
    }

    def detect_framework(self, dependencies: List[str], files: List[str]) -> str:
        """
        Identifies the framework using dependency mapping or key config file signatures.
        Returns 'Unknown' if no matching frameworks are detected.
        """
        # 1. Dependency-based check
        for dep in dependencies:
            dep_lower = dep.lower()
            if dep_lower in self.DEPENDENCY_MAP:
                return self.DEPENDENCY_MAP[dep_lower]

        # 2. File signature check (fallback)
        file_names = {f.split("/")[-1] for f in files}

        if any(f.startswith("next.config.") for f in file_names):
            return "NextJS"

        if "manage.py" in file_names:
            return "Django"

        return "Unknown"
