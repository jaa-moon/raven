from collections import Counter
from typing import List

class LanguageDetector:
    """
    Analyzes scanned file paths to determine the primary language of a project.
    """
    EXTENSION_MAP = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".go": "Go"
    }

    def detect_language(self, files: List[str]) -> str:
        """
        Determines the primary language by counting files matching mapped extensions.
        Returns 'Unknown' if no matching languages are found.
        """
        counts = Counter()

        for file in files:
            # Get lowercase file extension (including the dot, e.g., '.py')
            ext = "".join(file.split(".")[-1:]).lower()
            # Restore the dot for mapping
            dotted_ext = f".{ext}" if "." in file else ""
            
            if dotted_ext in self.EXTENSION_MAP:
                lang = self.EXTENSION_MAP[dotted_ext]
                counts[lang] += 1

        if not counts:
            return "Unknown"

        # Return the language with the maximum file count
        return counts.most_common(1)[0][0]
