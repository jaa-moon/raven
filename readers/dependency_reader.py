import json
import re
from pathlib import Path
from typing import List, Set

class DependencyReader:
    """
    Scans and parses dependency definition files (requirements.txt, package.json, go.mod)
    to extract dependency names.
    """

    def read_dependencies(self, root_path: Path, files: List[str]) -> List[str]:
        """
        Looks for known dependency files in the list of project files,
        parses them, and returns a sorted list of unique dependency names.
        """
        dependencies: Set[str] = set()

        for file_rel_path in files:
            file_path = root_path / file_rel_path
            filename = file_path.name

            if filename == "requirements.txt":
                dependencies.update(self._parse_requirements(file_path))
            elif filename == "package.json":
                dependencies.update(self._parse_package_json(file_path))
            elif filename == "go.mod":
                dependencies.update(self._parse_go_mod(file_path))

        return sorted(list(dependencies))

    def _parse_requirements(self, file_path: Path) -> Set[str]:
        """
        Parses python requirements.txt file.
        Strips version constraints, comments, and flags.
        """
        deps = set()
        if not file_path.exists():
            return deps

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines, comments, and flags like -r or -e
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    
                    # Split on common delimiters: ==, >=, <=, >, <, ~=, ;, [ (extras)
                    # Example: "Django[argon2]>=3.2; python_version > '3.7'"
                    parts = re.split(r'==|>=|<=|>|<|~=|;|\[', line)
                    dep_name = parts[0].strip()
                    if dep_name:
                        deps.add(dep_name.lower())
        except Exception:
            pass # Fail silently or log error internally
        return deps

    def _parse_package_json(self, file_path: Path) -> Set[str]:
        """
        Parses package.json dependencies and devDependencies keys.
        """
        deps = set()
        if not file_path.exists():
            return deps

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
                # Check normal dependencies
                if "dependencies" in data and isinstance(data["dependencies"], dict):
                    deps.update(data["dependencies"].keys())
                
                # Check devDependencies
                if "devDependencies" in data and isinstance(data["devDependencies"], dict):
                    deps.update(data["devDependencies"].keys())
        except Exception:
            pass
        return deps

    def _parse_go_mod(self, file_path: Path) -> Set[str]:
        """
        Parses go.mod dependencies listed in 'require' blocks or single statements.
        """
        deps = set()
        if not file_path.exists():
            return deps

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                in_require_block = False
                for line in f:
                    line = line.strip()
                    
                    # Detect start of require block
                    if line.startswith("require ("):
                        in_require_block = True
                        continue
                    
                    # Detect end of require block
                    if in_require_block and line.startswith(")"):
                        in_require_block = False
                        continue
                    
                    # Parse block entries
                    if in_require_block:
                        # Skip comments
                        if line.startswith("//") or not line:
                            continue
                        parts = line.split()
                        if parts:
                            deps.add(parts[0])
                        continue
                    
                    # Parse single line requires
                    if line.startswith("require ") and not line.startswith("require ("):
                        parts = line.split()
                        # Expected format: require github.com/gin-gonic/gin v1.7.2
                        if len(parts) >= 2:
                            deps.add(parts[1])
        except Exception:
            pass
        return deps
