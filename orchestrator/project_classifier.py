"""
orchestrator/project_classifier.py
-----------------------------------
Stack detection engine for Raven autonomous pentesting agent.

Inspects target project directories to identify language, web framework,
dependencies, entry points, default ports, and static route endpoints.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from reports.models import ProjectProfile


class ProjectClassifier:
    """
    Analyzes project root directory to construct a ProjectProfile.
    """

    def __init__(self, target_path: Path | str) -> None:
        self.target_path = Path(target_path).resolve()

    def classify(self) -> ProjectProfile:
        """Execute stack detection rules and return a ProjectProfile."""
        if not self.target_path.exists() or not self.target_path.is_dir():
            return ProjectProfile(path=str(self.target_path))

        language, framework = self._detect_language_and_framework()
        entry_point = self._detect_entry_point(language, framework)
        detected_port = self._detect_port(language, framework)
        dependencies = self._parse_dependencies(language)
        detected_routes = self._extract_static_routes(language)
        health_paths = self._determine_health_paths(framework)

        return ProjectProfile(
            path=str(self.target_path),
            language=language,
            framework=framework,
            entry_point=entry_point,
            detected_port=detected_port,
            dependencies=dependencies,
            detected_routes=detected_routes,
            health_check_paths=health_paths,
            environment={}
        )

    def _detect_language_and_framework(self) -> Tuple[str, str]:
        """Detect primary programming language and web framework."""
        # Python
        if list(self.target_path.glob("*.py")) or (self.target_path / "requirements.txt").exists():
            language = "Python"
            framework = "Generic-Python"
            all_py_text = ""
            for p in list(self.target_path.rglob("*.py"))[:30]:
                try:
                    all_py_text += p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass
            if "flask" in all_py_text.lower():
                framework = "Flask"
            elif "fastapi" in all_py_text.lower():
                framework = "FastAPI"
            elif "django" in all_py_text.lower():
                framework = "Django"
            return language, framework

        # Node / JavaScript / TypeScript
        if (self.target_path / "package.json").exists() or list(self.target_path.glob("*.js")):
            language = "NodeJS"
            framework = "Express"
            pkg_file = self.target_path / "package.json"
            if pkg_file.exists():
                try:
                    data = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    if "next" in deps:
                        framework = "Next.js"
                    elif "nest" in deps or "@nestjs/core" in deps:
                        framework = "NestJS"
                    elif "express" in deps:
                        framework = "Express"
                except Exception:
                    pass
            return language, framework

        # Go
        if (self.target_path / "go.mod").exists() or list(self.target_path.glob("*.go")):
            language = "Go"
            framework = "Gin"
            if (self.target_path / "go.mod").exists():
                txt = (self.target_path / "go.mod").read_text(encoding="utf-8", errors="ignore").lower()
                if "fiber" in txt:
                    framework = "Fiber"
                elif "echo" in txt:
                    framework = "Echo"
            return language, framework

        # Java
        if (self.target_path / "pom.xml").exists() or (self.target_path / "build.gradle").exists():
            return "Java", "Spring Boot"

        return "Unknown", "Unknown"

    def _detect_entry_point(self, language: str, framework: str) -> str:
        """Find the main entry point file."""
        if language == "Python":
            for candidate in ["app.py", "main.py", "wsgi.py", "run.py", "server.py"]:
                if (self.target_path / candidate).exists():
                    return candidate
            py_files = [p.relative_to(self.target_path).as_posix() for p in self.target_path.glob("*.py")]
            return py_files[0] if py_files else "app.py"

        if language == "NodeJS":
            pkg = self.target_path / "package.json"
            if pkg.exists():
                try:
                    data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
                    if "main" in data:
                        return data["main"]
                except Exception:
                    pass
            for candidate in ["index.js", "server.js", "app.js", "main.js"]:
                if (self.target_path / candidate).exists():
                    return candidate
            return "index.js"

        if language == "Go":
            if (self.target_path / "main.go").exists():
                return "main.go"
            go_files = [p.relative_to(self.target_path).as_posix() for p in self.target_path.glob("*.go")]
            return go_files[0] if go_files else "main.go"

        if language == "Java":
            return "app.jar"

        return "main"

    def _detect_port(self, language: str, framework: str) -> int:
        """Detect or assign default port for framework."""
        defaults = {
            "Flask": 5000,
            "FastAPI": 8000,
            "Django": 8000,
            "Express": 3000,
            "Next.js": 3000,
            "NestJS": 3000,
            "Go": 8080,
            "Gin": 8080,
            "Spring Boot": 8080
        }
        port = defaults.get(framework, 5000)

        # Scan code files for hardcoded port assignments
        regex = re.compile(r'(?:port|LISTEN|Listen|PORT)\s*[:=]?\s*(\d{4,5})')
        for file_path in list(self.target_path.rglob("*"))[:40]:
            if file_path.is_file() and file_path.suffix in [".py", ".js", ".ts", ".go", ".env", ".properties", ".yml", ".yaml"]:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    match = regex.search(content)
                    if match:
                        found_port = int(match.group(1))
                        if 1024 <= found_port <= 65535:
                            return found_port
                except Exception:
                    pass
        return port

    def _parse_dependencies(self, language: str) -> List[str]:
        """Parse list of third-party package dependencies."""
        deps: List[str] = []
        if language == "Python" and (self.target_path / "requirements.txt").exists():
            try:
                lines = (self.target_path / "requirements.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
                for line in lines:
                    line = line.strip().split("#")[0]
                    if line:
                        pkg = re.split(r'[==<=>~!]', line)[0].strip()
                        if pkg:
                            deps.append(pkg)
            except Exception:
                pass

        elif language == "NodeJS" and (self.target_path / "package.json").exists():
            try:
                data = json.loads((self.target_path / "package.json").read_text(encoding="utf-8", errors="ignore"))
                deps.extend(list(data.get("dependencies", {}).keys()))
            except Exception:
                pass

        return deps[:50]

    def _extract_static_routes(self, language: str) -> List[str]:
        """Extract HTTP route patterns using static regex parsing."""
        routes: Set[str] = set()
        route_patterns = [
            r'@app\.route\s*\(\s*[\'"]([^\'"]+)[\'"]',          # Flask @app.route("/path")
            r'@(?:router|app)\.(?:get|post|put|delete)\s*\(\s*[\'"]([^\'"]+)[\'"]', # FastAPI/Express
            r'app\.(?:get|post|put|delete|use)\s*\(\s*[\'"]([^\'"]+)[\'"]',        # Express app.get("/path")
            r'r\.(?:GET|POST|PUT|DELETE)\s*\(\s*[\'"]([^\'"]+)[\'"]',               # Gin r.GET("/path")
            r'@(?:Get|Post|Put|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?[\'"]([^\'"]+)[\'"]' # Spring Boot
        ]

        for file_path in list(self.target_path.rglob("*"))[:50]:
            if file_path.is_file() and file_path.suffix in [".py", ".js", ".ts", ".go", ".java"]:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for pattern in route_patterns:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            route = match.group(1)
                            if route and not route.startswith("<") and len(route) < 100:
                                routes.add(route if route.startswith("/") else "/" + route)
                except Exception:
                    pass

        return sorted(list(routes)) if routes else ["/"]

    def _determine_health_paths(self, framework: str) -> List[str]:
        """Generate list of health check HTTP endpoints based on framework."""
        if framework == "Spring Boot":
            return ["/actuator/health", "/health", "/"]
        return ["/health", "/api/health", "/healthz", "/"]
