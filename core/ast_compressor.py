"""
core/ast_compressor.py
---------------------
AST Context Compression engine for Raven Phase 9.

Parses source code files into Abstract Syntax Trees (or structural regex approximations)
to extract high-risk code units, score them for security signals, and reduce total
token consumption while strictly preserving original file line numbers.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Tuple

from core.models import CompressedChunk, CompressionResult


class RiskScorer:
    """
    Scores each CompressedChunk from 0.0 to 1.0 based on security signals.
    Higher score indicates higher risk of vulnerability, prioritizing the code unit
    for LLM analysis.
    """

    SIGNALS = {
        # Input handling
        "takes_external_input": 0.20,
        "uses_user_param": 0.15,

        # Dangerous operations
        "raw_sql_pattern": 0.25,
        "shell_execution": 0.25,
        "file_operation": 0.15,
        "http_outbound": 0.15,
        "deserialization": 0.20,
        "template_render": 0.15,

        # Auth & crypto
        "auth_function": 0.20,
        "crypto_operation": 0.15,
        "hardcoded_string": 0.20,

        # Framework-specific
        "flask_route": 0.10,
        "django_view": 0.10,
        "express_route": 0.10,
        "orm_raw_query": 0.25,
    }

    # Signal pattern definitions
    PATTERNS = {
        "takes_external_input": r"\b(request|req|ctx|form|body|input|args)\b",
        "uses_user_param": r"\b(user|username|email|password|token|input|data|body|payload)\b",
        "raw_sql_pattern": r"(\bexecute\s*\(|\bcursor\.execute|\braw\s*\(|SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM)",
        "shell_execution": r"(\bsubprocess|\bos\.system|\bexec\s*\(|\beval\s*\(|\bcheck_output|\bpopen\b|\bchild_process\b)",
        "file_operation": r"(\bopen\s*\(|\breadFile|\bos\.path|\bread_text|\bread_bytes|\bfs\.)",
        "http_outbound": r"(\brequests\.|fetch\s*\(|\baxios|\burllib|\bhttpx\.)",
        "deserialization": r"(\bpickle|\bjson\.loads|\byaml\.load|\byaml\.unsafe_load|\bmarshal\.)",
        "template_render": r"(\brender_template|\bjinja|\bejs|\bmustache|\bhandlebars)",
        "crypto_operation": r"(\bhashlib|\bbcrypt|\bjwt\.encode|\bjwt\.decode|\bFernet|\bAES|\bRSA)",
        "flask_route": r"(@\w+\.route|@app\.route)",
        "django_view": r"(def\s+(get|post|put|delete)\s*\(\s*self\s*,\s*request)",
        "express_route": r"(app\.(get|post|put|delete|use)|router\.(get|post|put|delete))",
        "orm_raw_query": r"(\.raw\s*\(|\.execute\s*\(|\btext\s*\()",
    }

    SECRET_PATTERN = r"(KEY|SECRET|PASSWORD|TOKEN|API_|DB_|CONN)"
    HIGH_RISK_METHODS = {
        "__init__", "save", "execute", "query", "authenticate", "login",
        "verify", "validate", "create", "delete", "update", "run", "handle", "process"
    }

    def score(self, chunk: CompressedChunk, raw_content: str) -> Tuple[float, List[str]]:
        """
        Evaluates security signals against chunk source code and name.
        Returns a tuple of (score clamped to 1.0, list of triggered reasons).
        """
        reasons: List[str] = []
        total_score = 0.0
        src = chunk.source
        name_lower = chunk.name.lower()

        # Check static signals via regex
        for signal_name, weight in self.SIGNALS.items():
            pattern = self.PATTERNS.get(signal_name)
            if pattern and re.search(pattern, src, re.IGNORECASE):
                total_score += weight
                reasons.append(signal_name)

        # Auth function check by name
        if any(keyword in name_lower for keyword in ["auth", "login", "verify", "token", "session", "password", "jwt"]):
            if "auth_function" not in reasons:
                total_score += self.SIGNALS["auth_function"]
                reasons.append("auth_function")

        # Hardcoded secret string in global assignment
        if chunk.chunk_type == "global_assignment":
            if re.search(self.SECRET_PATTERN, chunk.name, re.IGNORECASE):
                if "hardcoded_string" not in reasons:
                    total_score += self.SIGNALS["hardcoded_string"]
                    reasons.append("hardcoded_string")

        # Priority names automatically receive a baseline boost
        if name_lower in {"main", "app", "create_app", "configure", "setup", "run", "start", "index", "handle_request"}:
            if "entry_point_function" not in reasons:
                total_score += 0.20
                reasons.append("entry_point_function")

        return round(min(total_score, 1.0), 2), reasons


class ASTCompressor:
    """
    Parses source code into structured compressed chunks using language-specific parsers.
    Falls back gracefully to raw content if AST parsing fails.
    """

    def __init__(self) -> None:
        self.scorer = RiskScorer()

    def compress(
        self,
        file_path: str,
        raw_content: str,
        language: str
    ) -> CompressionResult:
        """
        Main entry point. Detects language, routes to appropriate parser,
        scores extracted chunks, and calculates compression statistics.
        """
        if not raw_content or not raw_content.strip():
            return CompressionResult(
                file_path=file_path,
                language=language,
                original_line_count=0,
                original_char_count=len(raw_content),
                compressed_char_count=0,
                compression_ratio=1.0,
                chunks=[],
                fallback_used=False,
                fallback_reason=""
            )

        orig_lines = len(raw_content.splitlines())
        orig_chars = len(raw_content)
        lang_lower = (language or "").lower()

        try:
            if lang_lower == "python":
                chunks = self._compress_python(raw_content, file_path)
            elif lang_lower in ("javascript", "typescript", "nodejs"):
                chunks = self._compress_javascript(raw_content, file_path)
            elif lang_lower == "go":
                chunks = self._compress_go(raw_content, file_path)
            else:
                return self._make_fallback(raw_content, file_path, language, f"Unsupported language: {language}")

            if not chunks:
                return self._make_fallback(raw_content, file_path, language, "No structural chunks extracted")

            # Score each chunk
            for chunk in chunks:
                score, reasons = self.scorer.score(chunk, raw_content)
                chunk.risk_score = score
                # Merge reasons if any exist
                chunk.risk_reasons = list(set(chunk.risk_reasons + reasons))

            # Compressed character count reflects Tier 1 & Tier 2 chunks sent to LLM
            compressed_chars = sum(
                len(c.source) for c in chunks
                if c.risk_score >= 0.15 or c.chunk_type in ("import_block", "global_assignment")
            )
            if compressed_chars == 0:
                compressed_chars = sum(len(c.source) for c in chunks)

            ratio = round(orig_chars / max(compressed_chars, 1), 2)


            return CompressionResult(
                file_path=file_path,
                language=language,
                original_line_count=orig_lines,
                original_char_count=orig_chars,
                compressed_char_count=compressed_chars,
                compression_ratio=ratio,
                chunks=chunks,
                fallback_used=False,
                fallback_reason=""
            )

        except Exception as e:
            return self._make_fallback(raw_content, file_path, language, str(e))

    def _compress_python(
        self,
        raw_content: str,
        file_path: str
    ) -> List[CompressedChunk]:
        """
        Parses Python source using stdlib `ast` module.
        Extracts functions, classes, import blocks, and module-level secret assignments.
        """
        tree = ast.parse(raw_content)
        lines = raw_content.splitlines()
        chunks: List[CompressedChunk] = []

        import_nodes: List[ast.AST] = []

        for node in tree.body:
            # 1. Imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                import_nodes.append(node)

            # 2. Standalone Functions
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                chunk = self._extract_python_function(node, lines, file_path, "function")
                if chunk:
                    chunks.append(chunk)

            # 3. Class Definitions
            elif isinstance(node, ast.ClassDef):
                class_start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
                class_end = getattr(node, "end_lineno", node.lineno)

                method_chunks: List[CompressedChunk] = []
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        m_chunk = self._extract_python_function(item, lines, file_path, "method", class_name=node.name)
                        if m_chunk:
                            method_chunks.append(m_chunk)

                if method_chunks:
                    chunks.extend(method_chunks)
                else:
                    src = "\n".join(lines[class_start - 1 : min(class_start + 5, len(lines))])
                    chunks.append(CompressedChunk(
                        chunk_id=f"class:{node.name}",
                        chunk_type="class_def",
                        name=node.name,
                        line_start=class_start,
                        line_end=min(class_start + 5, class_end),
                        source=src,
                        language="python",
                        file_path=file_path
                    ))

            # 4. Global String Assignments (Secrets)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = getattr(target, "id", "")
                    if target_name and re.search(RiskScorer.SECRET_PATTERN, target_name, re.IGNORECASE):
                        start = node.lineno
                        end = getattr(node, "end_lineno", start)
                        src = "\n".join(lines[start - 1 : end])
                        chunks.append(CompressedChunk(
                            chunk_id=f"global:{target_name}",
                            chunk_type="global_assignment",
                            name=target_name,
                            line_start=start,
                            line_end=end,
                            source=src,
                            risk_score=0.40,
                            risk_reasons=["hardcoded_string"],
                            language="python",
                            file_path=file_path
                        ))

        # Group all imports into a single import_block chunk
        if import_nodes:
            first_lineno = import_nodes[0].lineno
            last_lineno = getattr(import_nodes[-1], "end_lineno", import_nodes[-1].lineno)
            import_lines = []
            for imp in import_nodes:
                st = imp.lineno
                en = getattr(imp, "end_lineno", st)
                import_lines.append("\n".join(lines[st - 1 : en]))
            import_src = "\n".join(import_lines)

            chunks.insert(0, CompressedChunk(
                chunk_id="imports:python",
                chunk_type="import_block",
                name="import_block",
                line_start=first_lineno,
                line_end=last_lineno,
                source=import_src,
                risk_score=0.10,
                risk_reasons=["imports"],
                language="python",
                file_path=file_path
            ))

        return chunks

    def _extract_python_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        lines: List[str],
        file_path: str,
        chunk_type: str,
        class_name: str = ""
    ) -> CompressedChunk | None:
        """Helper to extract source code for a Python FunctionDef node."""
        start_line = node.decorator_list[0].lineno if node.decorator_list else node.lineno
        end_line = getattr(node, "end_lineno", node.lineno)
        if start_line > len(lines):
            return None

        source_lines = lines[start_line - 1 : end_line]
        source = "\n".join(source_lines)
        name = f"{class_name}:{node.name}" if class_name else node.name
        chunk_id = f"{chunk_type}:{name}"

        return CompressedChunk(
            chunk_id=chunk_id,
            chunk_type=chunk_type,  # type: ignore
            name=name,
            line_start=start_line,
            line_end=end_line,
            source=source,
            language="python",
            file_path=file_path
        )

    def _compress_javascript(
        self,
        raw_content: str,
        file_path: str
    ) -> List[CompressedChunk]:
        """
        Parses JavaScript/TypeScript using regex structural extraction and brace depth matching.
        """
        lines = raw_content.splitlines()
        chunks: List[CompressedChunk] = []

        # 1. Collect all import and require statements into one import_block
        import_matches = list(re.finditer(r'^(?:import\s+.+from\s+[\'"].+[\'"]|(?:const|let|var)\s+\w+\s*=\s*require\([^)]+\));?', raw_content, re.MULTILINE))
        if import_matches:
            imp_sources = [m.group(0) for m in import_matches]
            first_line = raw_content[:import_matches[0].start()].count('\n') + 1
            last_line = raw_content[:import_matches[-1].end()].count('\n') + 1
            chunks.append(CompressedChunk(
                chunk_id="imports:javascript",
                chunk_type="import_block",
                name="import_block",
                line_start=first_line,
                line_end=last_line,
                source="\n".join(imp_sources),
                risk_score=0.10,
                risk_reasons=["imports"],
                language="javascript",
                file_path=file_path
            ))

        # 2. Match functions and class methods
        patterns = [
            (r'^(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(', "function"),
            (r'^(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{', "function"),
            (r'^(?:export\s+)?class\s+(\w+)', "class_def"),
            (r'^\s{2,}(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{', "method"),
        ]

        for pattern, chunk_type in patterns:
            for match in re.finditer(pattern, raw_content, re.MULTILINE):
                name = match.group(1)
                start_index = match.start()
                line_start = raw_content[:start_index].count('\n') + 1

                extracted_src, line_end = self._extract_brace_block(raw_content, start_index, line_start)
                if extracted_src:
                    chunks.append(CompressedChunk(
                        chunk_id=f"{chunk_type}:{name}",
                        chunk_type=chunk_type,  # type: ignore
                        name=name,
                        line_start=line_start,
                        line_end=line_end,
                        source=extracted_src,
                        risk_reasons=["regex_approximation"],
                        language="javascript",
                        file_path=file_path
                    ))

        return chunks

    def _compress_go(
        self,
        raw_content: str,
        file_path: str
    ) -> List[CompressedChunk]:
        """
        Parses Go source using regex structural extraction and brace depth matching.
        """
        chunks: List[CompressedChunk] = []

        # 1. Import block
        import_match = re.search(r'import\s*\(\s*[\s\S]*?\)', raw_content)
        if import_match:
            line_start = raw_content[:import_match.start()].count('\n') + 1
            line_end = raw_content[:import_match.end()].count('\n') + 1
            chunks.append(CompressedChunk(
                chunk_id="imports:go",
                chunk_type="import_block",
                name="import_block",
                line_start=line_start,
                line_end=line_end,
                source=import_match.group(0),
                risk_score=0.10,
                risk_reasons=["imports"],
                language="go",
                file_path=file_path
            ))

        # 2. Functions & Methods
        patterns = [
            (r'^func\s+(\w+)\s*\(', "function"),
            (r'^func\s+\(\w+\s+\*?(\w+)\)\s+(\w+)\s*\(', "method"),
            (r'^type\s+(\w+)\s+struct\s*\{', "class_def"),
        ]

        for pattern, chunk_type in patterns:
            for match in re.finditer(pattern, raw_content, re.MULTILINE):
                if chunk_type == "method":
                    struct_name = match.group(1)
                    method_name = match.group(2)
                    name = f"{struct_name}:{method_name}"
                else:
                    name = match.group(1)

                start_index = match.start()
                line_start = raw_content[:start_index].count('\n') + 1
                extracted_src, line_end = self._extract_brace_block(raw_content, start_index, line_start)
                if extracted_src:
                    chunks.append(CompressedChunk(
                        chunk_id=f"{chunk_type}:{name}",
                        chunk_type=chunk_type,  # type: ignore
                        name=name,
                        line_start=line_start,
                        line_end=line_end,
                        source=extracted_src,
                        risk_reasons=["regex_approximation"],
                        language="go",
                        file_path=file_path
                    ))

        return chunks

    def _extract_brace_block(self, content: str, start_index: int, line_start: int) -> Tuple[str, int]:
        """
        Extracts code snippet from start_index to matching closing brace using depth counting.
        """
        depth = 0
        in_block = False
        end_index = len(content)

        for i in range(start_index, len(content)):
            char = content[i]
            if char == '{':
                depth += 1
                in_block = True
            elif char == '}':
                depth -= 1
                if in_block and depth == 0:
                    end_index = i + 1
                    break

        extracted = content[start_index:end_index]
        line_end = line_start + extracted.count('\n')
        return extracted.strip(), line_end

    def _make_fallback(
        self,
        raw_content: str,
        file_path: str,
        language: str,
        reason: str
    ) -> CompressionResult:
        """
        Fault-tolerant fallback. Wraps raw content into a single max-risk chunk.
        Guarantees that AST compression failures never break a scan.
        """
        lines = raw_content.splitlines()
        line_count = len(lines)
        char_count = len(raw_content)

        fallback_chunk = CompressedChunk(
            chunk_id=f"fallback:{Path(file_path).name}",
            chunk_type="function",
            name=Path(file_path).name,
            line_start=1,
            line_end=max(line_count, 1),
            source=raw_content,
            risk_score=1.0,
            risk_reasons=["fallback_raw_content"],
            language=language,
            file_path=file_path
        )

        return CompressionResult(
            file_path=file_path,
            language=language,
            original_line_count=line_count,
            original_char_count=char_count,
            compressed_char_count=char_count,
            compression_ratio=1.0,
            chunks=[fallback_chunk],
            fallback_used=True,
            fallback_reason=reason
        )
