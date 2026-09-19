"""
tests/test_ast_compressor.py
----------------------------
Unit tests for Raven Phase 9 AST Context Compression engine.
"""

import unittest
from core.ast_compressor import ASTCompressor
from core.models import CompressedChunk
from llm.prompt_builder import PromptBuilder


class TestASTCompressor(unittest.TestCase):

    def setUp(self):
        self.compressor = ASTCompressor()
        self.prompt_builder = PromptBuilder()

    def test_python_function_extraction(self):
        """Test extraction of Python Flask route function with SQL query."""
        code = (
            "@app.route('/user')\n"
            "def get_user():\n"
            "    username = request.args.get('username')\n"
            "    cursor.execute(f'SELECT * FROM users WHERE name = {username}')\n"
            "    return 'ok'\n"
        )
        result = self.compressor.compress("app.py", code, "Python")

        self.assertFalse(result.fallback_used)
        self.assertTrue(len(result.chunks) >= 1)

        func_chunk = next(c for c in result.chunks if c.name == "get_user")
        self.assertEqual(func_chunk.line_start, 1)
        self.assertEqual(func_chunk.line_end, 5)
        self.assertGreaterEqual(func_chunk.risk_score, 0.40)
        self.assertIn("raw_sql_pattern", func_chunk.risk_reasons)

    def test_python_import_block(self):
        """Test grouping of Python imports into a single import_block chunk."""
        code = (
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "import subprocess\n"
            "from flask import Flask, request\n"
            "\n"
            "app = Flask(__name__)\n"
        )
        result = self.compressor.compress("main.py", code, "Python")

        self.assertFalse(result.fallback_used)
        import_chunks = [c for c in result.chunks if c.chunk_type == "import_block"]
        self.assertEqual(len(import_chunks), 1)

        imp_chunk = import_chunks[0]
        self.assertIn("import os", imp_chunk.source)
        self.assertIn("from flask import Flask, request", imp_chunk.source)

    def test_python_secret_assignment(self):
        """Test extraction of module-level secret string assignments."""
        code = (
            "import os\n"
            "API_KEY = 'sk-abc123longsecretkeyvalue'\n"
            "DB_PASSWORD = 'supersecretpass'\n"
        )
        result = self.compressor.compress("config.py", code, "Python")

        self.assertFalse(result.fallback_used)
        secret_chunks = [c for c in result.chunks if c.chunk_type == "global_assignment"]
        self.assertTrue(len(secret_chunks) >= 1)

        api_chunk = next(c for c in secret_chunks if "API_KEY" in c.name)
        self.assertIn("hardcoded_string", api_chunk.risk_reasons)

    def test_javascript_function_extraction(self):
        """Test regex structural extraction of JavaScript route handler."""
        code = (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "function handleLogin(req, res) {\n"
            "    const body = req.body;\n"
            "    res.send(body);\n"
            "}\n"
        )
        result = self.compressor.compress("server.js", code, "JavaScript")

        self.assertFalse(result.fallback_used)
        func_chunks = [c for c in result.chunks if c.name == "handleLogin"]
        self.assertEqual(len(func_chunks), 1)

        chunk = func_chunks[0]
        self.assertIn("takes_external_input", chunk.risk_reasons)

    def test_tier_filtering(self):
        """Test prompt tier filtering: Tier 1 (full), Tier 2 (signatures), Tier 3 (omitted)."""
        chunks = [
            # 3 High risk (score >= 0.40)
            CompressedChunk(chunk_id="f1", chunk_type="function", name="high1", line_start=1, line_end=5, source="def high1():\n    exec('code')", risk_score=0.50, risk_reasons=["shell_execution"]),
            CompressedChunk(chunk_id="f2", chunk_type="function", name="high2", line_start=10, line_end=15, source="def high2():\n    cursor.execute('sql')", risk_score=0.50, risk_reasons=["raw_sql_pattern"]),
            CompressedChunk(chunk_id="f3", chunk_type="function", name="high3", line_start=20, line_end=25, source="def high3():\n    os.system('cmd')", risk_score=0.50, risk_reasons=["shell_execution"]),
            # 4 Medium risk (0.15 <= score < 0.40)
            CompressedChunk(chunk_id="m1", chunk_type="function", name="med1", line_start=30, line_end=35, source="def med1():\n    print('a')\n    print('b')\n    print('c')\n    return 1", risk_score=0.20, risk_reasons=["takes_external_input"]),
            CompressedChunk(chunk_id="m2", chunk_type="function", name="med2", line_start=40, line_end=45, source="def med2():\n    print('a')\n    print('b')\n    print('c')\n    return 2", risk_score=0.20, risk_reasons=["file_operation"]),
            CompressedChunk(chunk_id="m3", chunk_type="function", name="med3", line_start=50, line_end=55, source="def med3():\n    print('a')\n    print('b')\n    print('c')\n    return 3", risk_score=0.20, risk_reasons=["http_outbound"]),
            CompressedChunk(chunk_id="m4", chunk_type="function", name="med4", line_start=60, line_end=65, source="def med4():\n    print('a')\n    print('b')\n    print('c')\n    return 4", risk_score=0.20, risk_reasons=["crypto_operation"]),
            # 3 Low risk (score < 0.15)
            CompressedChunk(chunk_id="l1", chunk_type="function", name="get_a", line_start=70, line_end=72, source="def get_a():\n    return self.a", risk_score=0.0, risk_reasons=[]),
            CompressedChunk(chunk_id="l2", chunk_type="function", name="set_a", line_start=75, line_end=77, source="def set_a(val):\n    self.a = val", risk_score=0.0, risk_reasons=[]),
            CompressedChunk(chunk_id="l3", chunk_type="function", name="to_str", line_start=80, line_end=82, source="def to_str():\n    return 'str'", risk_score=0.0, risk_reasons=[]),
        ]

        prompt = self.prompt_builder.build_from_chunks("test.py", chunks, compression_ratio=3.0)

        # High risk full source in prompt
        self.assertIn("def high1()", prompt)
        self.assertIn("def high2()", prompt)
        self.assertIn("def high3()", prompt)

        # Medium risk signature in prompt with omission comment
        self.assertIn("--- function: med1 (line 30) ---", prompt)
        self.assertIn("[body compressed", prompt)

        # Low risk omitted from prompt
        self.assertNotIn("def get_a()", prompt)
        self.assertNotIn("def set_a(", prompt)
        self.assertNotIn("def to_str()", prompt)

    def test_fallback_on_syntax_error(self):
        """Test fallback behavior when Python source contains syntax errors."""
        bad_code = "def invalid_syntax_function(:\n    return 'broken'\n"
        result = self.compressor.compress("bad.py", bad_code, "Python")

        self.assertTrue(result.fallback_used)
        self.assertEqual(result.compression_ratio, 1.0)
        self.assertEqual(len(result.chunks), 1)
        self.assertEqual(result.chunks[0].risk_score, 1.0)

    def test_line_number_preservation(self):
        """Test that original file line numbers are preserved accurately."""
        padding = "\n" * 46  # 46 blank lines
        code = padding + "def target_func():\n    return 'line 47'\n"
        result = self.compressor.compress("padded.py", code, "Python")

        self.assertFalse(result.fallback_used)
        chunk = next(c for c in result.chunks if c.name == "target_func")
        self.assertEqual(chunk.line_start, 47)

    def test_compression_ratio_reported(self):
        """Test compression ratio calculation on large source file."""
        # 1000 char source file with boilerplate
        large_code = "import os\n\n"
        for i in range(30):
            large_code += f"def getter_{i}():\n    return {i}\n\n"
        large_code += "def dangerous_sink(cmd):\n    os.system(cmd)\n"

        result = self.compressor.compress("large.py", large_code, "Python")
        self.assertFalse(result.fallback_used)
        self.assertGreaterEqual(result.compression_ratio, 1.5)


if __name__ == "__main__":
    unittest.main()
