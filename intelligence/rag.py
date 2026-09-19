"""
intelligence/rag.py
-------------------
Long-term knowledge: checklists, previous cases, validated lessons and
security reference material, retrieved by *context* (BM25, offline and
deterministic). Learned lessons persist under $RAVEN_HOME/knowledge.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Optional

from core.models import Lesson, RAGContext, RAGSnippet

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge"
_STOP = set("a an and are as at be by for from has have in is it of on or that the this to was were with".split())
_KIND_BY_DIR = {"checklists": "checklist", "cases": "case", "lessons": "lesson"}


def tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9_.+-]{2,}", text.lower()) if t not in _STOP]


def _chunks(text: str, limit: int = 900) -> List[tuple]:
    """Split markdown into (heading, body) chunks of bounded size."""
    out, heading, buf = [], "", []
    def flush():
        body = "\n".join(buf).strip()
        while len(body) > limit:
            cut = body.rfind("\n", 0, limit) or limit
            out.append((heading, body[:cut].strip()))
            body = body[cut:].strip()
        if body:
            out.append((heading, body))
    for line in text.splitlines():
        if line.startswith("#"):
            flush()
            buf.clear()
            heading = line.lstrip("# ").strip()
        else:
            buf.append(line)
    flush()
    return out


class _Doc:
    __slots__ = ("snippet", "tokens", "tf", "tags")

    def __init__(self, snippet: RAGSnippet, tags: Iterable[str] = ()) -> None:
        self.snippet = snippet
        self.tags = {t.lower() for t in tags}
        # title tokens count double: headings are strong topical signals
        self.tokens = tokenize(snippet.title) * 2 + tokenize(snippet.text) + list(self.tags)
        self.tf = Counter(self.tokens)


class KnowledgeBase:
    def __init__(self, knowledge_dir: Optional[Path] = None, learned_dir: Optional[Path] = None) -> None:
        self.knowledge_dir = knowledge_dir or KNOWLEDGE_DIR
        home = Path(os.environ.get("RAVEN_HOME", str(Path.home() / ".raven")))
        self.learned_path = (learned_dir or home / "knowledge") / "lessons.jsonl"
        self._docs: List[_Doc] = []
        self._df: Counter = Counter()
        self._avg = 1.0
        self.reload()

    # -- indexing ---------------------------------------------------------------

    def reload(self) -> None:
        docs: List[_Doc] = []
        if self.knowledge_dir.exists():
            for md in sorted(self.knowledge_dir.rglob("*.md")):
                rel = md.relative_to(self.knowledge_dir)
                kind = _KIND_BY_DIR.get(rel.parts[0], "knowledge")
                text = md.read_text(encoding="utf-8", errors="ignore")
                for heading, body in _chunks(text):
                    docs.append(_Doc(RAGSnippet(
                        source=rel.as_posix(), title=heading or md.stem, kind=kind, text=body)))  # type: ignore[arg-type]
        for lesson in self.learned_lessons():
            docs.append(_Doc(self._lesson_snippet(lesson), lesson.tags))
        self._docs = docs
        self._df = Counter(t for d in docs for t in set(d.tokens))
        self._avg = (sum(len(d.tokens) for d in docs) / len(docs)) if docs else 1.0

    @staticmethod
    def _lesson_snippet(l: Lesson) -> RAGSnippet:
        return RAGSnippet(
            source=f"learned/{l.lesson_id}", title=f"{l.kind.title()}: {l.context}", kind=l.kind,
            text=(f"Observation: {l.observation}\nLesson: {l.lesson}\n"
                  f"Recommended validation: {l.recommended_validation}"))

    # -- retrieval --------------------------------------------------------------

    def retrieve(self, query: str, purpose: str = "", top_k: int = 4,
                 kinds: Optional[Iterable[str]] = None) -> RAGContext:
        q = tokenize(query)
        wanted = set(kinds) if kinds else None
        n = max(len(self._docs), 1)
        scored = []
        for d in self._docs:
            if wanted and d.snippet.kind not in wanted:
                continue
            score, dl = 0.0, len(d.tokens)
            for t in q:
                f = d.tf.get(t, 0)
                if not f:
                    continue
                idf = math.log(1 + (n - self._df[t] + 0.5) / (self._df[t] + 0.5))
                score += idf * (f * 2.2) / (f + 1.2 * (0.25 + 0.75 * dl / self._avg))
            if score > 0:
                scored.append((score, d))
        scored.sort(key=lambda x: -x[0])
        snippets = [d.snippet.model_copy(update={"score": round(s, 3)}) for s, d in scored[:top_k]]
        return RAGContext(query=query, purpose=purpose, snippets=snippets)

    # -- learned lessons --------------------------------------------------------

    def learned_lessons(self) -> List[Lesson]:
        if not self.learned_path.exists():
            return []
        out = []
        for line in self.learned_path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(Lesson.model_validate(json.loads(line)))
            except (json.JSONDecodeError, ValueError):
                continue
        return out

    def add_lesson(self, lesson: Lesson) -> bool:
        """Persist a lesson unless an equivalent one exists. Returns True if stored."""
        key = (lesson.context.lower(), lesson.lesson.lower())
        if any((l.context.lower(), l.lesson.lower()) == key for l in self.learned_lessons()):
            return False
        self.learned_path.parent.mkdir(parents=True, exist_ok=True)
        with self.learned_path.open("a", encoding="utf-8") as fh:
            fh.write(lesson.model_dump_json() + "\n")
        self.reload()
        return True
