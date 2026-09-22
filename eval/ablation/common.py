"""Strict, content-addressed IO for frozen experiments (never rebuild indexes)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(value):
    if not isinstance(value, bytes):
        value = (value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"))).encode()
    return hashlib.sha256(value).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()] if Path(path).exists() else []


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def write_jsonl(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    temp.replace(path)


def append_jsonl(path, row):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        stream.flush()


def identity(record):
    r = record.get("corpus_entry", record)
    return tuple(r.get(k) for k in ("ghsa_id", "fix_commit_sha", "file_path", "function_name"))


def entry_identity(entry):
    return identity(entry.model_dump())


def source_key(source, language):
    """Declared-language syntax identity, preserving literals and identifiers."""
    from provtrail.pipeline.controller.parsing import parse_source
    for text in (source, "class __Wrapper {\n" + source + "\n}"):
        root = parse_source(text, language=language).root_node
        if root.has_error:
            continue
        def walk(node):
            if node.type == "comment":
                return None
            children = [v for child in node.children if (v := walk(child)) is not None]
            return [node.type, children if children else node.text.decode()]
        return digest([language, walk(root)])
    return digest([language, source])


def seal(value):
    return dict(value, content_sha256=digest(value))


def unseal(value):
    body = {k: v for k, v in value.items() if k != "content_sha256"}
    if digest(body) != value.get("content_sha256"):
        raise ValueError("Content seal mismatch")
    return body
