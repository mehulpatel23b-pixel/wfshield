"""wfyaml — a dependency-free parser for the YAML subset used by GitHub
Actions workflow files.

Supported syntax (everything a real workflow uses in practice):
  * comments (``#`` outside of quoted strings)
  * nested mappings via indentation
  * block lists (``- `` items), including lists of mappings
  * block scalars (``|``, ``|-``, ``|+``, ``>``, ``>-``, ``>+``) — the
    ``run:`` / ``env:`` script payloads
  * scalars: raw strings, quoted strings, ints, floats, booleans, null
  * empty inline maps/lists (``{}`` / ``[]``)
  * simple inline lists (``key: [a, b, c]``)

Every string produced is a :class:`Loc` — a ``str`` subclass that also
carries the 1-based source line it came from, so rules can report exact
locations without a second pass.

Not supported (will not raise; values are kept best-effort):
  * anchors and aliases, multi-document streams, deep flow nesting.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple


class YamlError(ValueError):
    """Raised only for structurally impossible documents."""


class Loc(str):
    """A string scalar that remembers its source line."""

    lineno: int = 0

    def __new__(cls, value: str, lineno: int = 0) -> "Loc":
        obj = super().__new__(cls, value)
        obj.lineno = lineno
        return obj


def _strip_comment(line: str) -> str:
    out: List[str] = []
    quote: Optional[str] = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                quote = None
            out.append(ch)
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _content(raw: str) -> str:
    return _strip_comment(raw).strip("\n").rstrip()


def _indent(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" "))


def _scalar(tok: str, lineno: int = 0) -> Any:
    tok = tok.strip()
    if tok == "" or tok == "~" or tok.lower() == "null":
        return None
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return Loc(tok[1:-1], lineno)
    low = tok.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", tok):
        try:
            return int(tok)
        except ValueError:
            return Loc(tok, lineno)
    if re.fullmatch(r"-?\d+\.\d+", tok):
        try:
            return float(tok)
        except ValueError:
            return Loc(tok, lineno)
    return Loc(tok, lineno)


def _split_inline(inner: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf or parts:
        parts.append("".join(buf))
    return parts


def _inline_list(tok: str, lineno: int = 0) -> List[Any]:
    inner = tok.strip()[1:-1].strip()
    if not inner:
        return []
    return [_scalar(p) for p in _split_inline(inner)]


_BLOCK_SCALAR_RE = re.compile(r"(?:\||>)(?:0|[1-9][0-9]*)?[+-]?")


class _Parser:
    def __init__(self, text: str) -> None:
        self.raw: List[str] = text.splitlines()
        self.i = 0
        self.n = len(self.raw)

    # -- navigation -------------------------------------------------

    def _sig(self, i: int) -> Optional[Tuple[int, int, str]]:
        """Next significant (non-blank, non-comment) raw line at or after i.

        Returns (raw_index, indent, content) or None.
        """
        while i < self.n:
            content = _content(self.raw[i])
            if content.strip():
                return (i, _indent(content), content.strip())
            i += 1
        return None

    def peek(self) -> Optional[Tuple[int, int, str]]:
        return self._sig(self.i)

    # -- block scalars ----------------------------------------------

    def _block_scalar(self, marker_indent: int, marker: str) -> Loc:
        start = self.i  # first raw line after the marker line
        scalar_indent: Optional[int] = None
        j = start
        while j < self.n:
            line = self.raw[j]
            if not line.strip():
                j += 1
                continue
            ind = _indent(line)
            if ind <= marker_indent:
                break
            scalar_indent = ind
            break
        lines: List[str] = []
        if scalar_indent is not None:
            j = start
            while j < self.n:
                line = self.raw[j]
                if not line.strip():
                    lines.append("")
                    j += 1
                    continue
                if _indent(line) < scalar_indent:
                    break
                lines.append(line[scalar_indent:])
                j += 1
            self.i = j
        else:
            nxt = self.peek()
            self.i = nxt[0] if nxt is not None else self.n
        if marker.startswith(">"):
            text = self._fold(lines)
        else:
            text = "\n".join(lines)
        chomp = marker[-1:] if marker[-1:] in ("+", "-") else ""
        if chomp == "+":
            if lines:
                text = "\n".join(lines) + "\n"
        elif chomp == "-":
            text = text.rstrip("\n")
        else:
            text = text.rstrip("\n")
            if text:
                text += "\n"
        return Loc(text, start + 1)

    @staticmethod
    def _fold(lines: List[str]) -> str:
        out: List[str] = []
        buf: List[str] = []
        for ln in lines:
            if ln == "":
                if buf:
                    out.append(" ".join(buf))
                    buf = []
                out.append("")
            else:
                buf.append(ln)
        if buf:
            out.append(" ".join(buf))
        return "\n".join(out)

    # -- structural parsing -------------------------------------------

    def parse_document(self) -> dict:
        nxt = self.peek()
        if nxt is None:
            return {}
        if nxt[2].startswith("- "):
            raise YamlError("top-level sequences are not valid workflow documents")
        return self._map(nxt[1])

    def _is_mapping_item(self, rest: str) -> bool:
        if rest.endswith(":"):
            return True
        before, sep, _after = rest.partition(": ")
        return sep != "" and before.split() and len(before.split()) == 1

    def _value_or_block(self, key: str, value: str, line_idx: int,
                        line_indent: int, into: dict) -> None:
        """Store ``key: value`` handling nested blocks and block scalars."""
        if value == "":
            nxt = self.peek()
            if nxt is None:
                into[key] = None
                return
            ni, nind, nline = nxt
            if nind > line_indent:
                into[key] = self._block(nind)
            elif nind == line_indent and nline.startswith("- "):
                into[key] = self._seq(nind)
            else:
                into[key] = None
        elif _BLOCK_SCALAR_RE.fullmatch(value):
            self.i = line_idx + 1
            into[key] = self._block_scalar(line_indent, value)
        elif value.startswith("[") and value.endswith("]"):
            into[key] = _inline_list(value, line_idx + 1)
        elif value == "{}":
            into[key] = {}
        else:
            into[key] = _scalar(value, line_idx + 1)

    def _map(self, indent: int, into: Optional[dict] = None) -> dict:
        result: dict = {} if into is None else into
        while True:
            nxt = self.peek()
            if nxt is None:
                break
            ni, nind, nline = nxt
            if nind < indent or nline.startswith("- "):
                break
            self.i = ni + 1
            key, _sep, value = nline.partition(":")
            key = key.strip().strip("'\"")
            value = value.strip()
            if not _sep:
                continue
            self._value_or_block(key, value, ni, nind, result)
        return result

    def _block(self, indent: int) -> Any:
        nxt = self.peek()
        assert nxt is not None
        if nxt[2].startswith("- "):
            return self._seq(nxt[1])
        return self._map(nxt[1])

    def _seq(self, dash_indent: int) -> List[Any]:
        items: List[Any] = []
        while True:
            nxt = self.peek()
            if nxt is None:
                break
            ni, nind, nline = nxt
            if nind != dash_indent or not nline.startswith("- "):
                break
            rest = nline[2:].strip()
            if self._is_mapping_item(rest):
                # "- key: value" — a mapping item
                self.i = ni + 1
                item: dict = {}
                key, _sep, value = rest.partition(":")
                key = key.strip().strip("'\"")
                content_col = nind + 2
                self._value_or_block(key, value.strip(), ni, content_col, item)
                follow = self.peek()
                if follow is not None and follow[1] > dash_indent:
                    self._map(follow[1], item)
                items.append(item)
            elif rest == "":
                self.i = ni + 1
                follow = self.peek()
                if follow is not None and follow[1] > dash_indent:
                    items.append(self._block(follow[1]))
                else:
                    items.append(None)
            else:
                self.i = ni + 1
                items.append(_scalar(rest, ni + 1))
        return items


def parse(text: str) -> dict:
    """Parse a workflow YAML document into a Python dict."""
    return _Parser(text).parse_document()
