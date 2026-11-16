from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "about:")

# Response bodies are capped at 200 KB by SafeHttpClient; extraction walks the
# full document but never keeps more than these references per page.
MAX_LINKS = 400
MAX_SCRIPTS = 80
MAX_FORMS = 50
MAX_FIELDS = 60


@dataclass
class FormField:
    name: str
    type: str = "text"
    autocomplete: str = ""


@dataclass
class FormRecord:
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)

    @property
    def parameter_names(self) -> list[str]:
        return [item.name for item in self.fields if item.name]


@dataclass
class Extraction:
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[FormRecord] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)

    @property
    def parameter_names(self) -> list[str]:
        names: list[str] = []
        for url in self.links:
            query = urlsplit(url).query
            names.extend(key for key, _ in parse_qsl(query, keep_blank_values=True))
        for form in self.forms:
            names.extend(form.parameter_names)
        return list(dict.fromkeys(name for name in names if name))


def normalize_url(base: str, reference: str) -> str | None:
    reference = reference.strip()
    if not reference or reference.lower().startswith(SKIP_SCHEMES):
        return None
    try:
        resolved, _ = urldefrag(urljoin(base, reference))
    except ValueError:
        return None
    parts = urlsplit(resolved)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    return resolved


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.result = Extraction()
        self._form: FormRecord | None = None
        self._in_script = False
        self._script_buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "form":
            action = values.get("action", "")
            method = (values.get("method") or "GET").upper()
            self._form = FormRecord(action=action, method=method)
            if len(self.result.forms) < MAX_FORMS:
                self.result.forms.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = values.get("name", "")
            if name and len(self._form.fields) < MAX_FIELDS:
                self._form.fields.append(
                    FormField(
                        name=name,
                        type=values.get("type", tag),
                        autocomplete=values.get("autocomplete", ""),
                    )
                )
        elif tag == "script":
            src = values.get("src", "")
            if src and len(self.result.scripts) < MAX_SCRIPTS:
                self.result.scripts.append(src)
            self._in_script = not src
            self._script_buffer = []
        elif tag in {"a", "area"}:
            self._add_link(values.get("href", ""))
        elif tag == "link":
            if "stylesheet" in values.get("rel", "").lower():
                self._add_link(values.get("href", ""))
        elif tag in {"iframe", "frame"}:
            self._add_link(values.get("src", ""))
        elif tag in {"img", "source", "video", "audio"}:
            self._add_link(values.get("src", ""))
        elif tag == "meta" and values.get("name", "").lower() == "generator":
            self.result.comments.append(f"generator: {values.get('content', '')}")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "input":
            self.handle_starttag(tag, attrs)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "script" and self._in_script:
            inline = "".join(self._script_buffer).strip()
            if inline and len(self.result.inline_scripts) < MAX_SCRIPTS:
                self.result.inline_scripts.append(inline[:20_000])
            self._in_script = False
            self._script_buffer = []

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.result.comments.append(data.strip()[:500])

    def _add_link(self, reference: str) -> None:
        if reference and len(self.result.links) < MAX_LINKS:
            self.result.links.append(reference)


def extract_document(base_url: str, body: str) -> Extraction:
    """Parse one HTML document and resolve its references against the final URL."""
    parser = _Extractor()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        # Malformed markup must never abort a crawl.
        pass
    result = parser.result
    result.links = _resolved(base_url, result.links)
    result.scripts = _resolved(base_url, result.scripts)
    for form in result.forms:
        if not form.action:
            form.action = base_url
        else:
            form.action = normalize_url(base_url, form.action) or ""
    return result


def _resolved(base_url: str, references: list[str]) -> list[str]:
    seen: list[str] = []
    for reference in references:
        normalized = normalize_url(base_url, reference)
        if normalized and normalized not in seen:
            seen.append(normalized)
    return seen
