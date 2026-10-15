"""Static analysis of a fetched page. No JavaScript is executed."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from .domains import brands_mentioned, flag, registered_domain

_META_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)
_MAX_TITLE = 200
_MAX_FORMS = 50


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self.forms: list[dict[str, Any]] = []
        self._form_stack: list[dict[str, Any]] = []
        self.loose_password_fields = 0
        self.iframes: list[dict[str, Any]] = []
        self.meta_refresh: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form" and len(self.forms) < _MAX_FORMS:
            form = {"action": a.get("action", "").strip(), "has_password": False}
            self.forms.append(form)
            self._form_stack.append(form)
        elif tag == "input" and a.get("type", "").lower() == "password":
            if self._form_stack:
                self._form_stack[-1]["has_password"] = True
            else:
                self.loose_password_fields += 1
        elif tag == "iframe":
            hidden = (
                "hidden" in a
                or a.get("width", "").strip() in {"0", "1"}
                or a.get("height", "").strip() in {"0", "1"}
                or bool(_HIDDEN_STYLE.search(a.get("style", "")))
            )
            self.iframes.append({"src": a.get("src", "").strip(), "hidden": hidden})
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            match = _META_REFRESH_URL.search(a.get("content", ""))
            if match and self.meta_refresh is None:
                self.meta_refresh = match.group(1).strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form_stack:
            self._form_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(len(p) for p in self.title_parts) < _MAX_TITLE:
            self.title_parts.append(data)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _decode(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w.-]+)", content_type, re.IGNORECASE)
    for encoding in ([match.group(1)] if match else []) + ["utf-8"]:
        try:
            return body.decode(encoding, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


def analyze_page(
    body: bytes,
    content_type: str,
    final_url: str,
    original_host: str,
    redirect_count: int,
    http_status: int,
    truncated: bool,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Summarise ``body`` and derive flags. ``original_host`` is the host the user submitted."""
    flags: list[dict[str, str]] = []
    final_host = _host(final_url)
    page_reg = registered_domain(final_host) if final_host else ""

    details: dict[str, Any] = {
        "status": "ok",
        "http_status": http_status,
        "final_url": final_url,
        "redirect_count": redirect_count,
        "truncated": truncated,
    }

    if original_host and final_host and registered_domain(original_host) != page_reg:
        details["redirected_off_domain"] = True
        flags.append(flag(
            "info", "redirects_to_other_domain",
            f"The address redirects to a different domain ({page_reg}).",
        ))

    if "html" not in content_type.lower() and content_type:
        details["note"] = "Response is not an HTML page, so page content was not analysed."
        return details, flags

    parser = _PageParser()
    try:
        parser.feed(_decode(body, content_type))
        parser.close()
    except Exception:  # html.parser is lenient, but never let a weird page break the scan
        details["note"] = "Page HTML could not be parsed."
        return details, flags

    title = " ".join("".join(parser.title_parts).split())[:_MAX_TITLE]
    password_forms = [f for f in parser.forms if f["has_password"]]
    password_fields = len(password_forms) + parser.loose_password_fields

    def off_domain(target: str) -> bool:
        if not target or target.startswith("#"):
            return False
        absolute = urljoin(final_url, target)
        scheme = urlsplit(absolute).scheme.lower()
        if scheme in ("javascript", "data"):
            return True
        host = _host(absolute)
        return bool(host) and registered_domain(host) != page_reg

    form_off = [f for f in parser.forms if off_domain(f["action"])]
    pw_form_off = [f for f in password_forms if off_domain(f["action"])]
    hidden_iframes = [i for i in parser.iframes if i["hidden"]]
    offsite_iframes = [i for i in parser.iframes if i["src"] and off_domain(i["src"])]
    refresh_off = bool(parser.meta_refresh and off_domain(parser.meta_refresh))

    details.update({
        "title": title or None,
        "form_count": len(parser.forms),
        "password_field_count": password_fields,
        "forms_posting_off_domain": len(form_off),
        "hidden_iframe_count": len(hidden_iframes),
        "offsite_iframe_count": len(offsite_iframes),
        "meta_refresh_off_domain": refresh_off,
    })

    if password_fields:
        flags.append(flag("info", "password_field", "The page asks for a password."))
    if pw_form_off:
        flags.append(flag(
            "high", "password_form_posts_off_domain",
            "A password form on this page submits to a different site than the one you are visiting.",
        ))
    elif form_off:
        flags.append(flag("warning", "form_posts_off_domain", "A form on this page submits to a different site."))
    if password_fields and final_url.lower().startswith("http://"):
        flags.append(flag("warning", "password_over_http", "The page asks for a password but is not served over HTTPS."))
    if hidden_iframes:
        flags.append(flag("warning", "hidden_iframe", "The page embeds hidden frames."))
    if refresh_off:
        flags.append(flag("warning", "meta_refresh_off_domain", "The page automatically redirects the visitor to another site."))
    if title:
        impersonated = brands_mentioned(title, page_reg)
        if impersonated:
            flags.append(flag(
                "warning", "title_brand_mismatch",
                f"The page title mentions {', '.join(impersonated)}, but the site '{page_reg}' is not that brand's domain.",
            ))
    return details, flags
