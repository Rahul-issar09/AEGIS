"""AEGIS Agent 1 — HTML Link and Form Crawler.

Crawls target HTML pages to discover endpoints, links, forms, and API routes
per PRD Section 15. All network requests strictly use HttpClient, ensuring
scope validation and rate limiting are never bypassed.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from agent1.discovery.base import DiscoverySource
from agent1.discovery.models import (
    Endpoint,
    EndpointParameter,
    ParameterLocation,
)

if TYPE_CHECKING:
    from agent1.http.client import HttpClient

logger = logging.getLogger("aegis.discovery.crawler")

# Regex to find quoted API paths in scripts or raw text (e.g. "/api/v1/users")
_API_PATH_RE = re.compile(
    r"""(?P<quote>['"`])(?P<path>/(?:api|v[0-9]+|rest|graphql)/[a-zA-Z0-9_\-\./{}]+)(?P=quote)"""
)


class _Form:
    """Internal helper to capture form details during HTML parsing."""

    def __init__(self, action: str = "", method: str = "GET") -> None:
        self.action = action
        self.method = method.upper() if method else "GET"
        self.inputs: list[dict[str, str]] = []


class _PageParser(HTMLParser):
    """Standard-library HTML parser to extract links, forms, and scripts."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[_Form] = []
        self.script_content: list[str] = []
        self._current_form: _Form | None = None
        self._in_script: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "a":
            href = attr_dict.get("href")
            if href and not href.startswith(("javascript:", "mailto:", "tel:")):
                abs_url = urljoin(self.base_url, href)
                clean_url, _ = urldefrag(abs_url)
                self.links.append(clean_url)

        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET")
            abs_action = urljoin(self.base_url, action) if action else self.base_url
            clean_action, _ = urldefrag(abs_action)
            self._current_form = _Form(action=clean_action, method=method)
            self.forms.append(self._current_form)

        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                input_type = attr_dict.get("type", "text" if tag == "input" else tag)
                self._current_form.inputs.append(
                    {"name": name, "type": input_type, "value": attr_dict.get("value", "")}
                )

        elif tag == "script":
            src = attr_dict.get("src")
            if src:
                abs_src = urljoin(self.base_url, src)
                clean_src, _ = urldefrag(abs_src)
                self.links.append(clean_src)
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.script_content.append(data)


class HtmlCrawler(DiscoverySource):
    """Scope-safe web crawler extracting endpoints from HTML and scripts.

    Per PRD Section 8 & 15:
    - Traverses links up to max_depth
    - Extracts links, forms, form inputs, script-referenced API paths
    - Every request goes through HttpClient (strictly enforcing scope & rate limits)
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 40,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages

    @property
    def name(self) -> str:
        return "crawler"

    def discover(
        self,
        target_url: str,
        http_client: HttpClient,
    ) -> list[Endpoint]:
        """Crawl the target URL and return all discovered endpoints."""
        discovered: list[Endpoint] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(target_url, 0)])

        target_parsed = urlparse(target_url)
        allowed_host = (target_parsed.hostname or "").lower()

        logger.info(
            "crawler.started",
            extra={"target": target_url, "max_depth": self.max_depth},
        )

        while queue and len(visited) < self.max_pages:
            current_url, depth = queue.popleft()
            clean_url, _ = urldefrag(current_url)

            if clean_url in visited:
                continue

            visited.add(clean_url)

            # Record this URL itself as an endpoint
            url_ep = self._url_to_endpoint(clean_url, method="GET")
            if url_ep:
                discovered.append(url_ep)

            # Do not fetch beyond max_depth
            if depth >= self.max_depth:
                continue

            # Fetch page content through HttpClient
            try:
                logger.debug(
                    "crawler.fetching",
                    extra={"url": clean_url, "depth": depth},
                )
                req_resp = http_client.get(clean_url)
            except Exception as e:
                logger.debug(
                    "crawler.fetch_failed",
                    extra={"url": clean_url, "error": str(e)},
                )
                continue

            response = req_resp.response
            if response.status_code >= 400:
                continue

            content_type = response.headers.get("content-type", "").lower()
            body_text = response.body

            # Extract API path literals from response body (useful for JS, JSON, HTML)
            for match in _API_PATH_RE.finditer(body_text):
                api_path = match.group("path")
                full_api_url = urljoin(clean_url, api_path)
                api_ep = self._url_to_endpoint(full_api_url, method="GET")
                if api_ep:
                    discovered.append(api_ep)

            # If HTML, parse DOM for links and forms
            if "html" in content_type or "<html" in body_text.lower():
                try:
                    parser = _PageParser(base_url=clean_url)
                    parser.feed(body_text)

                    # Process forms
                    for form in parser.forms:
                        form_ep = self._form_to_endpoint(form, clean_url)
                        if form_ep:
                            discovered.append(form_ep)

                    # Process links
                    for link in parser.links:
                        link_parsed = urlparse(link)
                        link_host = (link_parsed.hostname or "").lower()
                        # Only follow links matching target host
                        if link_host == allowed_host and link not in visited:
                            # Record as endpoint
                            lep = self._url_to_endpoint(link, method="GET")
                            if lep:
                                discovered.append(lep)
                            # Queue for deeper crawl
                            if depth + 1 <= self.max_depth:
                                queue.append((link, depth + 1))

                    # Process script content for API endpoints
                    for script in parser.script_content:
                        for match in _API_PATH_RE.finditer(script):
                            api_path = match.group("path")
                            full_api_url = urljoin(clean_url, api_path)
                            api_ep = self._url_to_endpoint(full_api_url, method="GET")
                            if api_ep:
                                discovered.append(api_ep)

                except Exception as e:
                    logger.debug(
                        "crawler.parse_failed",
                        extra={"url": clean_url, "error": str(e)},
                    )

        logger.info(
            "crawler.completed",
            extra={"visited_count": len(visited), "discovered_count": len(discovered)},
        )
        return discovered

    def _url_to_endpoint(self, url: str, method: str = "GET") -> Endpoint | None:
        """Convert a URL string into an Endpoint model."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return None

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        path = parsed.path or "/"
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        query_params = sorted(query_dict.keys())

        endpoint_params = [
            EndpointParameter(
                name=name,
                location=ParameterLocation.QUERY,
                type="string",
                required=False,
            )
            for name in query_params
        ]

        return Endpoint(
            id="ep_tmp",
            method=method.upper(),
            scheme=parsed.scheme,
            host=parsed.hostname,
            port=port,
            path=path,
            raw_path=path,
            parameters=endpoint_params,
            query_parameters=query_params,
            source="crawler",
        )

    def _form_to_endpoint(self, form: _Form, base_url: str) -> Endpoint | None:
        """Convert a parsed HTML form into an Endpoint model."""
        target_url = form.action or base_url
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.hostname:
            return None

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        path = parsed.path or "/"
        param_location = (
            ParameterLocation.FORM
            if form.method == "POST"
            else ParameterLocation.QUERY
        )

        parameters: list[EndpointParameter] = []
        query_params: list[str] = []

        for inp in form.inputs:
            name = inp["name"]
            itype = inp.get("type", "text")
            param_type = "integer" if itype == "number" else "string"
            parameters.append(
                EndpointParameter(
                    name=name,
                    location=param_location,
                    type=param_type,
                    required=False,
                    description=f"Form field ({itype})",
                )
            )
            if param_location == ParameterLocation.QUERY:
                query_params.append(name)

        return Endpoint(
            id="ep_tmp",
            method=form.method,
            scheme=parsed.scheme,
            host=parsed.hostname,
            port=port,
            path=path,
            raw_path=path,
            parameters=parameters,
            query_parameters=sorted(query_params),
            source="crawler",
        )
