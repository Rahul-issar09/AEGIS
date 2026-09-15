"""AEGIS Agent 1 — OpenAPI / Swagger Specification Parser.

Probes target application for OpenAPI/Swagger definitions and converts
discovered paths and operations into Endpoint models per PRD Section 15.
Does NOT assume OpenAPI endpoints exist; fails gracefully.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import yaml

from agent1.discovery.base import DiscoverySource
from agent1.discovery.models import (
    Endpoint,
    EndpointParameter,
    ParameterLocation,
)

if TYPE_CHECKING:
    from agent1.http.client import HttpClient

logger = logging.getLogger("aegis.discovery.openapi")

# Standard probe locations per PRD Section 15
DEFAULT_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/openapi.yml",
]

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


class OpenApiParser(DiscoverySource):
    """Discovery source that probes and parses OpenAPI/Swagger specifications."""

    def __init__(
        self,
        custom_paths: list[str] | None = None,
    ) -> None:
        self.probe_paths = custom_paths or list(DEFAULT_OPENAPI_PATHS)

    @property
    def name(self) -> str:
        return "openapi"

    def discover(
        self,
        target_url: str,
        http_client: HttpClient,
    ) -> list[Endpoint]:
        """Probe for OpenAPI/Swagger documents and parse endpoints."""
        endpoints: list[Endpoint] = []
        parsed_target = urlparse(target_url)
        base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        for path in self.probe_paths:
            probe_url = urljoin(base_origin, path)
            try:
                logger.debug("openapi.probe", extra={"url": probe_url})
                req_resp = http_client.get(probe_url)
                resp = req_resp.response

                if resp.status_code != 200:
                    continue

                body = resp.body.strip()
                if not body:
                    continue

                # Try parsing as JSON or YAML
                spec = self._parse_content(body)
                if not spec or not isinstance(spec, dict):
                    continue

                # Validate it's an OpenAPI or Swagger document
                if "openapi" in spec or "swagger" in spec or "paths" in spec:
                    logger.info(
                        "openapi.spec_found",
                        extra={"url": probe_url, "version": spec.get("openapi") or spec.get("swagger")},
                    )
                    parsed_endpoints = self.parse_spec(spec, target_url)
                    endpoints.extend(parsed_endpoints)
                    # Found and parsed a valid specification
                    break

            except Exception as e:
                logger.debug(
                    "openapi.probe_failed",
                    extra={"url": probe_url, "error": str(e)},
                )
                continue

        return endpoints

    def _parse_content(self, text: str) -> dict[str, Any] | None:
        """Safely parse text as JSON or YAML."""
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except Exception:
                pass

        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        return None

    def parse_spec(
        self,
        spec: dict[str, Any],
        base_url: str,
    ) -> list[Endpoint]:
        """Convert a parsed OpenAPI/Swagger specification into Endpoint models."""
        endpoints: list[Endpoint] = []
        parsed_base = urlparse(base_url)
        scheme = parsed_base.scheme or "http"
        host = parsed_base.hostname or ""
        port = parsed_base.port
        if port is None:
            port = 443 if scheme == "https" else 80

        # Determine base path prefix (Swagger basePath or OpenAPI servers[0].url)
        base_prefix = ""
        if "basePath" in spec and isinstance(spec["basePath"], str):
            base_prefix = spec["basePath"].rstrip("/")
        elif "servers" in spec and isinstance(spec["servers"], list) and spec["servers"]:
            server_url = spec["servers"][0].get("url", "")
            if server_url.startswith("/"):
                base_prefix = server_url.rstrip("/")
            elif server_url.startswith("http"):
                server_parsed = urlparse(server_url)
                base_prefix = server_parsed.path.rstrip("/")

        global_security = bool(spec.get("security"))
        paths = spec.get("paths", {})

        if not isinstance(paths, dict):
            return []

        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            full_path = f"{base_prefix}/{path_key.lstrip('/')}"
            if not full_path.startswith("/"):
                full_path = "/" + full_path

            # Common parameters for the path item
            common_params = path_item.get("parameters", [])
            if not isinstance(common_params, list):
                common_params = []

            for method_name, op_item in path_item.items():
                if method_name.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(op_item, dict):
                    continue

                method = method_name.upper()

                # Determine authentication requirement
                # PRD Section 12 & 16: authentication_required
                if "security" in op_item:
                    sec_val = op_item["security"]
                    # If empty list [], explicit auth override (public)
                    auth_required = bool(sec_val)
                else:
                    auth_required = global_security

                # Combine common and operation-level parameters
                op_params = op_item.get("parameters", [])
                if not isinstance(op_params, list):
                    op_params = []

                all_raw_params = common_params + op_params
                parameters: list[EndpointParameter] = []
                query_param_names: list[str] = []

                for raw_p in all_raw_params:
                    if not isinstance(raw_p, dict):
                        continue
                    p_name = raw_p.get("name", "")
                    if not p_name:
                        continue

                    p_in = raw_p.get("in", "query").lower()
                    loc_map = {
                        "path": ParameterLocation.PATH,
                        "query": ParameterLocation.QUERY,
                        "header": ParameterLocation.HEADER,
                        "body": ParameterLocation.BODY,
                        "formdata": ParameterLocation.FORM,
                        "cookie": ParameterLocation.HEADER,
                    }
                    loc = loc_map.get(p_in, ParameterLocation.QUERY)

                    schema = raw_p.get("schema", {})
                    p_type = "string"
                    if isinstance(schema, dict) and "type" in schema:
                        p_type = schema["type"]
                    elif "type" in raw_p:
                        p_type = raw_p["type"]

                    parameters.append(
                        EndpointParameter(
                            name=p_name,
                            location=loc,
                            type=p_type,
                            required=bool(raw_p.get("required", False)),
                            default=raw_p.get("default"),
                            description=raw_p.get("description", ""),
                        )
                    )
                    if loc == ParameterLocation.QUERY:
                        query_param_names.append(p_name)

                # Extract requestBody parameters (OpenAPI 3)
                req_body = op_item.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    json_media = content.get("application/json", {})
                    body_schema = json_media.get("schema", {})
                    if isinstance(body_schema, dict) and "properties" in body_schema:
                        props = body_schema.get("properties", {})
                        req_fields = set(body_schema.get("required", []))
                        for prop_name, prop_def in props.items():
                            if isinstance(prop_def, dict):
                                parameters.append(
                                    EndpointParameter(
                                        name=prop_name,
                                        location=ParameterLocation.BODY,
                                        type=prop_def.get("type", "string"),
                                        required=prop_name in req_fields,
                                        description=prop_def.get("description", ""),
                                    )
                                )

                endpoint = Endpoint(
                    id="ep_tmp",
                    method=method,
                    scheme=scheme,
                    host=host,
                    port=port,
                    path=full_path,
                    raw_path=full_path,
                    parameters=parameters,
                    query_parameters=sorted(set(query_param_names)),
                    source="openapi",
                    authentication_required=auth_required,
                )
                endpoints.append(endpoint)

        return endpoints
