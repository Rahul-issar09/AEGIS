"""AEGIS Agent 1 — Endpoint normalization and deduplication.

Implements path parameter normalization and deduplication across multiple
discovery sources per PRD Section 12, 16, and 46.
"""

from __future__ import annotations

import re
from typing import Sequence

from agent1.discovery.models import (
    Endpoint,
    EndpointParameter,
    ParameterLocation,
)

# Regex patterns for dynamic URL segments
_INTEGER_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_PREFIXED_ID_RE = re.compile(r"^[a-zA-Z]{2,6}_[0-9a-zA-Z]+$")
_COLON_PARAM_RE = re.compile(r"^:([a-zA-Z0-9_]+)$")
_BRACKET_PARAM_RE = re.compile(r"^\{([a-zA-Z0-9_]+)\}$")

# Known static segments that should never be treated as variables
_STATIC_SEGMENTS = {
    "api",
    "v1",
    "v2",
    "v3",
    "v4",
    "v5",
    "auth",
    "login",
    "logout",
    "signup",
    "register",
    "admin",
    "user",
    "users",
    "profile",
    "me",
    "settings",
    "config",
    "health",
    "metrics",
    "ping",
    "status",
    "docs",
    "static",
    "assets",
    "css",
    "js",
    "images",
    "search",
    "upload",
    "download",
    "export",
    "import",
}


class EndpointNormalizer:
    """Normalizes URL paths and deduplicates endpoints discovered from multiple sources."""

    @classmethod
    def normalize_path(
        cls, raw_path: str
    ) -> tuple[str, list[EndpointParameter]]:
        """Normalize concrete dynamic segments in a URL path into parameter templates.

        Examples:
            /api/users/123 -> /api/users/{id}, [EndpointParameter(name="id", location=PATH)]
            /api/users/:userId -> /api/users/{userId}, [EndpointParameter(name="userId", location=PATH)]
            /api/items/550e8400-e29b-41d4-a716-446655440000 -> /api/items/{id}, [EndpointParameter]

        Args:
            raw_path: The raw observed URL path.

        Returns:
            Tuple of (normalized_path, list of detected path parameters).
        """
        if not raw_path:
            return "/", []

        # Ensure single leading slash
        clean_path = "/" + raw_path.lstrip("/")
        segments = clean_path.split("/")

        normalized_segments: list[str] = []
        path_params: list[EndpointParameter] = []
        param_counts: dict[str, int] = {}

        for i, segment in enumerate(segments):
            if i == 0 and segment == "":
                normalized_segments.append("")
                continue

            # Check if segment is already an explicit parameter {param}
            bracket_match = _BRACKET_PARAM_RE.match(segment)
            if bracket_match:
                param_name = bracket_match.group(1)
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(
                    EndpointParameter(
                        name=param_name,
                        location=ParameterLocation.PATH,
                        type="string",
                        required=True,
                    )
                )
                continue

            # Check for Express-style :param
            colon_match = _COLON_PARAM_RE.match(segment)
            if colon_match:
                param_name = colon_match.group(1)
                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(
                    EndpointParameter(
                        name=param_name,
                        location=ParameterLocation.PATH,
                        type="string",
                        required=True,
                    )
                )
                continue

            # Check if segment is dynamic (integer, uuid, hash, prefixed ID)
            is_dynamic = False
            param_type = "string"

            if segment.lower() not in _STATIC_SEGMENTS:
                if _INTEGER_RE.match(segment):
                    is_dynamic = True
                    param_type = "integer"
                elif _UUID_RE.match(segment):
                    is_dynamic = True
                    param_type = "identifier"
                elif _HASH_RE.match(segment):
                    is_dynamic = True
                    param_type = "identifier"
                elif _PREFIXED_ID_RE.match(segment):
                    is_dynamic = True
                    param_type = "identifier"

            if is_dynamic:
                # Derive a meaningful parameter name from preceding segment if possible
                prev_segment = segments[i - 1] if i > 0 else ""
                base_name = "id"
                if prev_segment and prev_segment not in ("api", "v1", "v2", "v3", ""):
                    # e.g., 'users' -> 'id' or 'user_id'
                    # Standard PRD Section 16 uses 'id' for single object paths
                    base_name = "id"

                # Disambiguate multiple path parameters
                if base_name in param_counts:
                    param_counts[base_name] += 1
                    param_name = f"{base_name}_{param_counts[base_name]}"
                else:
                    param_counts[base_name] = 1
                    param_name = base_name

                normalized_segments.append(f"{{{param_name}}}")
                path_params.append(
                    EndpointParameter(
                        name=param_name,
                        location=ParameterLocation.PATH,
                        type=param_type,
                        required=True,
                        description=f"Path parameter identified from '{segment}'",
                    )
                )
            else:
                normalized_segments.append(segment)

        normalized_path = "/".join(normalized_segments)
        # Collapse multiple slashes
        normalized_path = re.sub(r"/+", "/", normalized_path)
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path

        return normalized_path, path_params

    @classmethod
    def normalize_endpoint(cls, endpoint: Endpoint) -> Endpoint:
        """Normalize an endpoint's path and parameters."""
        raw_path = endpoint.raw_path or endpoint.path
        normalized_path, detected_params = cls.normalize_path(raw_path)

        # Merge detected path parameters with existing parameters
        existing_params = list(endpoint.parameters)
        existing_names = {p.name for p in existing_params}

        for dp in detected_params:
            if dp.name not in existing_names:
                existing_params.append(dp)
                existing_names.add(dp.name)

        return endpoint.model_copy(
            update={
                "path": normalized_path,
                "raw_path": raw_path,
                "parameters": existing_params,
            }
        )

    @classmethod
    def deduplicate(
        cls,
        endpoints: Sequence[Endpoint],
        id_prefix: str = "ep",
    ) -> list[Endpoint]:
        """Deduplicate a collection of endpoints and re-index them cleanly.

        Merges endpoints with matching signature (METHOD:HOST:PORT:PATH).
        Combines parameters, headers, sources, and authentication flags.

        Args:
            endpoints: Raw list of discovered endpoints.
            id_prefix: Prefix for generated endpoint IDs (default 'ep').

        Returns:
            Deduplicated, sorted list of Endpoint objects with IDs like 'ep_001'.
        """
        merged_map: dict[str, Endpoint] = {}

        for ep in endpoints:
            # First normalize the path
            normalized_ep = cls.normalize_endpoint(ep)
            sig = normalized_ep.signature

            if sig not in merged_map:
                merged_map[sig] = normalized_ep
            else:
                existing = merged_map[sig]
                merged_map[sig] = cls._merge_endpoints(existing, normalized_ep)

        # Sort deterministically: by path, then by method
        sorted_endpoints = sorted(
            merged_map.values(),
            key=lambda e: (e.path, e.method, e.host, e.port),
        )

        # Assign sequential IDs (ep_001, ep_002, ...)
        reindexed: list[Endpoint] = []
        for i, ep in enumerate(sorted_endpoints, start=1):
            reindexed.append(
                ep.model_copy(update={"id": f"{id_prefix}_{i:03d}"})
            )

        return reindexed

    @classmethod
    def _merge_endpoints(cls, primary: Endpoint, incoming: Endpoint) -> Endpoint:
        """Merge metadata from two duplicate endpoints."""
        # Merge sources
        sources = set()
        for src in primary.source.split(","):
            if src.strip():
                sources.add(src.strip())
        for src in incoming.source.split(","):
            if src.strip():
                sources.add(src.strip())
        merged_source = ",".join(sorted(sources))

        # Merge parameters
        param_dict: dict[str, EndpointParameter] = {
            p.name: p for p in primary.parameters
        }
        for p in incoming.parameters:
            if p.name not in param_dict:
                param_dict[p.name] = p
            else:
                # Prefer more specific metadata (e.g. from OpenAPI over crawler)
                curr = param_dict[p.name]
                if incoming.source == "openapi" and primary.source != "openapi":
                    param_dict[p.name] = p
                elif not curr.description and p.description:
                    param_dict[p.name] = curr.model_copy(
                        update={"description": p.description}
                    )

        # Merge query parameter names
        merged_query_params = sorted(
            set(primary.query_parameters) | set(incoming.query_parameters)
        )

        # Merge headers
        merged_headers = dict(primary.headers)
        merged_headers.update(incoming.headers)

        # Authentication required: if either specifies True, True wins
        auth_req = primary.authentication_required
        if incoming.authentication_required is not None:
            if auth_req is None:
                auth_req = incoming.authentication_required
            else:
                auth_req = auth_req or incoming.authentication_required

        # Prefer OpenAPI for raw_path if existing had none
        raw_path = primary.raw_path or incoming.raw_path

        return primary.model_copy(
            update={
                "source": merged_source,
                "parameters": list(param_dict.values()),
                "query_parameters": merged_query_params,
                "headers": merged_headers,
                "authentication_required": auth_req,
                "raw_path": raw_path,
            }
        )
