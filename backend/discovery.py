"""
Week 2 (Member 2): Integration & Testing - Discovery Module
Build an OpenAPI-style inventory from observed traffic and flag endpoints
that are missing from openapi/openapi.yaml (shadow / zombie APIs).
"""

import re
import yaml
from typing import Set, List, Optional

class APIDiscovery:
    def __init__(self, spec_path: str = "../openapi/openapi.yaml"):
        self.spec_path = spec_path
        self.spec_endpoints: Set[str] = self._load_spec()
        self.observed_endpoints: Set[str] = set()

    def _load_spec(self) -> Set[str]:
        """Load and normalize existing OpenAPI specification endpoints."""
        endpoints = set()
        try:
            with open(self.spec_path, "r") as f:
                spec_data = yaml.safe_load(f)
                if spec_data and "paths" in spec_data:
                    for path in spec_data["paths"].keys():
                        endpoints.add(self.normalize_path(path))
        except Exception as e:
            print(f"Warning: Could not load OpenAPI spec from {self.spec_path}: {e}")
        return endpoints

    def normalize_path(self, path: str) -> str:
        """
        Normalise dynamic path segments into generic parameters.
        E.g., /orders/101/items/45 -> /orders/{id}/items/{id}
        """
        if not path:
            return "/"
        
        # Remove query parameters if present
        path = path.split("?")[0]
        segments = path.strip("/").split("/")
        normalized_segments = []
        
        for segment in segments:
            # Check if segment is numeric or a UUID-like hash string
            if segment.isdigit() or re.match(r"^[0-9a-fA-F-]{8,}$", segment):
                normalized_segments.append("{id}")
            else:
                normalized_segments.append(segment)
                
        return "/" + "/".join(normalized_segments)

    def record_endpoint(self, path: str) -> str:
        """Record and normalize an observed endpoint from traffic."""
        norm_path = self.normalize_path(path)
        self.observed_endpoints.add(norm_path)
        return norm_path

    def find_shadow_apis(self) -> List[str]:
        """
        Identify observed endpoints that are missing from the OpenAPI spec 
        (Shadow / Zombie APIs).
        """
        shadows = []
        for ep in self.observed_endpoints:
            if ep not in self.spec_endpoints:
                shadows.append(ep)
        return shadows