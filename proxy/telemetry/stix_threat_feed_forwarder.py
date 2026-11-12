"""
STIX/TAXII 2.1 Threat Feed Forwarder
====================================
Formats blocked adversarial payloads into STIX 2.1 Cyber Threat Intelligence (CTI)
observable bundles for enterprise SIEM/SOAR and TAXII 2.1 distribution.
"""

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class STIXBundleResult:
    bundle_id: str
    indicator_count: int
    raw_bundle: Dict[str, Any]


class STIXThreatFeedForwarder:
    """Serializes AI firewall threat incidents into STIX 2.1 bundles."""

    def __init__(self, identity_name: str = "Agentic-AI-Firewall-v42"):
        self.identity_name = identity_name
        self.identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, identity_name)}"

    def create_threat_bundle(self, incidents: List[Dict[str, Any]]) -> STIXBundleResult:
        bundle_uuid = str(uuid.uuid4())
        objects = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": self.identity_id,
                "name": self.identity_name,
                "identity_class": "system"
            }
        ]

        for inc in incidents:
            indicator_id = f"indicator--{uuid.uuid4()}"
            attack_type = inc.get("violation_code", "GENERIC_AI_EXPLOIT")
            pattern = f"[ai-firewall:pattern = '{inc.get('details', '')}']"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "name": f"AI Security Threat - {attack_type}",
                "pattern": pattern,
                "pattern_type": "stix",
                "created_by_ref": self.identity_id
            })

        bundle = {
            "type": "bundle",
            "id": f"bundle--{bundle_uuid}",
            "objects": objects
        }

        return STIXBundleResult(
            bundle_id=bundle["id"],
            indicator_count=len(incidents),
            raw_bundle=bundle
        )
