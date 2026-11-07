"""Native Windows smoke: force the primary collector off, then read CIM/ARP locally.

No collector source is executed by this module through eval/exec. The normal
discovery transport executes its fixed, bounded, read-only PowerShell/ARP
commands. Output deliberately omits addresses, MACs, hostnames and raw errors.
"""
from __future__ import annotations

import json
from pathlib import Path
import platform
import sys
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class ValidationError(RuntimeError):
    """Only fixed validation codes may be exposed by this helper."""


def require(condition, code):
    if not condition:
        raise ValidationError(code)


def main():
    try:
        require(platform.system() == "Windows", "WINDOWS_RUNNER_REQUIRED")
        from labguard import discovery

        original = discovery._json_command
        counts = {"primary_forced": 0, "cim_queries": 0}

        def primary_unavailable(command, warnings, label):
            if command and command[-1] == discovery.WINDOWS_SCRIPT:
                counts["primary_forced"] += 1
                return None
            if command and command[-1] == discovery.CIM_SCRIPT:
                counts["cim_queries"] += 1
            return original(command, warnings, label)

        transport = discovery.LocalObservationTransport()
        try:
            with patch.object(discovery, "_json_command", side_effect=primary_unavailable):
                snapshot = transport.request("snapshot")
        finally:
            transport.close()

        require(counts["primary_forced"] == 1, "PRIMARY_FAILURE_NOT_FORCED")
        require(counts["cim_queries"] == 1, "CIM_QUERY_NOT_EXECUTED")
        require(snapshot.get("mode") == "observation", "INVALID_OBSERVATION_MODE")
        metadata = snapshot.get("discovery")
        require(isinstance(metadata, dict), "DISCOVERY_METADATA_MISSING")
        sources = metadata.get("sources")
        whitelist = {"windows-nettcpip", "windows-cim", "windows-arp"}
        require(isinstance(sources, list) and all(isinstance(item, str) and item in whitelist for item in sources), "UNEXPECTED_DISCOVERY_SOURCE")
        require("windows-cim" in sources and metadata.get("interfaces_read") is True, "CIM_CONFIGURATION_UNAVAILABLE")
        require(metadata.get("read_success") is True, "NO_SUCCESSFUL_LOCAL_READ")
        capabilities = snapshot.get("capabilities")
        require(isinstance(capabilities, dict) and capabilities.get("inventory") is True, "INVENTORY_CAPABILITY_MISSING")
        require(all(value is False for key, value in capabilities.items() if key != "inventory"), "MUTATION_CAPABILITY_EXPOSED")
        require(all(isinstance(snapshot.get(key), list) for key in ("interfaces", "devices", "events", "connections")), "INVALID_COLLECTION_SHAPE")
        require(not snapshot["events"] and not snapshot["connections"], "TRAFFIC_HISTORY_MUST_STAY_EMPTY")

        print(json.dumps({
            "ok": True,
            "mode_observation": True,
            "interface_count": len(snapshot["interfaces"]),
            "device_count": len(snapshot["devices"]),
            "interfaces_read": metadata["interfaces_read"],
            "routes_read": metadata.get("routes_read") is True,
            "neighbors_read": metadata.get("neighbors_read") is True,
            "cim_used": True,
            "arp_used": "windows-arp" in sources,
            "mutation_capabilities_disabled": True,
            "forced_primary_count": counts["primary_forced"],
            "cim_query_count": counts["cim_queries"],
        }, sort_keys=True))
        return 0
    except ValidationError as error:
        print("FAIL: native discovery validation: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: native discovery validation did not complete.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
