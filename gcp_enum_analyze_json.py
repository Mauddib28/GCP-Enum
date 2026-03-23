#!/usr/bin/env python3
"""
Optional JSON helpers for gcp_enum (supplemental to shell checks).
Reads JSON from stdin; emits CONFIG_FINDING lines to stdout.

Modes:
  sql-instance / gke-cluster — for manual piping of describe JSON (shell checks are primary).
  project-iam — conditional IAM bindings only (set GCP_ENUM_PROJECT for context).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


def _emit(severity: str, rule: str, **fields: str) -> None:
    parts = [f"CONFIG_FINDING source=python severity={severity} rule={rule}"]
    for k, v in fields.items():
        safe = v.replace("\n", " ").strip()[:500]
        parts.append(f"{k}={safe}")
    print(" ".join(parts))


def analyze_sql_instance(data: dict[str, Any]) -> None:
    name = str(data.get("name", ""))
    settings = data.get("settings") or {}
    ip_cfg = settings.get("ipConfiguration") or {}
    require_ssl = ip_cfg.get("requireSsl")
    if require_ssl is False:
        _emit("MEDIUM", "sql_require_ssl_disabled", instance=name)
    authed = ip_cfg.get("authorizedNetworks") or []
    for net in authed:
        cidr = (net or {}).get("value", "")
        if cidr == "0.0.0.0/0":
            _emit("HIGH", "sql_authorized_network_open", instance=name, cidr=cidr)


def analyze_gke_cluster(data: dict[str, Any]) -> None:
    name = str(data.get("name", ""))
    zone = str(data.get("zone", ""))
    labac = data.get("legacyAbac") or {}
    if labac.get("enabled") is True:
        _emit("MEDIUM", "gke_legacy_abac_enabled", cluster=name, zone=zone)
    man = data.get("masterAuthorizedNetworksConfig") or {}
    if not man or man.get("enabled") is False:
        _emit("LOW", "gke_master_authorized_networks_disabled", cluster=name, zone=zone)
        return
    cidrs = man.get("cidrBlocks") or []
    for block in cidrs:
        cidr = (block or {}).get("cidrBlock", "")
        if cidr == "0.0.0.0/0":
            _emit("HIGH", "gke_master_authorized_network_open", cluster=name, zone=zone, cidr=cidr)


def analyze_project_iam(data: dict[str, Any]) -> None:
    """Bindings that include IAM conditions (shell CSV flatten omits condition detail)."""
    proj = os.environ.get("GCP_ENUM_PROJECT", "")
    for binding in data.get("bindings") or []:
        cond = binding.get("condition")
        if not cond:
            continue
        role = str(binding.get("role", ""))
        expr = str(cond.get("expression", ""))[:400]
        title = str(cond.get("title", ""))[:200]
        for member in binding.get("members") or []:
            _emit(
                "LOW",
                "iam_conditional_binding",
                project=proj,
                role=role,
                member=str(member),
                expression=expr,
                title=title,
            )


def main() -> int:
    p = argparse.ArgumentParser(description="GCP enum supplemental JSON analysis")
    p.add_argument(
        "mode",
        choices=("sql-instance", "gke-cluster", "project-iam"),
        help="Document type on stdin",
    )
    args = p.parse_args()
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"gcp_enum_analyze_json: invalid JSON: {e}", file=sys.stderr)
        return 1
    if args.mode == "sql-instance":
        analyze_sql_instance(data)
    elif args.mode == "gke-cluster":
        analyze_gke_cluster(data)
    else:
        analyze_project_iam(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
