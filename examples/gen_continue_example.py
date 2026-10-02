#!/usr/bin/env python3
"""Regenerate examples/continue_request.json.

Scenario: the classic root rotation from examples/plan_request.json is one
action in -- ``a1-add-new-root`` has executed (billing-service now trusts both
roots) -- when a fresh stapled OCSP response shows the currently served leaf
``leaf-old`` to be revoked. The endpoint still serves the old chain in the
field, and one clean alternative chain (``leaf-alt`` under the new root) is
available alongside the original target chain.

The endpoint must move off the revoked old leaf before the old root's trust
anchor is removed; the remaining replace_cert is only eligible from stage 2,
so the safe continuation is an explicit no-op stage 1 followed by
replace + remove together at stage 2.

The example request can be POSTed as-is:

    curl -s http://localhost:8080/plans/continue \
      -H 'Content-Type: application/json' \
      --data @examples/continue_request.json
"""
import json
import pathlib

REQUEST = {
    "certificates": [
        {
            "cert_id": "root-old",
            "subject": "CN=Old Root CA",
            "issuer": "CN=Old Root CA",
            "not_valid_before": "2020-01-01T00:00:00Z",
            "not_valid_after": "2030-01-01T00:00:00Z",
        },
        {
            "cert_id": "root-new",
            "subject": "CN=New Root CA",
            "issuer": "CN=New Root CA",
            "not_valid_before": "2024-01-01T00:00:00Z",
            "not_valid_after": "2035-01-01T00:00:00Z",
        },
        {
            "cert_id": "leaf-old",
            "subject": "CN=api.example.com",
            "issuer": "CN=Old Root CA",
            "not_valid_before": "2025-01-01T00:00:00Z",
            "not_valid_after": "2026-12-31T00:00:00Z",
        },
        {
            "cert_id": "leaf-new",
            "subject": "CN=api.example.com",
            "issuer": "CN=New Root CA",
            "not_valid_before": "2026-01-01T00:00:00Z",
            "not_valid_after": "2027-12-31T00:00:00Z",
        },
        {
            "cert_id": "leaf-alt",
            "subject": "CN=api.example.com",
            "issuer": "CN=New Root CA",
            "not_valid_before": "2026-06-01T00:00:00Z",
            "not_valid_after": "2028-12-31T00:00:00Z",
        },
    ],
    "trust_anchors": [
        {"client_id": "billing-service", "cert_id": "root-old"}
    ],
    "endpoints": [
        {
            "endpoint_id": "api.example.com",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-new", "root-new"],
        }
    ],
    "relationships": [
        {"client_id": "billing-service", "endpoint_id": "api.example.com"}
    ],
    "actions": [
        {
            "action_id": "a1-add-new-root",
            "type": "add_trust",
            "client_id": "billing-service",
            "anchor_cert_id": "root-new",
            "allowed_stages": [1, 2, 3],
        },
        {
            "action_id": "a2-serve-new-leaf",
            "type": "replace_cert",
            "endpoint_id": "api.example.com",
            "new_chain": ["leaf-new", "root-new"],
            "allowed_stages": [2, 3],
        },
        {
            "action_id": "a3-remove-old-root",
            "type": "remove_trust",
            "client_id": "billing-service",
            "anchor_cert_id": "root-old",
            "allowed_stages": [1, 2, 3],
        },
    ],
    "plan_time": "2026-10-01T00:00:00Z",
    "completed_action_ids": ["a1-add-new-root"],
    "field_chains": [
        {"endpoint_id": "api.example.com", "chain": ["leaf-old", "root-old"]}
    ],
    "alternatives": [
        {
            "endpoint_id": "api.example.com",
            "candidate_chains": [["leaf-alt", "root-new"]],
        }
    ],
    "revocation_evidence": [
        {"cert_id": "leaf-old", "kind": "ocsp", "fresh": True,
         "status": "revoked"}
    ],
}


def main() -> None:
    out = pathlib.Path(__file__).with_name("continue_request.json")
    out.write_text(json.dumps(REQUEST, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
