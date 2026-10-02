"""Tests for POST /plans/continue: safe replanning after mid-run revocation."""
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
client = TestClient(app)


def cert(cid, subject, issuer):
    return {
        "cert_id": cid,
        "subject": subject,
        "issuer": issuer,
        "not_valid_before": (NOW - timedelta(days=3650)).isoformat(),
        "not_valid_after": (NOW + timedelta(days=365)).isoformat(),
    }


def scenario(certs_=None, actions=None, endpoints=None,
             clients=("billing",), trust=("root-old",)):
    if certs_ is None:
        certs_ = [
            cert("root-old", "CN=Old Root", "CN=Old Root"),
            cert("root-new", "CN=New Root", "CN=New Root"),
            cert("leaf-old", "CN=api", "CN=Old Root"),
            cert("leaf-new", "CN=api", "CN=New Root"),
        ]
    if endpoints is None:
        endpoints = [{
            "endpoint_id": "api",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-new", "root-new"],
        }]
    if actions is None:
        actions = [
            {"action_id": "a1-add", "type": "add_trust",
             "client_id": "billing", "anchor_cert_id": "root-new",
             "allowed_stages": [1, 2, 3]},
            {"action_id": "a2-rep", "type": "replace_cert",
             "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"],
             "allowed_stages": [2, 3]},
            {"action_id": "a3-rm", "type": "remove_trust",
             "client_id": "billing", "anchor_cert_id": "root-old",
             "allowed_stages": [1, 2, 3]},
        ]
    return {
        "certificates": certs_,
        "trust_anchors": [
            {"client_id": cl, "cert_id": r} for cl in clients for r in trust
        ],
        "endpoints": endpoints,
        "relationships": [
            {"client_id": cl, "endpoint_id": e["endpoint_id"]}
            for cl in clients for e in endpoints
        ],
        "actions": actions,
        "plan_time": NOW.isoformat(),
    }


REVOKED_OLD = [
    {"cert_id": "leaf-old", "kind": "ocsp", "fresh": True, "status": "revoked"}
]
FIELD_OLD = [{"endpoint_id": "api", "chain": ["leaf-old", "root-old"]}]


def cont(extra):
    return client.post("/plans/continue", json={**scenario(), **extra})


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_prefix_add_completes_replace_and_remove():
    r = cont({
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "revocation_evidence": REVOKED_OLD,
    })
    assert r.status_code == 200, r.text
    b = r.json()
    # a2 is only allowed from stage 2, so stage 1 is an explicit no-op and
    # the replace+remove pair lands in stage 2.
    assert b["stage_count"] == 2
    assert b["stages"][0] == {"stage": 1, "action_ids": [],
                              "chain_deployments": []}
    assert b["stages"][1]["action_ids"] == ["a2-rep", "a3-rm"]
    assert b["stages"][1]["chain_deployments"] == [
        {"endpoint_id": "api", "chain": ["leaf-new", "root-new"]}
    ]
    assert b["completed_action_ids"] == ["a1-add"]
    assert b["selected_chains"] == [
        {"endpoint_id": "api", "chain": ["leaf-new", "root-new"]}
    ]
    eliminated = b["eliminated_chains"]
    assert len(eliminated) == 1
    assert eliminated[0]["role"] == "current"
    assert eliminated[0]["blocking_certificate"] == "leaf-old"
    assert eliminated[0]["reason"] == "certificate_revoked"


def test_single_stage_when_remainder_allows_it():
    r = client.post("/plans/continue", json={
        **scenario(actions=[
            {"action_id": "a1-add", "type": "add_trust", "client_id": "billing",
             "anchor_cert_id": "root-new", "allowed_stages": [1, 2, 3]},
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"], "allowed_stages": [1, 2, 3]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [1, 2, 3]},
        ]),
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "revocation_evidence": REVOKED_OLD,
    })
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["stage_count"] == 1
    assert b["stages"][0]["action_ids"] == ["a2-rep", "a3-rm"]


def test_remove_trust_cannot_precede_replacement():
    # remove only eligible at stage 1, replace only from stage 2: removing
    # the old anchor while the revoked-but-still-served old leaf depends on it
    # breaks the relationship, so no continuation exists.
    r = client.post("/plans/continue", json={
        **scenario(actions=[
            {"action_id": "a1-add", "type": "add_trust", "client_id": "billing",
             "anchor_cert_id": "root-new", "allowed_stages": [1, 2]},
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"], "allowed_stages": [2]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [1]},
        ]),
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "revocation_evidence": REVOKED_OLD,
    })
    assert r.status_code == 409
    b = r.json()
    assert b["status"] == "infeasible"
    assert b["relationship"] == {"client_id": "billing", "endpoint_id": "api"}
    assert b["blocking_action"] == "a3-rm"
    assert b["blocking_certificate"] == "root-old"
    assert b["reason"] == "untrusted_root"


def test_conflicting_good_revoked_eliminates_current_chain():
    r = client.post("/plans/continue", json={
        **scenario(actions=[
            {"action_id": "a1-add", "type": "add_trust", "client_id": "billing",
             "anchor_cert_id": "root-new", "allowed_stages": [1]},
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"], "allowed_stages": [1]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [1]},
        ]),
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "revocation_evidence": [
            {"cert_id": "leaf-old", "kind": "ocsp", "fresh": True,
             "status": "good"},
            {"cert_id": "leaf-old", "kind": "crl", "fresh": True,
             "status": "revoked"},
        ],
    })
    assert r.status_code == 200, r.text
    b = r.json()
    reasons = {(e["role"], e["reason"]) for e in b["eliminated_chains"]}
    assert ("current", "conflicting_evidence") in reasons
    assert b["stages"][0]["chain_deployments"][0]["chain"] == [
        "leaf-new", "root-new"
    ]


def test_stale_evidence_does_not_eliminate():
    r = cont({
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "revocation_evidence": [
            {"cert_id": "leaf-old", "kind": "ocsp", "fresh": False,
             "status": "revoked"}
        ],
    })
    assert r.status_code == 200, r.text
    assert r.json()["eliminated_chains"] == []


def test_revoked_intermediate_eliminates_chain():
    certs_ = [
        cert("root", "CN=Root", "CN=Root"),
        cert("inter", "CN=Inter", "CN=Root"),
        cert("inter-alt", "CN=InterAlt", "CN=Root"),
        cert("leaf", "CN=svc", "CN=Inter"),
        cert("leaf-alt", "CN=svc", "CN=InterAlt"),
    ]
    endpoints = [{
        "endpoint_id": "svc",
        "current_chain": ["leaf", "inter", "root"],
        "target_chain": ["leaf-alt", "inter-alt", "root"],
    }]
    actions = [{
        "action_id": "rep", "type": "replace_cert", "endpoint_id": "svc",
        "new_chain": ["leaf-alt", "inter-alt", "root"],
        "allowed_stages": [1],
    }]
    r = client.post("/plans/continue", json={
        **scenario(certs_=certs_, endpoints=endpoints, actions=actions,
                   clients=("cl",), trust=("root",)),
        "completed_action_ids": [],
        "field_chains": [{"endpoint_id": "svc",
                          "chain": ["leaf", "inter", "root"]}],
        "revocation_evidence": [
            {"cert_id": "inter", "kind": "crl", "fresh": True,
             "status": "revoked"}
        ],
    })
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["eliminated_chains"][0]["role"] == "current"
    assert b["eliminated_chains"][0]["blocking_certificate"] == "inter"
    assert b["selected_chains"][0]["chain"] == [
        "leaf-alt", "inter-alt", "root"
    ]


def test_revoked_trust_root_is_not_reviewed():
    # The chain-terminating anchor's status cannot be established from within
    # its own chain, mirroring /deployments/revocation-review.
    r = cont({
        "completed_action_ids": ["a1-add", "a2-rep", "a3-rm"],
        "field_chains": [{"endpoint_id": "api",
                          "chain": ["leaf-new", "root-new"]}],
        "revocation_evidence": [
            {"cert_id": "root-new", "kind": "ocsp", "fresh": True,
             "status": "revoked"}
        ],
    })
    assert r.status_code == 200, r.text
    assert r.json()["eliminated_chains"] == []


# ---------------------------------------------------------------------------
# Alternative candidate chains
# ---------------------------------------------------------------------------


def test_alternative_chain_used_when_target_is_revoked():
    extra_certs = scenario()["certificates"] + [
        cert("leaf-alt", "CN=api", "CN=New Root"),
    ]
    r = client.post("/plans/continue", json={
        **scenario(certs_=extra_certs, actions=[
            {"action_id": "a1-add", "type": "add_trust", "client_id": "billing",
             "anchor_cert_id": "root-new", "allowed_stages": [1]},
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"], "allowed_stages": [1]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [1]},
        ]),
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "alternatives": [{
            "endpoint_id": "api",
            "candidate_chains": [["leaf-alt", "root-new"]],
        }],
        "revocation_evidence": REVOKED_OLD + [
            {"cert_id": "leaf-new", "kind": "crl", "fresh": True,
             "status": "revoked"}
        ],
    })
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["selected_chains"] == [
        {"endpoint_id": "api", "chain": ["leaf-alt", "root-new"]}
    ]
    roles = {(e["role"], e["blocking_certificate"])
             for e in b["eliminated_chains"]}
    assert ("current", "leaf-old") in roles
    assert ("target", "leaf-new") in roles


def test_chain_tie_break_is_full_fingerprint_lexicographic():
    extra_certs = scenario()["certificates"] + [
        cert("leaf-aaa", "CN=api", "CN=New Root"),
        cert("leaf-zzz", "CN=api", "CN=New Root"),
    ]
    endpoints = [{
        "endpoint_id": "api",
        "current_chain": ["leaf-old", "root-old"],
        "target_chain": ["leaf-zzz", "root-new"],
    }]
    r = client.post("/plans/continue", json={
        **scenario(certs_=extra_certs, endpoints=endpoints, actions=[
            {"action_id": "a1-add", "type": "add_trust", "client_id": "billing",
             "anchor_cert_id": "root-new", "allowed_stages": [1]},
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-zzz", "root-new"], "allowed_stages": [1]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [1]},
        ]),
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "alternatives": [{
            "endpoint_id": "api",
            "candidate_chains": [
                ["leaf-zzz", "root-new"],
                ["leaf-aaa", "root-new"],
            ],
        }],
        "revocation_evidence": REVOKED_OLD,
    })
    assert r.status_code == 200, r.text
    # Both chains are valid and the target itself is leaf-zzz; the smallest
    # complete chain fingerprint wins regardless of input order.
    assert r.json()["selected_chains"][0]["chain"] == [
        "leaf-aaa", "root-new"
    ]


def test_untrusted_alternative_is_never_selected():
    extra_certs = scenario()["certificates"] + [
        cert("root-mid", "CN=Mid Root", "CN=Mid Root"),
        cert("leaf-mid", "CN=api", "CN=Mid Root"),
    ]
    # The new root is never added (a1 absent); only alternative is rooted at
    # an untrusted root, and the original target is revoked.
    r = client.post("/plans/continue", json={
        **scenario(certs_=extra_certs, actions=[
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"], "allowed_stages": [1]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [2]},
        ]),
        "completed_action_ids": [],
        "field_chains": FIELD_OLD,
        "alternatives": [{
            "endpoint_id": "api",
            "candidate_chains": [["leaf-mid", "root-mid"]],
        }],
        "revocation_evidence": REVOKED_OLD + [
            {"cert_id": "leaf-new", "kind": "crl", "fresh": True,
             "status": "revoked"}
        ],
    })
    assert r.status_code == 409
    assert r.json()["reason"] == "untrusted_root"


def test_no_clean_destination_reports_blocking_certificate():
    r = client.post("/plans/continue", json={
        **scenario(actions=[
            {"action_id": "a1-add", "type": "add_trust", "client_id": "billing",
             "anchor_cert_id": "root-new", "allowed_stages": [1]},
            {"action_id": "a2-rep", "type": "replace_cert", "endpoint_id": "api",
             "new_chain": ["leaf-new", "root-new"], "allowed_stages": [1]},
            {"action_id": "a3-rm", "type": "remove_trust", "client_id": "billing",
             "anchor_cert_id": "root-old", "allowed_stages": [1]},
        ]),
        "completed_action_ids": ["a1-add"],
        "field_chains": FIELD_OLD,
        "revocation_evidence": REVOKED_OLD + [
            {"cert_id": "leaf-new", "kind": "ocsp", "fresh": True,
             "status": "revoked"}
        ],
    })
    assert r.status_code == 409
    b = r.json()
    assert b["reason"] == "no_clean_destination"
    assert b["relationship"] == {"client_id": "billing", "endpoint_id": "api"}
    assert b["blocking_certificate"] == "leaf-new"


def test_dirty_chain_with_no_replace_left_is_infeasible():
    # The replace already ran (immutable prefix) and the field still serves a
    # revoked chain: nothing left can retire it.
    r = cont({
        "completed_action_ids": ["a2-rep"],
        "field_chains": [{"endpoint_id": "api",
                          "chain": ["leaf-old", "root-old"]}],
        "revocation_evidence": REVOKED_OLD,
    })
    assert r.status_code == 409
    b = r.json()
    assert b["reason"] == "certificate_revoked"
    assert b["blocking_certificate"] == "leaf-old"
    assert b["blocking_action"] is None


# ---------------------------------------------------------------------------
# Prefix / resume-state semantics
# ---------------------------------------------------------------------------


def test_prefix_that_already_broke_relationship_is_invalid():
    # Both add and remove of the same distinct anchors executed; with the old
    # leaf still served and the old anchor removed, trust is already gone.
    r = cont({
        "completed_action_ids": ["a1-add", "a3-rm"],
        "field_chains": FIELD_OLD,
    })
    assert r.status_code == 409
    b = r.json()
    assert b["status"] == "invalid"
    assert b["stage"] == 0
    assert b["blocking_certificate"] == "root-old"
    assert b["blocking_action"] is None


def test_completed_replace_served_chain_is_field_truth():
    # Prefix executed the replace, but the field observation is authoritative:
    # the endpoint still serves the new clean chain.
    r = cont({
        "completed_action_ids": ["a1-add", "a2-rep"],
        "field_chains": [{"endpoint_id": "api",
                          "chain": ["leaf-new", "root-new"]}],
    })
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["stages"][-1]["action_ids"] == ["a3-rm"]


def test_all_actions_completed_returns_empty_continuation():
    r = cont({
        "completed_action_ids": ["a1-add", "a2-rep", "a3-rm"],
        "field_chains": [{"endpoint_id": "api",
                          "chain": ["leaf-new", "root-new"]}],
    })
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["stage_count"] == 0
    assert b["stages"] == []
    assert b["selected_chains"] == []


# ---------------------------------------------------------------------------
# Request validation (422)
# ---------------------------------------------------------------------------


def test_unknown_completed_action():
    r = cont({"completed_action_ids": ["nope"]})
    assert r.status_code == 422


def test_duplicate_completed_action():
    r = cont({"completed_action_ids": ["a1-add", "a1-add"]})
    assert r.status_code == 422


def test_unknown_field_endpoint():
    r = cont({"field_chains": [{"endpoint_id": "ghost", "chain": ["x"]}]})
    assert r.status_code == 422


def test_unknown_cert_in_candidate_chain():
    r = cont({
        "alternatives": [{
            "endpoint_id": "api",
            "candidate_chains": [["leaf-ghost", "root-new"]],
        }]
    })
    assert r.status_code == 422


def test_candidate_chain_must_end_at_self_signed_root():
    r = cont({
        "alternatives": [{
            "endpoint_id": "api",
            "candidate_chains": [["leaf-new", "leaf-old", "root-old"]],
        }]
    })
    assert r.status_code == 422


def test_unknown_evidence_cert():
    r = cont({
        "revocation_evidence": [
            {"cert_id": "ghost", "kind": "ocsp", "fresh": True,
             "status": "revoked"}
        ]
    })
    assert r.status_code == 422


def test_more_than_twelve_alternatives_rejected():
    chains = [["leaf-new", "root-new"]] * 13
    r = cont({
        "alternatives": [{"endpoint_id": "api", "candidate_chains": chains}]
    })
    assert r.status_code == 422
