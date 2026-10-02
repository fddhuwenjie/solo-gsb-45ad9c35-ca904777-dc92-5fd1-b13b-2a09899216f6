"""Safe continuation after revocation is discovered during plan execution.

``POST /plans/continue`` answers: while the original rotation plan is already
partially executed, fresh offline evidence shows one or more certificates to
be revoked (or carries contradictory good/revoked evidence); how can the
deployment be finished safely without ever rolling the executed prefix back?

Inputs on top of the original :class:`PlanRequest`:

* ``completed_action_ids`` — the immutable executed prefix;
* ``field_chains`` — the chains actually served on the endpoints right now
  (ground truth for the resume state; endpoints not listed keep the chain the
  executed prefix implies);
* up to 12 ``candidate_chains`` per endpoint;
* fresh offline revocation evidence keyed by ``cert_id``.

Processing:

1. **Eliminate evidence-dirty chains.** Every distinct current (field), target
   and candidate chain containing a non-anchor certificate with fresh
   ``revoked`` evidence (``certificate_revoked``) or with both fresh ``good``
   and fresh ``revoked`` evidence (``conflicting_evidence``) is removed. The
   trust root terminating a chain is never reviewed. Stale/missing evidence
   does not eliminate a chain here (only *fresh* evidence participates;
   /deployments/revocation-review is the fail-closed front door).
2. **Fix the resume state.** Anchors are exactly the initial anchors modified
   by the executed add/remove actions; served chains are the field
   observations. The prefix itself is never revisited and must already leave
   every required relationship with a valid trust path.
3. **Plan the remainder.** The remaining actions keep their original
   ``allowed_stages``; each remaining ``replace_cert`` may deploy any clean
   chain among its (clean) original target and the endpoint's clean
   alternatives. A minimum-stage continuation is sought with the same
   semantics and lexicographic action tie-break as /plans (complete chain
   fingerprints are the secondary tie-break), so that every required
   relationship keeps a valid trust path after every stage — in particular a
   ``remove_trust`` can never precede the replacement that retires the last
   chain anchored at it, and a revoked chain may never be selected as a
   destination.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Optional

from .engine import (
    INF,
    PathFailure,
    Scenario,
    ScenarioValidationError,
    TrustEdge,
    TrustState,
    batch_conflict,
    build_scenario,
    evaluate_path,
)
from .models import (
    ChainCert,
    ContinueChainDeployment,
    ContinueFailure,
    ContinueRequest,
    ContinueStage,
    ContinueSuccess,
    EliminatedChain,
    RelationshipRef,
)


# ---------------------------------------------------------------------------
# Request validation beyond the shared PlanRequest machinery
# ---------------------------------------------------------------------------


def _validate_named_chain(sc: Scenario, chain: list[str], where: str) -> None:
    """Same structural checks a target/new chain receives at build time."""
    if len(set(chain)) != len(chain):
        raise ScenarioValidationError(
            f"{where}: certificate chain must not contain a certificate more "
            f"than once (chains with cycles are rejected)"
        )
    for cid in chain:
        if cid not in sc.certs:
            raise ScenarioValidationError(f"{where}: unknown certificate '{cid}'")
    last = sc.certs[chain[-1]]
    if last.issuer != last.subject:
        raise ScenarioValidationError(
            f"{where}: chain must end at a self-signed root, but "
            f"'{chain[-1]}' is not self-signed (subject='{last.subject}', "
            f"issuer='{last.issuer}')"
        )
    for idx, cid in enumerate(chain[:-1]):
        nxt = sc.certs[chain[idx + 1]]
        if sc.certs[cid].issuer != nxt.subject:
            raise ScenarioValidationError(
                f"{where}: issuer mismatch at '{cid}' -> '{chain[idx + 1]}' "
                f"(issuer '{sc.certs[cid].issuer}' != subject '{nxt.subject}')"
            )


def _validate_inputs(
    sc: Scenario,
    req: ContinueRequest,
    field_chains: dict[str, list[str]],
) -> None:
    seen: set[str] = set()
    for aid in req.completed_action_ids:
        if aid not in set(sc.action_ids):
            raise ScenarioValidationError(
                f"completed_action_ids: unknown action_id '{aid}'"
            )
        if aid in seen:
            raise ScenarioValidationError(
                f"completed_action_ids: action '{aid}' appears more than once"
            )
        seen.add(aid)

    seen_eps: set[str] = set()
    for fc in req.field_chains:
        if fc.endpoint_id in seen_eps:
            raise ScenarioValidationError(
                f"field_chains: endpoint_id '{fc.endpoint_id}' appears more "
                f"than once"
            )
        seen_eps.add(fc.endpoint_id)
        if fc.endpoint_id not in sc.endpoint_chains:
            raise ScenarioValidationError(
                f"field_chains: unknown endpoint_id '{fc.endpoint_id}'"
            )
        _validate_named_chain(
            sc, fc.chain, f"field_chains['{fc.endpoint_id}'].chain"
        )
        field_chains[fc.endpoint_id] = list(fc.chain)

    seen_alt: set[str] = set()
    for alt in req.alternatives:
        if alt.endpoint_id in seen_alt:
            raise ScenarioValidationError(
                f"alternatives: endpoint_id '{alt.endpoint_id}' appears more "
                f"than once"
            )
        seen_alt.add(alt.endpoint_id)
        if alt.endpoint_id not in sc.endpoint_chains:
            raise ScenarioValidationError(
                f"alternatives: unknown endpoint_id '{alt.endpoint_id}'"
            )
        for j, chain in enumerate(alt.candidate_chains):
            _validate_named_chain(
                sc,
                chain,
                f"alternatives['{alt.endpoint_id}'].candidate_chains[{j}]",
            )

    for ev in req.revocation_evidence:
        if ev.cert_id not in sc.certs:
            raise ScenarioValidationError(
                f"revocation_evidence: unknown certificate '{ev.cert_id}'"
            )


# ---------------------------------------------------------------------------
# Evidence aggregation and chain elimination
# ---------------------------------------------------------------------------


def _cert_verdicts(req: ContinueRequest) -> dict[str, str]:
    """Aggregate fresh evidence per cert_id.

    fresh revoked only -> certificate_revoked; both fresh good and fresh
    revoked -> conflicting_evidence; fresh good only -> ok. Stale items are
    ignored entirely (they prove nothing at the review instant)."""
    statuses: dict[str, set[str]] = {}
    for ev in req.revocation_evidence:
        if not ev.fresh:
            continue
        statuses.setdefault(ev.cert_id, set()).add(ev.status)
    verdicts: dict[str, str] = {}
    for cid, sts in statuses.items():
        if "revoked" in sts and "good" in sts:
            verdicts[cid] = "conflicting_evidence"
        elif "revoked" in sts:
            verdicts[cid] = "certificate_revoked"
        else:
            verdicts[cid] = "ok"
    return verdicts


def _chain_verdict(
    chain: list[str], verdicts: dict[str, str]
) -> Optional[tuple[str, str]]:
    """First (leaf-first) non-anchor cert with eliminating evidence.

    The terminal trust root is not reviewed: its revocation status cannot be
    established from within its own chain."""
    for cid in chain[:-1]:
        v = verdicts.get(cid)
        if v in ("certificate_revoked", "conflicting_evidence"):
            return v, cid
    return None


# ---------------------------------------------------------------------------
# Resume state
# ---------------------------------------------------------------------------


def _resume_anchors(sc: Scenario, prefix_mask: int) -> frozenset[TrustEdge]:
    anchors = set(sc.initial_anchors)
    for i, edge in sc.add_edges.items():
        if prefix_mask >> i & 1:
            anchors.add(edge)
    for i, edge in sc.remove_edges.items():
        if prefix_mask >> i & 1:
            anchors.discard(edge)
    return frozenset(anchors)


def _resume_chains(
    sc: Scenario, prefix_mask: int, field: dict[str, list[str]]
) -> dict[str, list[str]]:
    chains = {ep: list(ch) for ep, ch in sc.endpoint_chains.items()}
    for i, ep in sc.replace_endpoint.items():
        if prefix_mask >> i & 1:
            chains[ep] = list(sc.target_chains[ep])
    chains.update({ep: list(ch) for ep, ch in field.items()})
    return chains


# ---------------------------------------------------------------------------
# Continuation solver
#
# Remaining actions are remapped to dense indices. A search state is
# (executed dense mask, next absolute stage, viable option sets). For each
# endpoint whose remaining replace_cert has already committed, V[ep] is the
# set of clean destination chains that have had a valid trust path for *every*
# relationship of the endpoint at *every* anchor configuration seen since the
# commit. An empty V means the trajectory is hopeless; at the end any member of
# V[ep] can be finalized, and the lexicographically smallest (options are
# stored sorted by complete chain fingerprint) is the stable choice.
# ---------------------------------------------------------------------------


def _valid_option_bits(
    sc: Scenario,
    ep_rels: dict[str, list],
    ep: str,
    options: dict[str, list[tuple[str, ...]]],
    anchors: frozenset[TrustEdge],
) -> int:
    """Bitmask of destination chains of ``ep`` under which every required
    relationship of the endpoint has a valid trust path at ``anchors``."""
    bits = 0
    for j, chain in enumerate(options[ep]):
        ok = True
        for rel in ep_rels[ep]:
            st = TrustState(anchors=anchors, chains={ep: list(chain)})
            if evaluate_path(sc, st, rel.client_id, ep) is not None:
                ok = False
                break
        if ok:
            bits |= 1 << j
    return bits


@dataclass
class _ContSolver:
    sc: Scenario
    prefix_mask: int
    dense: list[int]                        # dense index -> global action index
    g2d: dict[int, int]                     # global -> dense
    m: int
    initial_anchors: frozenset[TrustEdge]
    initial_chains: dict[str, list[str]]
    # endpoint -> sorted distinct clean destination chains (pending replaces)
    options: dict[str, list[tuple[str, ...]]]
    ep_rels: dict[str, list]                # endpoint -> its relationships
    memo: dict[tuple, int] = field(default_factory=dict)
    _valid_cache: dict[tuple, int] = field(default_factory=dict)

    def _replace_global(self, ep: str) -> int:
        return next(
            gi for gi, e in self.sc.replace_endpoint.items() if e == ep
        )

    # -- state derivations ---------------------------------------------------

    def global_mask(self, mask: int) -> int:
        g = self.prefix_mask
        for d in range(self.m):
            if mask >> d & 1:
                g |= 1 << self.dense[d]
        return g

    def batch_global(self, batch: int) -> int:
        """Global action bits of ``batch`` alone — used for the *same-stage*
        add/remove contradiction check (executed prefix never participates)."""
        g = 0
        for d in range(self.m):
            if batch >> d & 1:
                g |= 1 << self.dense[d]
        return g

    def anchors_for(self, mask: int) -> frozenset[TrustEdge]:
        gmask = self.global_mask(mask)
        anchors = set(self.sc.initial_anchors)
        for i, edge in self.sc.add_edges.items():
            if gmask >> i & 1:
                anchors.add(edge)
        for i, edge in self.sc.remove_edges.items():
            if gmask >> i & 1:
                anchors.discard(edge)
        return frozenset(anchors)

    def _valid_option_bits(
        self, ep: str, anchors: frozenset[TrustEdge]
    ) -> int:
        key = (ep, frozenset(anchors))
        cached = self._valid_cache.get(key)
        if cached is None:
            cached = _valid_option_bits(
                self.sc, self.ep_rels, ep, self.options, anchors
            )
            self._valid_cache[key] = cached
        return cached

    def _served_chain(
        self, ep: str, mask: int, viable: dict[str, int]
    ) -> list[str]:
        d = self.g2d.get(self._replace_global(ep))
        if d is not None and mask >> d & 1:
            v = viable[ep]
            low = (v & -v).bit_length() - 1
            return list(self.options[ep][low])
        return self.initial_chains[ep]

    def _good(self, mask: int, viable: dict[str, int]) -> bool:
        anchors = self.anchors_for(mask)
        for rel in self.sc.relationships:
            chain = self._served_chain(rel.endpoint_id, mask, viable)
            st = TrustState(anchors=anchors, chains={rel.endpoint_id: chain})
            if evaluate_path(self.sc, st, rel.client_id, rel.endpoint_id) is not None:
                return False
        return True

    # -- batch transition ----------------------------------------------------

    def advance(
        self, mask: int, batch: int, viable: dict[str, int]
    ) -> Optional[dict[str, int]]:
        """Commit ``batch``; new viable sets, or None when the batch already
        makes the state unconditionally unusable (a committed replacement has
        no currently-valid clean chain or a relationship breaks)."""
        new_mask = mask | batch
        anchors = self.anchors_for(new_mask)
        nv: dict[str, int] = {}
        for ep in self.options:
            d = self.g2d[self._replace_global(ep)]
            valid_now = self._valid_option_bits(ep, anchors)
            if batch >> d & 1:
                v = valid_now
            elif new_mask >> d & 1:
                v = viable[ep] & valid_now
            else:
                continue  # still pending: nothing committed yet
            if v == 0:
                return None
            nv[ep] = v
        if not self._good(new_mask, nv):
            return None
        return nv

    # -- sparse stage skipping ----------------------------------------------

    def next_growth_stage(self, mask: int, after: int) -> Optional[int]:
        best: Optional[int] = None
        for d in range(self.m):
            if mask >> d & 1:
                continue
            stages = self.sc.allowed_sorted[self.dense[d]]
            pos = bisect_right(stages, after)
            if pos < len(stages) and (best is None or stages[pos] < best):
                best = stages[pos]
        return best

    # -- shortest completion -------------------------------------------------

    def finish(
        self, mask: int, stage: int, viable: dict[str, int]
    ) -> int:
        full = (1 << self.m) - 1
        if mask == full:
            return stage - 1
        if stage > self.sc.max_stage:
            return INF
        key = (mask, stage, tuple(sorted(viable.items())))
        cached = self.memo.get(key)
        if cached is not None:
            return cached

        available = 0
        for d in range(self.m):
            gi = self.dense[d]
            if (not (mask >> d & 1)) and stage in self.sc.allowed[gi]:
                available |= 1 << d

        best = INF
        sub = available
        while sub:
            if batch_conflict(self.sc, self.batch_global(sub)) is None:
                nv = self.advance(mask, sub, viable)
                if nv is not None:
                    best = min(best, self.finish(mask | sub, stage + 1, nv))
                    if best == stage:
                        self.memo[key] = best
                        return best
            sub = (sub - 1) & available

        nxt = self.next_growth_stage(mask, stage)
        if nxt is not None and (best == INF or nxt < best) and self._good(mask, viable):
            best = min(best, self.finish(mask, nxt, viable))

        self.memo[key] = best
        return best

    # -- lexicographically smallest minimum continuation --------------------

    def solve(self, k: int) -> Optional[list[tuple[int, int]]]:
        """Return [(stage_number, dense_batch_bits)] with real stage numbers
        (empty no-op stages emitted as gaps), or None."""
        full = (1 << self.m) - 1
        out: list[tuple[int, int]] = []
        mask = 0
        stage = 1
        viable: dict[str, int] = {}
        while mask != full and stage <= self.sc.max_stage:
            available = 0
            for d in range(self.m):
                gi = self.dense[d]
                if (not (mask >> d & 1)) and stage in self.sc.allowed[gi]:
                    available |= 1 << d

            chosen = 0
            decided = 0
            for d in range(self.m):
                bit = 1 << d
                if not (available & bit) or (decided & bit):
                    continue
                decided |= bit
                must = chosen | bit
                optional = available & ~(mask | decided | chosen)
                exists = False
                t = optional
                while True:
                    cand = must | t
                    if batch_conflict(
                        self.sc, self.batch_global(cand)
                    ) is None:
                        nv = self.advance(mask, cand, viable)
                        if nv is not None and self.finish(
                            mask | cand, stage + 1, nv
                        ) <= k:
                            exists = True
                            break
                    if t == 0:
                        break
                    t = (t - 1) & optional
                if exists:
                    chosen = must

            if chosen == 0:
                nxt = self.next_growth_stage(mask, stage)
                if nxt is None:
                    return None
                # Jump only when an optimal completion can still be reached.
                if self.finish(mask, nxt, viable) > k:
                    return None
                while stage < nxt:
                    out.append((stage, 0))
                    stage += 1
                continue

            nv = self.advance(mask, chosen, viable)
            if nv is None:
                return None
            viable = nv
            out.append((stage, chosen))
            mask |= chosen
            stage += 1
        return out if mask == full else None

    # -- final chain choice --------------------------------------------------

    def final_chains(
        self, batches: list[tuple[int, int]]
    ) -> dict[str, list[str]]:
        """Replay the batches and pick the lexicographically smallest chain
        that has stayed viable ever since each replacement committed."""
        viable: dict[str, int] = {}
        mask = 0
        for _stage, batch in batches:
            if batch == 0:
                continue
            nv = self.advance(mask, batch, viable)
            assert nv is not None
            viable = nv
            mask |= batch
        chosen: dict[str, list[str]] = {}
        for ep, v in viable.items():
            low = (v & -v).bit_length() - 1
            chosen[ep] = list(self.options[ep][low])
        return chosen


# ---------------------------------------------------------------------------
# Failure diagnostics
# ---------------------------------------------------------------------------


def _chain_dtos(sc: Scenario, chain: list[str]) -> list[ChainCert]:
    return [
        ChainCert(
            cert_id=cid,
            subject=sc.certs[cid].subject,
            issuer=sc.certs[cid].issuer,
        )
        for cid in chain
    ]


def _anchors_of(sc: Scenario, anchors: frozenset[TrustEdge], client_id: str):
    return sorted(e.cert_id for e in anchors if e.client_id == client_id)


def _failure(
    sc: Scenario,
    *,
    status: str,
    stage: int,
    rel_idx: int,
    reason: str,
    chain: list[str],
    anchors: list[str],
    blocking_certificate: Optional[str],
    blocking_action: Optional[str] = None,
) -> ContinueFailure:
    rel = sc.relationships[rel_idx]
    who = f"relationship {rel.client_id} -> {rel.endpoint_id}"
    if stage == 0:
        prefix = "the executed prefix already leaves"
    else:
        prefix = f"stage {stage} leaves"
    if reason == "untrusted_root":
        message = (
            f"{prefix} {who} without a trust path: chain terminates at "
            f"'{chain[-1]}', which is not among the client's trust anchors "
            f"({', '.join(anchors) or 'none'})"
        )
    elif reason == "issuer_mismatch":
        message = (
            f"{prefix} {who} with a broken chain [{' -> '.join(chain)}]: "
            f"issuer/subject mismatch"
        )
    elif reason == "certificate_revoked":
        message = (
            f"{who}: the currently served chain contains freshly revoked "
            f"certificate '{blocking_certificate}' and no remaining "
            f"replace_cert action can move the endpoint to clean evidence"
        )
    elif reason == "conflicting_evidence":
        message = (
            f"{who}: the currently served chain contains certificate "
            f"'{blocking_certificate}' with conflicting fresh good/revoked "
            f"evidence and no remaining replace_cert action can move the "
            f"endpoint to clean evidence"
        )
    elif reason == "no_clean_destination":
        message = (
            f"{who}: the remaining replace_cert action has no clean "
            f"destination chain — the target and every alternative contains "
            f"freshly revoked or conflicting evidence "
            f"(blocking certificate '{blocking_certificate}')"
        )
    else:
        message = f"{prefix} {who} invalid ({reason})"
    return ContinueFailure(
        status=status,  # type: ignore[arg-type]
        stage=stage,
        relationship=RelationshipRef(
            client_id=rel.client_id, endpoint_id=rel.endpoint_id
        ),
        blocking_certificate=blocking_certificate,
        blocking_action=blocking_action,
        reason=reason,
        chain=_chain_dtos(sc, chain),
        trusted_anchors=anchors,
        message=message,
    )


def _path_failure(
    sc: Scenario,
    *,
    status: str,
    stage: int,
    anchors: frozenset[TrustEdge],
    served: dict[str, list[str]],
    pf_rel: tuple[int, PathFailure],
    blocking_action: Optional[str] = None,
) -> ContinueFailure:
    ridx, pf = pf_rel
    return _failure(
        sc,
        status=status,
        stage=stage,
        rel_idx=ridx,
        reason=pf.reason,
        chain=pf.chain,
        anchors=_anchors_of(sc, anchors, sc.relationships[ridx].client_id),
        blocking_certificate=pf.chain[pf.failure_index],
        blocking_action=blocking_action,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _first_broken(
    sc: Scenario,
    anchors: frozenset[TrustEdge],
    served: dict[str, list[str]],
):
    for ridx, rel in enumerate(sc.relationships):
        st = TrustState(anchors=anchors, chains=served)
        pf = evaluate_path(sc, st, rel.client_id, rel.endpoint_id)
        if pf is not None:
            return ridx, pf
    return None


def continue_plan(
    req: ContinueRequest,
) -> ContinueSuccess | ContinueFailure:
    sc = build_scenario(req)
    field_chains: dict[str, list[str]] = {}
    _validate_inputs(sc, req, field_chains)

    action_index = {aid: i for i, aid in enumerate(sc.action_ids)}
    prefix_mask = 0
    for aid in req.completed_action_ids:
        prefix_mask |= 1 << action_index[aid]

    verdicts = _cert_verdicts(req)

    # -- served (field) chains and target/candidate elimination --------------
    served = _resume_chains(sc, prefix_mask, field_chains)

    field_dirty: dict[str, tuple[str, str]] = {}
    for ep, chain in served.items():
        hit = _chain_verdict(chain, verdicts)
        if hit is not None:
            field_dirty[ep] = hit

    target_dirty: dict[str, tuple[str, str]] = {}
    for ep, chain in sc.target_chains.items():
        hit = _chain_verdict(chain, verdicts)
        if hit is not None:
            target_dirty[ep] = hit

    candidate_dirty: dict[str, list[tuple[tuple[str, ...], str, str]]] = {}
    candidates_by_ep: dict[str, list[tuple[str, ...]]] = {}
    for alt in req.alternatives:
        seen_chains: set[tuple[str, ...]] = set()
        for chain in alt.candidate_chains:
            t = tuple(chain)
            if t in seen_chains:
                continue
            seen_chains.add(t)
            hit = _chain_verdict(list(t), verdicts)
            if hit is not None:
                candidate_dirty.setdefault(alt.endpoint_id, []).append(
                    (t, hit[0], hit[1])
                )
            else:
                candidates_by_ep.setdefault(alt.endpoint_id, []).append(t)

    # -- remaining actions and clean destination options ---------------------
    dense = [
        i for i in range(sc.n)
        if not (prefix_mask >> i & 1)
    ]
    g2d = {gi: d for d, gi in enumerate(dense)}
    m = len(dense)

    options: dict[str, list[tuple[str, ...]]] = {}
    for gi, ep in sc.replace_endpoint.items():
        if prefix_mask >> gi & 1:
            continue  # replacement already executed (field chain authoritative)
        seen_chains: set[tuple[str, ...]] = set()
        opts: list[tuple[str, ...]] = []
        target_t = tuple(sc.target_chains[ep])
        if ep not in target_dirty:
            seen_chains.add(target_t)
            opts.append(target_t)
        for t in sorted(candidates_by_ep.get(ep, [])):
            if t not in seen_chains:
                seen_chains.add(t)
                opts.append(t)
        opts.sort()
        options[ep] = opts

    initial_anchors = _resume_anchors(sc, prefix_mask)

    # Endpoint -> relationships (only such endpoints block the continuation).
    ep_rels: dict[str, list] = {}
    for rel in sc.relationships:
        ep_rels.setdefault(rel.endpoint_id, []).append(rel)

    # -- stage 0 blockers ----------------------------------------------------
    # 1) the immutable resume state must already have valid trust paths.
    broken = _first_broken(sc, initial_anchors, served)
    if broken is not None:
        return _path_failure(
            sc,
            status="invalid",
            stage=0,
            anchors=initial_anchors,
            served=served,
            pf_rel=broken,
        )

    # 2) a dirty chain still in service with no remaining replace to retire
    #    it cannot be continued safely.
    for ridx, rel in enumerate(sc.relationships):
        ep = rel.endpoint_id
        if ep not in field_dirty or ep in options:
            continue
        reason, blocker = field_dirty[ep]
        return _failure(
            sc,
            status="infeasible",
            stage=0,
            rel_idx=ridx,
            reason=reason,
            chain=served[ep],
            anchors=_anchors_of(sc, initial_anchors, rel.client_id),
            blocking_certificate=blocker,
        )

    # 3) a remaining replace with no clean destination is hopeless.
    for ep in options:
        if options[ep]:
            continue
        blocker: Optional[str] = None
        chain = sc.target_chains[ep]
        if ep in target_dirty:
            blocker = target_dirty[ep][1]
        else:
            dlist = candidate_dirty.get(ep, [])
            if dlist:
                blocker = dlist[0][2]
                chain = list(dlist[0][0])
        # The response names a relationship; prefer this endpoint's first
        # one, otherwise the scenario's first relationship (an endpoint
        # without any required relationship still cannot deploy its pending
        # replace_cert onto anything).
        ridx = next(
            (i for i, rel in enumerate(sc.relationships)
             if rel.endpoint_id == ep),
            0,
        )
        rel = sc.relationships[ridx]
        return _failure(
            sc,
            status="infeasible",
            stage=0,
            rel_idx=ridx,
            reason="no_clean_destination",
            chain=chain,
            anchors=_anchors_of(sc, initial_anchors, rel.client_id),
            blocking_certificate=blocker,
        )

    # Drop endpoint entries without relationships from the solver's option
    # map: nothing constrains them, the replacement still executes but its
    # destination choice is simply the lexicographically smallest clean one.
    solver_options = {ep: opts for ep, opts in options.items() if ep in ep_rels}

    solver = _ContSolver(
        sc=sc,
        prefix_mask=prefix_mask,
        dense=dense,
        g2d=g2d,
        m=m,
        initial_anchors=initial_anchors,
        initial_chains=served,
        options=solver_options,
        ep_rels=ep_rels,
    )

    k = solver.finish(0, 1, {})
    if k >= INF:
        return _eager_failure(sc, solver, options, initial_anchors, served)

    batches = solver.solve(k)
    assert batches is not None

    # Chains actually deployed: solver picks for relationship-bearing
    # endpoints; pick the lexicographically smallest clean chain for the rest.
    chosen_chains = solver.final_chains(batches)
    for ep, opts in options.items():
        if ep not in chosen_chains:
            chosen_chains[ep] = list(opts[0])

    # -- response assembly ---------------------------------------------------
    stages_out: list[ContinueStage] = []
    for num, batch in batches:
        action_ids: list[str] = []
        deployments: list[ContinueChainDeployment] = []
        for d in range(m):
            if batch >> d & 1:
                gi = dense[d]
                action_ids.append(sc.action_ids[gi])
                ep = sc.replace_endpoint.get(gi)
                if ep is not None:
                    deployments.append(
                        ContinueChainDeployment(
                            endpoint_id=ep, chain=chosen_chains[ep]
                        )
                    )
        deployments.sort(key=lambda d: d.endpoint_id)
        stages_out.append(
            ContinueStage(
                stage=num,
                action_ids=action_ids,
                chain_deployments=deployments,
            )
        )

    selected = [
        ContinueChainDeployment(endpoint_id=ep, chain=chosen_chains[ep])
        for ep in sorted(chosen_chains)
    ]

    eliminated: list[EliminatedChain] = []
    role_order = {"current": 0, "target": 1, "candidate": 2}
    for ep, (reason, blocker) in field_dirty.items():
        eliminated.append(
            EliminatedChain(
                endpoint_id=ep, role="current", chain=served[ep],
                reason=reason, blocking_certificate=blocker,
            )
        )
    for ep, (reason, blocker) in target_dirty.items():
        eliminated.append(
            EliminatedChain(
                endpoint_id=ep, role="target", chain=sc.target_chains[ep],
                reason=reason, blocking_certificate=blocker,
            )
        )
    for ep, items in candidate_dirty.items():
        for t, reason, blocker in items:
            eliminated.append(
                EliminatedChain(
                    endpoint_id=ep, role="candidate", chain=list(t),
                    reason=reason, blocking_certificate=blocker,
                )
            )
    eliminated.sort(
        key=lambda e: (
            e.endpoint_id, role_order[e.role], tuple(e.chain)
        )
    )

    return ContinueSuccess(
        stage_count=len(batches),
        completed_action_ids=sorted(req.completed_action_ids),
        stages=stages_out,
        selected_chains=selected,
        eliminated_chains=eliminated,
    )


def _eager_failure(
    sc: Scenario,
    solver: _ContSolver,
    options: dict[str, list[tuple[str, ...]]],
    initial_anchors: frozenset[TrustEdge],
    served: dict[str, list[str]],
) -> ContinueFailure:
    """Concrete diagnostic replay when no continuation exists.

    Every remaining action is placed at the earliest stage it allows; a
    committing replace_cert deploys the lexicographically smallest clean
    chain that is valid for all the endpoint's relationships at that moment.
    Actions are applied one at a time in action_id order, so the first action
    after which a relationship loses its trust path is attributed as the
    blocking action. Since ``finish()`` proved the instance infeasible, this
    deterministic replay is guaranteed to reach a reportable break.
    """
    dense = solver.dense
    m = len(dense)
    full = (1 << m) - 1
    mask = 0
    stage = 1
    anchors = initial_anchors
    chains = {ep: list(ch) for ep, ch in served.items()}

    def report(ridx: int, *, gi: Optional[int], stg: int,
               chain_override: Optional[list[str]] = None) -> ContinueFailure:
        rel = sc.relationships[ridx]
        chain = chain_override or chains[rel.endpoint_id]
        st = TrustState(anchors=anchors, chains={rel.endpoint_id: chain})
        pf = evaluate_path(sc, st, rel.client_id, rel.endpoint_id)
        if pf is None:
            pf = PathFailure(
                "untrusted_root", chain, len(chain) - 1,
                _anchors_of(sc, anchors, rel.client_id),
            )
        else:
            # Preserve the chain being evaluated (e.g. an about-to-commit
            # alternative) rather than the currently served one.
            pf.chain = list(chain)
        return _path_failure(
            sc,
            status="infeasible",
            stage=stg,
            anchors=anchors,
            served=chains,
            pf_rel=(ridx, pf),
            blocking_action=(
                sc.action_ids[gi] if gi is not None else None
            ),
        )

    while mask != full:
        batch = 0
        for d in range(m):
            gi = dense[d]
            if (not (mask >> d & 1)) and stage in sc.allowed[gi]:
                batch |= 1 << d
        if batch == 0:
            nxt = solver.next_growth_stage(mask, stage)
            if nxt is None:
                # Nothing left can ever be scheduled; the trust state itself
                # is healthy, so attribute to the first relationship with no
                # further legal action.
                rel = sc.relationships[0]
                return _failure(
                    sc,
                    status="infeasible",
                    stage=stage,
                    rel_idx=0,
                    reason="no_eligible_actions_at_stage",
                    chain=chains[rel.endpoint_id],
                    anchors=_anchors_of(sc, anchors, rel.client_id),
                    blocking_certificate=None,
                )
            stage = nxt
            continue

        for d in range(m):
            if not (batch >> d & 1):
                continue
            gi = dense[d]
            if gi in sc.add_edges:
                anchors = anchors | {sc.add_edges[gi]}
            elif gi in sc.remove_edges:
                anchors = anchors - {sc.remove_edges[gi]}
            else:
                ep = sc.replace_endpoint[gi]
                if ep in solver.ep_rels:
                    bits = _valid_option_bits(
                        sc, solver.ep_rels, ep, options, anchors
                    )
                else:
                    # No required relationship constrains this endpoint.
                    bits = (1 << len(options[ep])) - 1
                if bits == 0:
                    # Committing here would immediately break the endpoint:
                    # report against the smallest clean destination chain.
                    bad_chain = list(options[ep][0])
                    ridx = next(
                        r for r, rel in enumerate(sc.relationships)
                        if rel.endpoint_id == ep
                    )
                    return report(ridx, gi=gi, stg=stage,
                                  chain_override=bad_chain)
                low = (bits & -bits).bit_length() - 1
                chains[ep] = list(options[ep][low])

            broken = _first_broken(sc, anchors, chains)
            if broken is not None:
                return report(broken[0], gi=gi, stg=stage)

        mask |= batch
        stage += 1

    # Defensive: unreachable while finish() reports INF.
    broken = _first_broken(sc, anchors, chains)
    if broken is None:
        rel = sc.relationships[0]
        return _failure(
            sc,
            status="infeasible",
            stage=stage - 1,
            rel_idx=0,
            reason="infeasible",
            chain=chains[rel.endpoint_id],
            anchors=_anchors_of(sc, anchors, rel.client_id),
            blocking_certificate=None,
        )
    return report(broken[0], gi=None, stg=stage - 1)
