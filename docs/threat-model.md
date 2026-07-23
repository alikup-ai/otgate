# Threat model: otgate vs. OWASP Top 10 for Agentic Applications (2026)

otgate is a policy enforcement point between an LLM agent and a tool backend
(OPC UA today). This document maps what it actually mitigates onto the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) — and, just as
importantly, what it does not.

The primary risk otgate addresses is **ASI02 — Tool Misuse & Exploitation**:
an agent that stays within its granted privileges but uses a legitimate tool in
an unsafe way. Everything else below is either partial coverage or explicitly
out of scope.

Coverage keys: **✅ addressed** · **◐ partial** · **✗ out of scope**

---

## ASI02 — Tool Misuse & Exploitation ✅ (primary)

> *"Agents misusing or abusing tools through unsafe composition, recursion, or
> excessive execution, causing harmful side effects."*

This is the risk otgate was built for. The agent is authorised to call
`write_tag`; the danger is in **what it writes, how fast, and under which
process conditions**. Identity and access controls do not see any of that — they
only answer "may this agent call this tool at all".

| ASI02 sub-mechanism | Mechanism in otgate | Proof |
|---|---|---|
| **Parameter pollution** — arguments pushed beyond the intended scope | `value_range` on the tag; the write is evaluated against the *value*, not just the tool name | `tests/test_engine.py::test_write_out_of_range_denied`, `test_write_below_range_denied` |
| **Excessive execution / harmful scale** — legitimate tool invoked at damaging frequency | `max_rate` + `rate_interval`, measured against the last write otgate let through; survives restarts via `OTGATE_RATE_HISTORY` | `tests/test_engine.py::test_max_rate_exceeded_denied`, `tests/test_rate_history.py::test_rate_limit_survives_restart` |
| **Unsafe use given system state** — the call is fine in isolation, unsafe right now | `interlocks`: the engine reads the current state of a guard tag (e.g. emergency shutdown) before allowing the write | `tests/test_engine.py::test_interlock_active_denied` |
| **Unverifiable safety condition** | If the interlock tag cannot be read, the write is **denied** rather than allowed (fail closed) | `tests/test_failclosed.py::test_unverifiable_interlock_fails_closed` |
| **Writes to tools never intended for the agent** | Deny-by-default: any tag absent from the policy is refused | `tests/test_engine.py::test_write_tag_not_in_policy_denied` |

**Not covered within ASI02:**

- **Tool chain manipulation.** Each call is evaluated independently. A sequence
  of individually valid writes that is harmful only in aggregate (or across
  several tags) is not detected. There is no cumulative budget across a series
  of actions.
- **Non-scalar arguments.** Values are numbers or booleans; structured payloads
  are not inspected.
- Rate limiting is per tag and wall-clock based, measured from the last write
  otgate allowed — not against the true process trend from a historian.

---

## ASI03 — Agent Identity & Privilege Abuse ◐

> *"Delegated authority, ambiguous agent identity, or trust assumptions lead to
> unauthorized actions."*

**Addressed:** each agent authenticates with its own bearer token and is bound
to its own policy (`agents.yaml`), so a diagnostics agent physically cannot use
an optimiser agent's write rights. Every audit line carries the acting agent.
Agent and operator capabilities are split across **separate authenticated HTTP
channels**, so an agent cannot reach the approval tools and rubber-stamp its own
writes.
*Proof:* `tests/test_agents.py`, `tests/test_auth.py`.

**Not covered:** the agent roster is static (read at startup — no live
add/revoke), tokens are long-lived with no rotation or expiry, and there is no
delegation chain or on-behalf-of semantics.

---

## ASI09 — Human-Agent Trust Exploitation ◐

> *"Exploiting human over-reliance on agents through misleading explanations or
> authority framing."*

**Addressed:** for `write_with_approval` tags the write is parked, not executed,
until a human decides. Two properties matter here:

1. **Re-evaluation on approval.** Approving records intent; otgate re-runs the
   full policy against the *current* state before executing. A request that was
   safe when raised and unsafe when approved (an interlock tripped meanwhile) is
   blocked. Approval is never a blank cheque.
2. **Fail-safe expiry.** An unanswered request expires and is never executed —
   silence means no.

Every decision carries a human-readable reason, so the operator approves a
concrete, explained action rather than an opaque request.
*Proof:* `tests/test_approval.py::test_approve_reevaluates_and_blocks_stale_ask`,
`test_approve_expired_request`.

**Not covered:** single-approver model (no quorum, no separation of duties), no
rate limiting on approval fatigue, and otgate cannot tell whether the human
actually understood what they approved.

---

## ASI08 — Cascading Agent Failures ◐

> *"Small agent failures propagate through connected systems, causing
> large-scale impact."*

**Addressed (locally):** otgate fails closed. If the backend is unreachable,
reads and writes return an ERROR outcome and are audited — never a silent
failure or a fabricated success. Rate limits bound how fast an agent can push
the process, which limits blast radius. `/health` exposes backend reachability
for monitoring.
*Proof:* `tests/test_failclosed.py`.

**Not covered:** otgate governs a single agent→backend edge. It has no view of
multi-agent topologies and cannot detect failures propagating between agents.

---

## Risks otgate does NOT address ✗

Being explicit about this matters more than claiming broad coverage.

| Risk | Why it is out of scope |
|---|---|
| **ASI01 Agent Goal Hijack** | otgate never sees prompts or model reasoning. It inspects *actions*, not intentions. A hijacked agent is constrained only insofar as its actions violate policy — which is the point, but it is not detection of the hijack. |
| **ASI04 Agentic Supply Chain Compromise** | No verification of tools, schemas, plugins or their provenance. |
| **ASI05 Unexpected Code Execution** | otgate mediates tag reads/writes, not code execution. No sandboxing. |
| **ASI06 Memory & Context Poisoning** | Agent memory and RAG stores are outside the gateway entirely. |
| **ASI07 Insecure Inter-Agent Communication** | Only the agent↔otgate↔backend path is mediated; agent-to-agent traffic is invisible. |
| **ASI10 Rogue Agents** | No behavioural baselining or drift detection across sessions. A rogue agent is limited by policy, but otgate will not flag it as rogue. |

---

## Structural assumptions and limits

These hold regardless of which risk is under discussion:

- **otgate is a soft layer.** It is effective only when it is the *only* path to
  the backend. If the OPC UA server is reachable directly, the policy means
  nothing. Network isolation is a precondition, not an optimisation.
- **It complements, never replaces, hardware interlocks / SIS.** Deterministic
  safety belongs below otgate, in the PLC/DCS.
- **Audit is append-only but not tamper-evident.** Entries are flushed to the OS
  on write; there is no hash chain or signature, so an attacker with filesystem
  access can alter history.
- **Single instance.** No HA; a crash removes agent access until restart (the
  safe direction, but still an availability limit).
- **Not production-grade for hazardous processes.** This is a reference
  implementation suitable for evaluation and, at most, a carefully scoped pilot.

---

## Reproducing the evidence

Every claim above is backed by a test that runs without external dependencies:

```bash
pytest -m asi02                # just the ASI02 evidence (7 tests)
pytest -m "not integration"    # policy, approval, auth, fail-closed, audit
pytest -m integration          # the same behaviours against a real OPC UA server
```

The `asi02` marker tags exactly the tests cited in the ASI02 table above, so the
claimed coverage is executable rather than asserted.

Shadow mode (`OTGATE_SHADOW=1`) is the recommended first step for any real
evaluation: allowed writes are logged as "WOULD execute" and never reach the
backend, so an agent can be assessed against a live process with zero effect on
it.
