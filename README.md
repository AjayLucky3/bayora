# BAYORA
### Hardware-Isolated Sandboxing & Zero-Trust Mediation for Adversarial AI Evaluation
**Project Type:** Independent Open-Source Security & Systems Infrastructure Project  
**Author & Maintainer:** Ajay Doma  
**Contact:** domaajay187@gmail.com | **GitHub:** [https://github.com/AjayLucky3](https://github.com/AjayLucky3)  
**Deployment:** Zero-dependency static architecture (GitHub Pages ready, 100% offline-capable)

---

> **CRITICAL HONESTY DISCLAIMER:**  
> This web interface is an **interactive architecture simulation and cryptographic verification environment**. The actual production isolation implementation specified in this document runs on **gVisor (`runsc`) user-space kernels with Docker container runtime boundaries**. In this browser simulation, execution timings are framed strictly as **"Design Target: <12 ms"**, and model workers / evaluators are labeled as **`(Mock)`**.

---

## 1. Executive Summary & Core Thesis
Current adversarial AI safety testing ("Red Teaming") inherently introduces catastrophic security risks:
1. **Shared-Kernel Compromise:** Untrusted adversarial payloads can exploit kernel vulnerabilities (`dirty_pipe`, `io_uring` privilege escalations) to compromise the host operating system or adjacent containers.
2. **Benchmark Distortion & Memory Snooping:** In shared model serving instances, KV-cache residue, defensive system prompts, and evaluator rules leak across tenant boundaries, allowing adversaries to game benchmarks.
3. **Auditability Deficits:** Safety score evaluations lack cryptographic provenance; logs can be altered retrospectively without detection.

**Bayora** eliminates these failure modes by enforcing **kernel-level hardware sandboxing** via gVisor (`runsc`), **blinded mediation** across segmented Docker internal subnets, **commit-reveal payload binding** with single-use cryptographic salts, and an **immutable, tamper-evident SHA-256 Merkle audit ledger**.

---

## 2. Threat Model & Security Boundaries

```
+-----------------------------------------------------------------------------------------+
|                                HOST LINUX OS (HARDENED)                                 |
|                                                                                         |
|  +-----------------------+     +-----------------------+     +-----------------------+  |
|  |      RED SANDBOX      |     |     BLIND BROKER      |     |  MODEL / EVAL TIER    |  |
|  |    (Untrusted Red)    |     |  (Stateless Gateway)  |     |   (Protected Core)    |  |
|  |                       |     |                       |     |                       |  |
|  |  +-----------------+  |     |  +-----------------+  |     |  +-----------------+  |  |
|  |  |  gVisor runsc   |  |     |  |  gVisor runsc   |  |     |  |  gVisor runsc   |  |  |
|  |  | (Sentry Kernel) |  |     |  | (Sentry Kernel) |  |     |  | (Sentry Kernel) |  |  |
|  |  +-----------------+  |     |  +-----------------+  |     |  +-----------------+  |  |
|  |           |           |     |           ^           |     |           ^           |  |
|  +-----------|-----------+     +-----------|-----------+     +-----------|-----------+  |
|              |                             |                             |              |
|              |    [red-broker-net]         |    [broker-internal-net]    |              |
|              +-----------------------------+-----------------------------+              |
|                   (Subnet: 172.28.0.0/24)             (Subnet: 172.29.0.0/24)           |
|                                                                                         |
|  [FIREWALL RULE: DIRECT ROUTE RED <---> MODEL WORKER / BLUE EVALUATOR = DROP / EHOSTUNREACH] |
+-----------------------------------------------------------------------------------------+
```

### Security Properties Enforced
| Domain | Threat | Bayora Mitigation Mechanism |
| :--- | :--- | :--- |
| **Syscall Isolation** | Host kernel exploits from adversarial code execution | gVisor `runsc` virtualizes all Linux syscalls in userspace via Sentry. Zero direct host syscall exposure. |
| **Network Snooping** | Red team probing internal evaluator or LLM endpoints | 3-tier segmented Docker bridge networks. Red sandbox only has network route to `Blind Broker:8000`. |
| **KV-Cache Residue** | Cross-tenant memory leakage in vLLM/TensorRT | Mandatory stateless cache purge (`[KV-CACHE PURGED \| VRAM ZEROED]`) after every inference turn. |
| **Defensive Leakage**| Adversary learning Blue evaluator guardrail heuristics | Blind mediation: Blue evaluator only receives candidate output, Red prompt is completely masked (`[MASKED]`). |
| **Audit Log Tampering** | Retrospective alteration of safety benchmark logs | Cryptographic hash chaining: $H_n = \text{SHA-256}(H_{n-1} + \text{data})$ and Merkle tree inclusion proofs. |
| **Payload Equivocation**| Swapping attack payload after observing defensive state | Commit-Reveal scheme: Red pre-commits `SHA-256(Prompt + Salt)` before dispatch. Replays rejected. |
| **Covert Reconnaissance**| Probing for defensive canary files or credentials | Decoy canary files (`/etc/mock_guard_weights.bin`). Access instantly triggers tenant freeze. |

---

## 3. Cryptographic Specification

### A. Commit-Reveal Protocol
1. **Pre-commitment:**
   $$\text{Salt} \leftarrow \text{CSPRNG}(16 \text{ bytes})$$
   $$\text{Commitment} = \text{SHA-256}(\text{Prompt} \parallel \text{Salt})$$
2. **Verification & Execution:**
   - Broker verifies $\text{SHA-256}(\text{Prompt} \parallel \text{Salt}) \stackrel{?}{=} \text{Commitment}$.
   - Replay filter checks if $\text{Salt}$ has already been consumed in the active ledger. If consumed: **`REJECT: REPLAY DETECTED`**.
3. **Audit Ledger Chaining:**
   For entry $n$, let:
   $$D_n = \text{Index}_n \parallel \text{Timestamp}_n \parallel \text{PayloadHash}_n \parallel \text{ResponseHash}_n \parallel \text{Score}_n$$
   $$H_0 = \text{0x0000000000000000000000000000000000000000000000000000000000000000}$$
   $$H_n = \text{SHA-256}(H_{n-1} \parallel D_n)$$
4. **Merkle Tree & Inclusion Proof:**
   - All leaf hashes $L_i = H_i$ are structured into a binary Merkle tree.
   - Sibling hashes provide $O(\log N)$ tamper verification against the published Merkle Root.

---

## 4. Production Specification & API Contract

### Docker Compose Architecture (`docker-compose.yml` snippet)
```yaml
version: '3.9'

services:
  red-sandbox:
    image: bayora/red-runner:latest
    runtime: runsc
    networks:
      - red-broker-net
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

  blind-broker:
    image: bayora/broker:latest
    runtime: runsc
    networks:
      - red-broker-net
      - broker-internal-net
    ports:
      - "127.0.0.1:8000:8000"

  model-worker:
    image: bayora/vllm-worker:latest
    runtime: runsc
    networks:
      - broker-internal-net
    environment:
      - ENFORCE_STATELESS=1

  blue-evaluator:
    image: bayora/blue-scorer:latest
    runtime: runsc
    networks:
      - broker-internal-net

networks:
  red-broker-net:
    internal: true
  broker-internal-net:
    internal: true
```

### API Endpoints
- `POST /v1/eval/commit`: Registers tamper-evident payload commitment (`{ commit_hash, salt }`).
- `POST /v1/eval/execute`: Dispatches prompt, validates salt, executes blinded inference, evaluates safety score, writes to ledger.
- `GET /v1/audit/proof?leaf_index=N`: Generates binary Merkle inclusion proof for ledger entry $N$.
- `GET /v1/ledger/verify`: Recomputes the full hash chain and returns boolean integrity status.

---

## 5. Repository File Structure
```
/
├── index.html     # Semantic, accessible brutalist DOM structure
├── styles.css     # High-contrast 1px monochrome styling, zero AI-SaaS clichés
├── app.js         # Web Crypto API SHA-256 engine, Merkle tree, state machines
└── README.md      # Systems architecture, threat model, mathematical proofs
```

---

## 6. How to Run Locally

### Requirements
- Any modern web browser supporting the W3C Web Crypto API (`window.crypto.subtle`).
- No Node.js, npm, webpack, or internet connection required.

### Starting Local Server
```bash
# From the repository root:
python3 -m http.server 8000

# Open in browser:
http://localhost:8000
```
Alternatively, open `index.html` directly in any web browser via `file://`.
