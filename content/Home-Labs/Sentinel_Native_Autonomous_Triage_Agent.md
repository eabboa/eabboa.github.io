# Sentinel-Native AI-Augmented Triage Agent

![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-1C3C3C?style=flat-square)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-REST_API-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat-square&logo=google&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API_v3-394EFF?style=flat-square)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API_v2-8B0000?style=flat-square)
![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG-00897B?style=flat-square)
![asyncio](https://img.shields.io/badge/asyncio-Concurrent_Execution-2C5BB4?style=flat-square)
![aiohttp](https://img.shields.io/badge/aiohttp-Async_I/O-2C5BB4?style=flat-square)
![Pydantic](https://img.shields.io/badge/Pydantic-Structured_Output-E92063?style=flat-square)
![tenacity](https://img.shields.io/badge/tenacity-Retry_Engine-FF6F00?style=flat-square)

**Type:** Cloud Security · Detection Engineering · AI Automation  
**Stack:** Microsoft Azure · Microsoft Sentinel · LangGraph · Pydantic · Managed Identities · Google Gemini · ChromaDB · VirusTotal · AbuseIPDB  
**Cost:** $0 (free tier across all services)  
**Code:** [sentinel-triage-agent](https://github.com/eabboa/sentinel-triage-agent)

**Objective:** A defensively engineered, zero-cost **SOAR architecture** designed to safely absorb Tier 1 benign-positive alarm fatigue without compromising true positive retention. It shifts the operational paradigm from reactive manual polling to deterministic, machine-speed orchestration with mandatory human oversight.

_Note_: This project demonstrates the operational logic of cybersecurity automation. LLMs are strictly bound as reasoning engines, constrained by typed schemas and conditional routing, to solve SOC bottlenecks under rigid production requirements.

_Status_: v0.5.0 Active

_Last updated_: 29-04-2026

---

## What I Built

Most SIEM integrations flow in one direction: a tool reads logs and produces output elsewhere. This project is **bidirectional**. Sentinel is both the source and the destination.

The agent polls for new incidents, fetches the full incident object and raw alerts from the **Sentinel REST API**, and condenses them into a token-efficient summary. A hybrid extraction layer uses compiled regex for structured IOCs (IPs, hashes, URLs) and a secondary LLM call for contextual entities (usernames, hostnames, domains) that regex cannot reliably parse. Extracted indicators are then enriched concurrently through AbuseIPDB and VirusTotal, with per-request retries and rate-limit serialization.

Before classification, the agent queries a **ChromaDB RAG store** for historical analyst corrections semantically similar to the current incident. These mismatches are injected as few-shot examples into the analyst prompt, grounding the model against previously observed mistakes. The LLM then produces a deterministic verdict via `with_structured_output` bound to a strict **Pydantic schema**, every field is typed, every classification is enumerated, and every confidence score is an exact integer.

Conditional routing branches on the classification and confidence. High-confidence true positives trigger an escalation path. Ambiguous verdicts route through **schema-gated KQL hunting query generation**, where the LLM is restricted to an explicit table-column map filtered by detected MITRE ATT&CK tactics. High-confidence false positives bypass KQL entirely and proceed directly to writeback.

The structured triage report, verdict, MITRE analysis, enrichment results, and KQL queries are posted as a comment on the Sentinel incident record. The graph then **suspends execution** at a LangGraph interrupt point. No incident is closed, no device is isolated, and no session is revoked without **_explicit human approval_**. This is the critical enforcement boundary: the agent recommends, the analyst decides.

After review, conditional routing either executes MDE device isolation before closure or proceeds directly to the close review gate. A terminal learning node compares the LLM's classification against the analyst's human-provided classification; divergences are embedded and stored in ChromaDB, closing the feedback loop.

That is the architecture SOAR platforms implement. This is a recreation of it for **$0**.

---

## What This Covers

| Area | Specifics |
|---|---|
| **Cloud Infrastructure** | Azure tenant setup, Log Analytics Workspace, Microsoft Sentinel REST API (stable `2023-02-01`). |
| Identity & Access | Zero-secret architecture. `DefaultAzureCredential` inherits Managed Identity (production) or Azure CLI tokens (development). Module-level token cache with 5-minute expiry buffer. |
| **Stateful Orchestration** | LangGraph `StateGraph` with 11 nodes, 3 conditional routing edges, `MemorySaver` checkpointing, and `interrupt_after` for human-in-the-loop suspension. |
| Adaptive Learning | ChromaDB RAG feedback loop. Analyst corrections are embedded via `all-MiniLM-L6-v2`, stored persistently, and retrieved as few-shot examples to reduce classification error iteratively. |
| **Deterministic AI** | `with_structured_output(AnalystVerdict)` paired with a rigid Pydantic schema. The LLM is forced into strongly typed outputs (`classification`, `is_true_positive`, `confidence`, `triage_summary`, `mitre_analysis`, `recommended_action`). Validation failures are caught at the node level. |
| **Schema-Gated KQL** | Hunting queries are constrained to an explicit table-column map (`SecurityAlert`, `SigninLogs`, `AuditLogs`, `SecurityEvent`, `OfficeActivity`). Tables are pre-filtered by detected MITRE ATT&CK tactics before prompt construction. |
| **Asynchronous I/O** | `asyncio.gather` with `Semaphore(3)` for concurrent incident processing. `aiohttp` with `ClientTimeout` for CTI enrichment. VirusTotal calls are serialized with a 15-second inter-request sleep. |
| **Rate Limiting & Retry** | Sliding-window `APIRateLimiter` capping Gemini to 14 RPM. `tenacity` retries with exponential backoff + jitter on `429`, `503`, and `RESOURCE_EXHAUSTED` across all LLM and REST API calls. |
| **Active Containment** | HITL-gated MDE device isolation and Entra ID session revocation via Azure REST APIs. All failures are captured as non-fatal errors. |

---

## Architecture Flow

Each node adheres to the **Single Responsibility Principle**. The pipeline state is managed by `TriageState`, a `TypedDict` used for LangGraph state management.

```
                    ┌───────┐
                    │ START │
                    └───┬───┘
                        │
                   ┌────▼────┐
                   │  fetch  │  GET incident + POST alerts via Sentinel REST API
                   └────┬────┘
                        │
                 ┌──────▼──────┐
                 │  summarize  │  Deterministic truncation (no LLM)
                 └──────┬──────┘
                        │
                  ┌─────▼─────┐
                  │  extract  │  Regex (IPs/hashes/URLs) + LLM (usernames/hostnames)
                  └─────┬─────┘
                        │
              ┌─────────┴─────────┐
       has IOCs?              no IOCs
              │                   │
        ┌─────▼─────┐             │
        │  enrich   │             │
        └─────┬─────┘             │
              └─────────┬─────────┘
                        │
                  ┌─────▼─────┐
                  │  analyst  │  LLM verdict + RAG few-shot correction
                  └─────┬─────┘
                        │
          ┌─────────────┼─────────────┐
     TP > 90%      ambiguous      FP > 95%
          │             │             │
   ┌──────▼──────┐ ┌───▼───┐          │
   │ escalation  │ │  kql  │          │
   └──────┬──────┘ └───┬───┘          │
          └─────────────┼─────────────┘
                        │
                 ┌──────▼──────┐
                 │  writeback  │  POST triage comment to Sentinel
                 └──────┬──────┘
                        │
              ══════ INTERRUPT ══════  (human review gate)
                        │
           ┌────────────┴────────────┐
    containment                 no containment
    approved?                        │
           │                         │
   ┌───────▼───────┐                 │
   │  containment  │  MDE isolate    │
   └───────┬───────┘                 │
           └────────────┬────────────┘
                        │
                ┌───────▼───────┐
                │ close_review  │  Sentinel close (if analyst approves)
                └───────┬───────┘
                        │
                 ┌──────▼──────┐
                 │  learning   │  RAG correction loop (ChromaDB)
                 └──────┬──────┘
                        │
                    ┌───▼───┐
                    │  END  │
                    └───────┘
```

### Conditional Routing Logic

Three conditional edges govern the pipeline:

1. **After `extract`:** If regex found IPs, hashes, or URLs → route to `enrich`. Otherwise → skip directly to `analyst`, avoiding unnecessary CTI API calls.

2. **After `analyst`:** The LLM verdict determines the next node:
   - `TruePositive` with confidence > 90 → `escalation` (high-severity path).
   - `FalsePositive` with confidence > 95 → bypass KQL, proceed directly to `writeback`.
   - All other cases → `kql` (generate hunting queries for ambiguous incidents).

3. **After `writeback` (post-HITL interrupt):** If the analyst approves containment → `containment` → `close_review`. Otherwise → `close_review` directly. No Autonomous closure occurs regardless of classification or confidence score.

---

## Designing for Failure

A security automation tool that fails open or corrupts state is a liability. Applying the principle of inversion, solving for what guarantees failure, and then engineering it out, produces the following fault-tolerance mechanisms:

### Race Condition Immunity (Optimistic Concurrency Control)
Human analysts and automated rules interact with incidents simultaneously. The pipeline fetches the incident's current ETag before every update and attaches it as an `If-Match` header on the `PUT` request. If the incident state mutated during the agent's execution window, Azure returns `412 Precondition Failed`, and the pipeline raises a `ConcurrencyConflictError` rather than silently overwriting an analyst's manual update.

### Credential Compromise Elimination
Hardcoded secrets are an unacceptable attack vector. The pipeline authenticates exclusively through `DefaultAzureCredential`, inheriting the identity of the compute environment. **In production**, this means **Azure Managed Identity with scoped RBAC** (`Microsoft Sentinel Contributor`). In development, it falls back to `az login` tokens. Tokens are cached module-level with a 5-minute expiry buffer to avoid unnecessary round-trip latency. No MSAL client secrets, no credential rotation, no static keys.

### Probabilistic Containment
LLMs are probabilistic, which makes them dangerous for Autonomous state machines. Every LLM output is bound to a strict **Pydantic schema** (`AnalystVerdict`) via `with_structured_output`. The model is forced into strongly typed outputs: an enumerated `classification`, a boolean `is_true_positive`, and an integer `confidence` score. Validation errors are caught at the node level and returned as structured error objects, preventing cascading failures or hallucinatory KQL execution. Additionally, no incident is closed, and no device is isolated without passing through the HITL interrupt gate.

### Graceful Degradation on CTI Timeout
Third-party threat intel APIs routinely throttle. The confidence scoring algorithm treats missing or timed-out CTI data as a **neutral baseline** (0-point modifier) rather than defaulting to "benign." This ensures that transient network errors or rate limits never result in false negatives. All CTI calls are wrapped with `aiohttp` timeouts, `tenacity` retries, and structured error capture. A failed enrichment degrades the confidence range; it never silently downgrades severity.

### Multi-Layer Retry Architecture
Transient failures are inevitable in distributed systems. The pipeline implements retries at three independent layers:
- **Azure REST API:** Shared `_http_request` wrapper with `tenacity` (3 attempts, exponential 1–10s) on `429`, `503`, `504`.
- **Gemini LLM:** Per-node `tenacity` wrappers (5 attempts, exponential 5–60s + random jitter) on `429 RESOURCE_EXHAUSTED` and `503 UNAVAILABLE`. Internal `max_retries=0` on all `ChatGoogleGenerativeAI` instances prevents double-retry loops.
- **CTI Enrichment:** `aiohttp` with `ClientTimeout(total=10)` and `tenacity` (3 attempts) on `ClientError`, `TimeoutError`, and transient HTTP codes.

### KQL Hallucination Mitigation
LLMs hallucinate KQL. They invent table names, reference nonexistent columns, and mix schemas across data connectors. The KQL node constrains the model by injecting an explicit `SENTINEL_TABLE_SCHEMA` map into the prompt, listing only approved tables (`SecurityAlert`, `SigninLogs`, `AuditLogs`, `SecurityEvent`, `OfficeActivity`) with their canonical column names. Tables are pre-filtered by detected MITRE ATT&CK tactics before prompt construction, eliminating references to disconnected data sources.

---

## Mandatory Human-in-the-Loop Enforcement

Every incident passes through the HITL gate.

1. The graph compiles with `interrupt_after=["writeback"]`. After the triage comment is posted to Sentinel, execution **suspends**.
2. The analyst reviews the verdict, MITRE analysis, enrichment results, and recommended actions in the console.
3. If compromised hostnames are present, the analyst is prompted to approve device containment.
4. The analyst approves or denies incident closure.
5. Only after explicit approval does the graph resume, executing containment (if approved) and then `close_review`.
6. The terminal `learning` node captures any classification divergence between the LLM and the analyst, embedding it in ChromaDB for future retrieval.

State persistence is handled by LangGraph's `MemorySaver` checkpointer with a unique `thread_id` per incident, ensuring each incident's execution context survives the interrupt without corruption.
