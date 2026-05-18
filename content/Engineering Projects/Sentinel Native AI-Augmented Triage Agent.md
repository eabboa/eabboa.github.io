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
**Stack:** Microsoft Sentinel · Azure · LangGraph · Google Gemini · VirusTotal · AbuseIPDB  
**Cost:** $0 (free tier across all services)  
**Status:** v0.6.0 Active  
**Code:** [sentinel-triage-agent](https://github.com/eabboa/sentinel-triage-agent)

## The Problem

A Tier 1 SOC analyst spends the majority of their shift on one task: manually opening alerts, checking IP reputation, looking up hashes, and deciding whether something is worth escalating. Most of it isn't. This is the false positive problem. And it not only wastes time but also creates fatigue that causes analysts to miss the **_alerts that actually matter_**.

This project automates the triage cycle for Microsoft Sentinel. Not the decision (the analyst still makes that), but everything that happens before the analyst needs to think.

_Last updated_: 18-05-2026

## What It Does

When a new incident appears in Sentinel, the agent:

1. **Fetches the full incident** and all associated raw alerts from the Sentinel API
2. **Extracts every indicator**. IP addresses, file hashes, URLs, usernames, and hostnames. Using a combination of pattern matching and a constrained AI call
3. **Enriches those indicators in parallel** against VirusTotal and AbuseIPDB, respecting API rate limits automatically
4. **Checks its own history and corrects itself**. A local vector database stores every case where the AI disagreed with an analyst's final call. Before issuing a verdict, it retrieves _similar past corrections and uses them to recalibrate_
5. **Issues a structured verdict**: True Positive, False Positive, or Ambiguous. With a confidence score and a MITRE ATT&CK breakdown
6. **Generates targeted hunting queries** (KQL) for ambiguous cases, constrained to tables that actually exist in the connected workspace rather than hallucinated.
7. **Posts a full triage report** as a comment directly on the Sentinel incident. The analyst sees everything in one place.
8. **Stops and waits.** No incident is closed. No device is isolated. Nothing happens until a human explicitly approves it.

After the analyst reviews and decides, the system either executes containment actions (device isolation, session revocation) or closes the incident. Then, it records whether the AI's classification matched the analyst's. That divergence data feeds back into the history store, so the **system gets more accurate over time.**

## Why This Architecture Matters

**The loop is closed.** Most automation tools are one-directional: they read from Sentinel and write somewhere else. This agent reads _from_ Sentinel and writes _back to_ Sentinel. The analyst never leaves their queue. The enrichment and verdict are waiting for them on the incident record.

**The AI is constrained, not autonomous.** The model cannot produce freeform output. Every verdict is validated against a strict schema: classification, confidence score, MITRE tactic mapping, and recommended action. All typed and enumerated. A response that doesn't conform to the schema is caught and handled before it reaches the analyst. Hunting queries are limited to verified table-column pairs; the model cannot reference tables that don't exist in the workspace.

**The human is the enforcement boundary.** The architecture makes autonomous closure structurally impossible, not just policy-prohibited. The pipeline suspends execution after posting the triage comment and will not resume without explicit analyst input. High-confidence verdicts do not bypass this gate. This is intentional: LLMs are probabilistic systems, and no confidence threshold justifies removing human judgment from a containment decision.

**Failures degrade gracefully, never silently.** If a threat intel API times out, the confidence score is reduced, not quietly marked benign. If the cloud API returns a conflict because an analyst manually updated the incident during processing, the pipeline raises a conflict error rather than overwriting the analyst's work.

## SOC Metrics This Addresses

| Metric | Impact |
|---|---|
| **Mean Time to Triage** | Enrichment, extraction, and classification run automatically. The triage report is waiting on the incident before a human opens the queue. |
| **Alert-to-Analyst Ratio** | High-confidence false positives are routed directly to writeback, removing them from the manual review queue entirely. |
| **True Positive Retention** | The human-in-the-loop gate ensures no real threat is closed without analyst sign-off, regardless of the AI's confidence. |
| **Mean Time to Contain** | Containment actions are pre-staged and execute immediately on analyst approval. No manual API interaction required. |
| **Classification Accuracy (over time)** | Every AI-analyst disagreement is stored and retrieved as a prior on future similar incidents. The system learns from its mistakes. |

## Full Technical Documentation

Implementation details, such as state graph design, async concurrency model, rate limiting, retry architecture, Pydantic schemas, ChromaDB RAG pipeline, ETag-based optimistic concurrency, and KQL hallucination mitigation, are documented in the repository.

→ [github.com/eabboa/sentinel-triage-agent](https://github.com/eabboa/sentinel-triage-agent)