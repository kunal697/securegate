# SecureGate System Design & Implementation

## Overview

**SecureGate** is an intermediary security layer designed to sit between users and Generative AI models. Its primary function is to detect, analyze, and prevent sensitive data leakage during real-time interactions with AI services. 

SecureGate acts as a safeguard that ensures prompts containing Personally Identifiable Information (PII), credentials, health information, financial data, or malicious prompt injections are intercepted and appropriately handled (blocked, masked, or quarantined) before reaching external AI APIs like OpenAI, Anthropic, or Google Gemini.

---

## 1. Core Architecture

The architecture of SecureGate is designed for speed, flexibility, and extensibility. It utilizes an **API Gateway / Proxy** model, where all AI interactions pass through the SecureGate pipeline.

### High-Level Data Flow

1. **Input Reception:** 
   - A user's prompt is captured via the SecureGate REST API (e.g., `/analyze`, `/chat`) or seamlessly intercepted using the System-Wide MITM Proxy.
2. **Pre-processing:**
   - The text undergoes sanitization and trimming via the `preprocessor` to remove noise and ensure consistent analysis.
3. **Parallel Detection Pipeline:**
   - The pre-processed text is sent to multiple specialized detection modules running concurrently (using a `ThreadPoolExecutor` with parallel workers).
4. **Decision Engine:**
   - Results from all detectors are aggregated. A policy-driven engine evaluates the scores against configured category thresholds to determine the final action.
5. **Action Enforcement:**
   - **Allow:** The request is safe and proceeds unmodified.
   - **Mask:** Sensitive entities are redacted and replaced with placeholders (e.g., `[REDACTED_CREDIT_CARD]`).
   - **Block:** The request is rejected outright (returning a 403 error).
   - **Quarantine:** Held for review (specifically targeted for source code or health info).
6. **Audit & Explainability:**
   - Detailed, PII-redacted audit logs and reasoning are generated for tracking and analytics.

---

## 2. Detection Methodologies (What We Have Built)

We have implemented a **Hybrid Detection Framework** featuring five independent analyzers that operate in parallel.

| Detector | Methodology | Description |
|----------|-------------|-------------|
| **Pattern Detector** | Regex & Rule-based | Fast, high-confidence matching for structured data like Credentials, API keys, SSNs, Credit Cards, IBANs, Emails, and Phone numbers. |
| **Prompt Injection** | Heuristics | Rule-based engine identifying adversarial attempts to bypass AI instructions (e.g., "ignore previous instructions", roleplay jailbreaks). |
| **NER Detector** | NLP (Presidio/spaCy) | Uses local Named Entity Recognition models to find unstructured PII (Persons, Emails, Phones, etc.). Supports lightweight (`sm`) or robust (`lg`) models. |
| **Semantic Analyzer**| Vector Embeddings | Uses `sentence-transformers` to match the semantic intent of a prompt against predefined sensitive templates (e.g., phrases indicating health disclosures). |
| **LLM Classifier** | Zero-Shot Classification | Uses Hugging Face's BART-MNLI model running locally to holistically categorize the prompt's sensitivity without relying on third-party cloud APIs. |

> **Note:** All machine learning detectors (NER, Semantic, LLM Classifier) run strictly locally. No user prompts are sent to external services for classification, ensuring privacy.

---

## 3. Decision Engine & Policies

The `decision_engine` resolves conflicting or complementary signals from the detectors based on predefined **Policies**.

### Category & Action Mapping
Sensitivities are classified into priority categories with default enforcement actions:
1. `CREDENTIALS` ➔ **Block**
2. `HEALTH_INFO` ➔ **Block** / **Quarantine**
3. `FINANCIAL_DATA` ➔ **Mask**
4. `PERSONAL_INFO` ➔ **Mask**
5. `SOURCE_CODE` ➔ **Block** / **Quarantine**

### Thresholds and Scoring
Each category has an associated minimum confidence threshold (e.g., 0.70 for Personal Info, 0.75 for Source Code). If any detector scores a category at or above its threshold, the corresponding action is triggered.

---

## 4. Interfaces and Integration

SecureGate provides multiple integration points depending on the deployment use case.

### 4.1 RESTful API
A FastAPI application offering programmatic access:
- `POST /analyze`: Evaluates text and returns the detection results and required action.
- `POST /analyze/text`: Convenience endpoint for raw text payloads.
- `GET /dashboard`, `/api/stats`, `/api/events`: Analytics and audit visualization.

### 4.2 Built-in LLM Chat Proxy
A `/chat` endpoint that acts as a wrapper around cloud LLMs (Gemini, OpenAI, or Self-hosted). It seamlessly analyzes the user's prompt, masks any identified sensitive data, forwards the sanitized prompt to the LLM backend, and returns the response.

### 4.3 System-Wide MITM Proxy
A `mitmproxy` addon that transparently intercepts HTTPS traffic directed at protected AI domains (e.g., `api.openai.com`, `generativelanguage.googleapis.com`). 
- Extracts the prompt from vendor-specific payload structures (`prompt_extractors.py`).
- Routes it to the SecureGate core for analysis.
- Dynamically rewrites the outgoing request (Masking) or drops the request entirely (Blocking) at the network level.

---

## 5. Technical Stack

- **Core Framework:** Python 3.x, FastAPI, Uvicorn, Pydantic.
- **NLP & ML:** spaCy, Presidio-Analyzer, SentenceTransformers, Hugging Face Transformers (`BART-MNLI`), PyTorch.
- **Proxy/Network:** `mitmproxy`, Requests.
- **Concurrency:** `asyncio`, `ThreadPoolExecutor`.

## 6. Current Implementation Status

As outlined in our `GAP_ANALYSIS_AND_ROADMAP.md`:
- **Fully Implemented:** The core pre-processing, parallel pipeline, all 5 detection modules, decision scoring, entity masking, MITM proxy request interception, and API analytics dashboard.
- **Next Steps (Roadmap):** Extending the MITM proxy to support strict *Quarantine* handling, adding output monitoring (analyzing the AI's response back to the user), and implementing dynamic policy loading from configuration files.
