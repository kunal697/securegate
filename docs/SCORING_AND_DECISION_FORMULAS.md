# SecureGate: scoring and decision formulas

This document describes how **per-detector confidence** is produced, how scores are **aggregated per sensitivity category**, and how the **final action** (Allow / Mask / Block) is chosen.

Implementation references:

- `src/securegate/decision_engine.py` — aggregation and policy decision
- `src/securegate/pipeline.py` — runs detectors, then `aggregate_results` → `decide` → optional masking

---

## 1. Notation

| Symbol | Meaning |
|--------|--------|
| \(T\) | Input text after preprocessing (`preprocess(T)` in the pipeline). |
| \(d \in \mathcal{D}\) | A detector instance (pattern, ner, gliner, semantic, llm_classifier, prompt_injection, …). |
| \(c \in \mathcal{C}\) | A `SensitivityCategory` (e.g. Credentials, Personal_Info, Safe). |
| \(\text{conf}_d\) | Detector-level **confidence** in \([0, 1]\) (see §2). |
| \(c_d\) | Category reported by detector \(d\) for that run (single top category per detector). |
| \(S(c)\) | **Aggregated score** for category \(c\) after combining all detectors (§3). |
| \(\tau(c)\) | Threshold for category \(c\) (defaults in `DEFAULT_THRESHOLDS`). |

Detectors that do not fire return `detected = false` and are skipped in aggregation (or contribute no non-SAFE category).

---

## 2. Per-detector confidence \(\text{conf}_d\)

Each detector returns one `DetectionResult` with a single pair \((c_d, \text{conf}_d)\) (plus entities where applicable). **Confidence is always on a 0–1 scale** (or 0 if not detected).

### 2.1 Pattern (`pattern`)

For each regex match \(m\) with fixed weight \(w_m \in [0,1]\) tied to that rule:

\[
\text{conf}_d = \max_{m} w_m, \quad c_d = \arg\max_{m} w_m \text{ (category of that rule)}.
\]

If no match: \(\text{conf}_d = 0\), \(c_d = \text{Safe}\).

### 2.2 NER — Presidio (`ner`)

Presidio spans with `score < 0.7` are dropped. For remaining spans, entity score is Presidio’s `score`. Credential regexes add fixed-confidence entities (e.g. \(0.90\)).

\[
\text{conf}_d = \max_i \text{score}_i, \quad c_d \text{ is the category of the span achieving that max}.
\]

If no entities: \(\text{conf}_d = 0\), Safe.

### 2.3 GLiNER (`gliner`)

Model returns entities with model scores \(s_i\). Each span maps to a category via `LABEL_TO_CATEGORY` (unknown label → Personal_Info).

\[
\text{conf}_d = \max_i s_i, \quad c_d \text{ = category of the span with } \max_i s_i.
\]

Filtering: GLiNER’s own `threshold` (`SECUREGATE_GLINER_THRESHOLD`, default `0.5`) is applied inside `predict_entities`; only returned spans are considered.

If no entities: \(\text{conf}_d = 0\), Safe.

### 2.4 Semantic (`semantic`)

Let \(q\) be the embedding of the truncated query text (first 512 chars), and \(t_j\) embeddings of template phrases, each labeled with a category \(c_j\). Cosine similarity:

\[
\text{sim}(q, t_j) = \frac{q \cdot t_j}{\|q\| \, \|t_j\|}.
\]

Let \(s = \max_j \text{sim}(q, t_j)\). Default template gate: \(\theta = 0.78\) (`SemanticAnalyzer.threshold`).

\[
\text{conf}_d = \text{round}(s, 2), \quad
\text{detected} = \mathbb{1}[s \ge \theta].
\]

If not detected, category is Safe; if detected, category follows the implementation’s tracking of the best-matching template (see `semantic.py`).

### 2.5 LLM classifier (`llm_classifier`)

**Local (BART-MNLI):** zero-shot scores over fixed labels; top label \(\ell\) with score \(s_0\). `min_score` default \(0.75\).

\[
\text{detected} = \mathbb{1}[\ell \neq \text{safe} \land s_0 \ge \text{min\_score}], \quad
\text{conf}_d = s_0 \text{ when detected}.
\]

**Remote (Gemini / self-hosted):** same idea: use returned label and confidence with the same safe / min-score gate.

### 2.6 Prompt injection (`prompt_injection`)

Each matched pattern has a fixed weight \(w_k\). Injection hits are mapped to category **Credentials** for policy purposes.

\[
\text{conf}_d = \max_{k:\,\text{pattern }k\text{ matches}} w_k.
\]

---

## 3. Aggregation: category scores \(S(c)\)

For each detector result \(r\) (with `detected == true` and `category ∉ {Safe, ∅}`):

- Let \(c = r.\text{category}\), \(s = r.\text{confidence}\).

**Current implementation (max per category, no detector weights):**

\[
S(c) = \max \{\, r.\text{confidence} : r.\text{detected} \land r.\text{category} = c \,\}.
\]

If no detector reports category \(c\), treat \(S(c) = 0\) (implicit via `.get(c, 0.0)` in `decide`).

`DEFAULT_WEIGHTS` in `decision_engine.py` (pattern, ner, gliner, …) is **reserved**; it is not multiplied into \(S(c)\) today. Future versions may use a weighted form, e.g. \(S(c) = \max_r w_{r.\text{detector}} \cdot r.\text{confidence}\).

---

## 4. Decision: action from \(S(c)\) and priority

Default thresholds \(\tau(c)\) (`DEFAULT_THRESHOLDS`):

| Category | Default \(\tau(c)\) |
|----------|---------------------|
| Credentials, Health_Info, Financial_Data, Personal_Info | \(0.70\) |
| Source_Code | \(0.75\) |

**Category priority** (first hit wins):  
Credentials → Health_Info → Financial_Data → Personal_Info → Source_Code.

For each \(c\) in that order:

\[
\text{if } S(c) \ge \tau(c) \text{ then return } \bigl(\text{action}(c),\, c,\, S(c)\bigr)
\]

where `action(c)` comes from `DEFAULT_ACTIONS` or `Policy.category_actions` (e.g. Credentials → Block, Personal_Info → Mask).

If no category satisfies \(S(c) \ge \tau(c)\):

\[
\text{return } (\text{Allow},\, \text{Safe},\, 0.0).
\]

The string **reasoning** attached to the result is human-readable, e.g.  
`"{category} detected (score={S(c):.2f} >= {τ}) -> {Action}"`.

---

## 5. Final API score: `sensitivity_score`

In `Pipeline.analyze`, the `AnalysisResult.sensitivity_score` is the **\(S(c)\) of the winning category** from `decide` (or `0.0` on Allow/Safe).

It is **not** a sum of all detectors; it is the aggregated score for the category that determined the outcome.

---

## 6. Masking (brief)

When the decision is **Mask** and there are merged entities, `mask_text(text, entities)` builds `masked_text`. Masking does not change \(S(c)\); it only affects the outbound text.

---

## 7. Summary formula chain

1. Each detector \(d\): compute \((c_d, \text{conf}_d)\) as in §2.  
2. Aggregate: \(S(c) = \max\{\text{conf}_d : c_d = c\}\) (§3).  
3. Decide: walk priority; first \(c\) with \(S(c) \ge \tau(c)\) picks action (§4).  
4. Expose `sensitivity_score = S(c_\text{winner})` or \(0\) if Allow (§5).

---

## 8. Tunable parameters (quick reference)

| Parameter | Where | Effect |
|-----------|--------|--------|
| `DEFAULT_THRESHOLDS` / `Policy.thresholds` | `decision_engine.py` | How high \(S(c)\) must be to trigger that category. |
| `DEFAULT_ACTIONS` / `Policy.category_actions` | `decision_engine.py` | Allow / Mask / Block per category. |
| `SECUREGATE_GLINER_THRESHOLD` | env | GLiNER entity cutoff. |
| `SemanticAnalyzer.threshold` | ctor / default `0.78` | Minimum cosine for semantic “detected”. |
| `LLMClassifier.min_score` | default `0.75` | Minimum top label score for LLM classifier. |
| NER span filter | `ner.py` (`score < 0.7`) | Drops low-confidence Presidio spans. |

For questions or proposed changes (e.g. using `DEFAULT_WEIGHTS` in §3), see `GAP_ANALYSIS_AND_ROADMAP.md`.
