# Phase 2A — Analysis Engine Design & Test Specification (Revised)

> **Project:** Sus — *"Sus? Now you'll know why."*  
> **Challenge:** SETU 2026 | Forge Realm — PS-01: Scam Spotter  
> **Phase:** 2A (Design and Test Plan Only — Pre-Implementation Gate)  
> **Date:** 2026-10-18  
> **Status:** REVISED & PENDING APPROVAL — Design-only task; zero application or test code modified.

---

## 1. Architectural Overview & Scope Boundaries

### 1.1 Guiding Principles
1. **Deterministic & Stateless:** A pure, side-effect-free function: `analyzeMessage(rawInput: string): AnalyzeResponse`. Zero external network calls, zero live URL fetching, zero threat intelligence APIs, zero database drivers, and zero AI/LLM models.
2. **ReDoS Immunity by Construction:** All regular expressions use atomic token matching, bounded character classes, and non-overlapping disjunctions. Nested quantifiers (such as `(a+)+`, `(.*)*`, or `(a|b+)*`) are strictly banned.
3. **Clause-Scoped Negation & Advisory Suppression:** Negation is scoped strictly to sentence/clause boundaries. Protective bank advisories (*"Never share your OTP"*) suppress credential theft flags only within their specific clause, while subsequent malicious solicitation in the same message is accurately detected.
4. **Heuristic Density Scoring (Non-Calibrated):** The composite score (0–100) measures heuristic signal density, **not** a calibrated statistical probability of fraud. All outputs explicitly declare their heuristic nature.
5. **Canonical UTF-16 Span Mapping:** All evidence offsets `[start, end]` are strictly defined as JavaScript UTF-16 code-unit indices relative to the unmodified input string, satisfying `0 <= start < end <= message.length` and `message.slice(start, end) === triggerText`.

### 1.2 Pipeline Architecture

```
Raw Unmodified Message Input (string)
              │
              ▼
[Stage 1: Validation & Bounded Sanitization]
              │  • Enforces 5 to 5,000 UTF-16 code units via Zod schema
              │  • Rejects empty strings, whitespace-only strings, non-strings
              │  • Preserves exact original string for index slicing
              ▼
[Stage 2: Clause Segmentation & Negation Pre-Scanner]
              │  • Segments text into clause spans by punctuation / line breaks
              │  • Identifies "Protective Advisory Zones" (e.g. "never share... OTP")
              │  • Records active suppression intervals: [start_clause, end_clause]
              ▼
[Stage 3: Multi-Category Rule Evaluator]
              │  • Evaluates 14 atomic, ReDoS-safe regex rules across 5 categories
              │  • If a match falls within an Advisory Suppression Zone, credential rule
              │    is suppressed and recorded as an educational benign finding
              │  • Extracts exact UTF-16 [start, end] slices from unmodified text
              ▼
[Stage 4: Mathematical Score Synthesis & Override Resolution]
              │  • De-duplicates multiple matches of the same rule (1 contribution per rule)
              │  • Applies category-level saturation caps
              │  • Sums category subtotals into composite score S ∈ [0, 100]
              │  • Evaluates explicit Critical Trigger Precedence overrides
              │  • Emits final risk classification: Low, Medium, or High
              ▼
[Stage 5: Actionable Guidance & Output Assembly]
              │  • Generates deterministic next steps mapped to triggered categories
              │  • Attaches cybercrime.gov.in guidance for Indian context
              │  • Populates in-memory metadata (execution time, heuristic disclaimer)
              ▼
Validated AnalyzeResponse
```

---

## 2. Negation, Context & Scope-Bounded Suppression

### 2.1 Clause-Scoped vs. Global Suppression
A major vulnerability in naive scam analyzers is global keyword suppression: if a message begins with a bank security warning (*"Never share your OTP with anyone"*), an attacker could prepend that phrase to bypass detection of an actual phishing link or credential demand.

Sus enforces **Sentence / Clause-Scoped Suppression**:
- **Clause Delimiters:** Sentence terminators (`.`, `!`, `?`, `\n`, `\r\n`), semicolons (`;`), and strong adversative conjunctions (`but`, `however`, `although`, `whereas`).
- **Suppression Zone:** When a protective pattern (`NEG-01` or `NEG-02`) matches, an Advisory Suppression Zone $[Z_{start}, Z_{end}]$ is created covering **only** the character indices of that specific clause.
- **Rule Interaction:** Any `CRED-*` (Credential Theft) match whose span $[M_{start}, M_{end}]$ falls entirely or partially inside $[Z_{start}, Z_{end}]$ is suppressed.
- **Out-of-Zone Execution:** Any `CRED-*` match outside $[Z_{start}, Z_{end}]$ executes normally and triggers alerts.

### 2.2 Quoted Text and Meta-Discussions
- When text appears inside quotation marks (`"..."`, `'...'`, `“...”`), the engine does not perform artificial semantic reasoning (since V1 has no LLM). 
- Patterns inside quotes are extracted with full transparency. The UI and explanation text explicitly note:
  *"Patterns detected. If this message is quoting a scam as a warning or news article, exercise independent judgment."*

### 2.3 The Core Contrast & Mixed Message Verification

| Case ID | Input Text | Segmentation & Processing | Findings & Classification |
| :--- | :--- | :--- | :--- |
| **Pure Warning** | `"Security Alert: Never share your OTP with anyone, including bank officials."` | Single clause $[0, 77]$. `NEG-01` matches. Suppression zone $[0, 77]$ active. `CRED-01` suppressed. | **Low Risk (Score: 0)**<br>Findings: 1 educational advisory (`security_advisory`). Zero credential alarms. |
| **Pure Phishing** | `"Dear customer, send us your OTP to verify your account immediately."` | Single clause. No negation. `CRED-01` matches `send us your OTP`. `URG-03` matches `immediately`. | **High Risk (Score: 50 $\rightarrow$ Critical Override)**<br>Findings: `CRED-01`, `URG-03`. Direct credential demand. |
| **Mixed Message (Warning + Scam)** | `"State Bank Alert: Never share your OTP with anyone. However, your KYC has expired, please send us your OTP to avoid card block."` | • Clause 1 $[0, 52]$: `NEG-01` active $\rightarrow$ suppression zone $[0, 52]$.<br>• Clause 2 $[53, 131]$: OUTSIDE zone. `CRED-01` matches `send us your OTP`. `URG-02` matches `card block`. | **High Risk (Score: 60 $\rightarrow$ High)**<br>Findings: Clause 1 flagged as advisory; Clause 2 flagged as high-severity `CRED-01` + `URG-02`. Message is **NOT** bypassed. |

---

## 3. Mathematical Scoring System & Risk Thresholds

### 3.1 Aggregation Algorithm & Duplicate Handling
To prevent repetitive keyword spamming from distorting scores, Sus enforces:
1. **Rule-Level De-duplication:** If a rule (e.g. `URG-03` "urgent") matches 4 times in a message, its weight $W_i$ is credited **only once**.
2. **Category Saturation Caps:** Each category has a maximum contribution cap $C_c$, preventing one category from dominating the score.
3. **Composite Score Formula:**

$$S = \min\left(100, \sum_{c \in \text{Categories}} \min\left(C_c, \sum_{i \in \text{UniqueTriggeredRules}_c} W_i\right)\right)$$

### 3.2 Category Weights & Caps Table

| Category | Category Cap $C_c$ | Rule ID | Rule Description | Weight $W_i$ | Severity |
| :--- | :---: | :--- | :--- | :---: | :---: |
| **Category 1: Credential Theft** | **45** | `CRED-01` | Direct OTP / PIN / Password solicitation | 35 | **High** |
| | | `CRED-02` | KYC / Aadhaar / PAN / Card CVV re-verification demand | 30 | **High** |
| | | `CRED-03` | Net-banking login credentials / secret code solicitation | 25 | **High** |
| **Category 2: Urgency Coercion** | **35** | `URG-01` | Utility disconnection / power blackout cutoff threat | 30 | **High** |
| | | `URG-02` | Account / SIM / Net-banking suspension countdown (<24h) | 25 | **High** |
| | | `URG-03` | Generic urgency keywords (urgent, immediately, act now) | 15 | **Medium** |
| **Category 3: Financial Pressure** | **30** | `FIN-01` | Utility bill unpaid dues demand | 20 | **Medium** |
| | | `FIN-02` | Unsolicited lottery, jackpot, or tax refund notification | 25 | **Medium** |
| | | `FIN-03` | Advance fee / processing fee transfer demand | 25 | **High** |
| **Category 4: Suspicious Links** | **35** | `LINK-01` | Public link shorteners (`bit.ly`, `tinyurl`, `t.co`, etc.) | 25 | **High** |
| | | `LINK-02` | Raw IP address hostnames in URLs | 30 | **High** |
| | | `LINK-03` | Deceptive subdomains / hyphenated brand mimics | 30 | **High** |
| | | `LINK-04` | Insecure HTTP for banking / verification action | 15 | **Medium** |
| **Category 5: Impersonation** | **30** | `IMP-01` | Persona paired with personal 10-digit mobile number | 25 | **High** |
| | | `IMP-02` | Unofficial mobile helpline masquerading as customer desk | 20 | **Medium** |

### 3.3 Resolution of Thresholds vs. Critical Overrides
The threshold ambiguity is strictly resolved by establishing an **Explicit Precedence Hierarchy**:

1. **Rule Precedence 1 (Advisory Suppression):** If a message contains ONLY `NEG-*` advisory matches and no out-of-zone scam matches, Risk Level is **Low** (Score = 0).
2. **Rule Precedence 2 (Critical Dual-Trigger Overrides):** Regardless of composite score, if either of the following high-lethal combinations is detected, the message is elevated to **High Risk** and the score is floored at **75**:
   - **Override A (Credential Phishing):** Any active `CRED-*` rule **AND** any active `URG-*` rule.
   - **Override B (Utility Cutoff Scam):** `URG-01` (power disconnection) **AND** (`LINK-01` OR `LINK-03` OR `IMP-01`).
   - **Override C (Advance Fee Fraud):** `FIN-02` (lottery/prize) **AND** `FIN-03` (processing fee demand).
3. **Rule Precedence 3 (Score-Based Classification):** If no Critical Override applies:
   - **Low Risk:** Score $0 \le S \le 24$ (No patterns or isolated weak signals).
   - **Medium Risk:** Score $25 \le S \le 54$ (Moderate signals: e.g. urgency + bill dues, or unverified link alone).
   - **High Risk:** Score $S \ge 55$ (Cumulative score from multiple categories).

### 3.4 Worked Scoring Examples

#### Worked Example 1: Benign Bank Credit Alert (Low Risk)
- **Input:** `"Your account 1234 credited with INR 5,000 on 17-Oct. Available balance: INR 24,500. - HDFC Bank"`
- **Triggers:** None.
- **Score:** 0 $\rightarrow$ **Low Risk**.

#### Worked Example 2: E-Commerce Flash Sale (Low Risk)
- **Input:** `"Hurry! Act now, limited time offer. Flat 50% discount on shoes today only."`
- **Triggers:** `URG-03` (Urgency: 15).
- **Category Cap:** Urgency cap = 35; credited = 15.
- **Score:** 15 $\rightarrow$ **Low Risk** (No financial demand, no link, no credentials).

#### Worked Example 3: Unverified Link Reminder (Medium Risk)
- **Input:** `"Please review your electricity bill dues before the due date at http://state-power.org"`
- **Triggers:** `FIN-01` (Bill dues: 20), `LINK-04` (Insecure HTTP: 15).
- **Score:** $20 + 15 = 35$ $\rightarrow$ **Medium Risk** (Exercise caution; no threats or credentials).

#### Worked Example 4: Bank KYC Phishing (High Risk via Override A)
- **Input:** `"Dear SBI customer, your net banking access will be suspended within 24 hours. Re-verify your Aadhaar and PAN card at https://sbi-kyc-verify-portal.in"`
- **Triggers:** `CRED-02` (30), `URG-02` (25), `LINK-03` (30).
- **Calculation:** Category Credential (30) + Urgency (25) + Link (30) = 85. Also satisfies Override A (`CRED-02` + `URG-02`).
- **Score:** 85 $\rightarrow$ **High Risk**.

#### Worked Example 5: Electricity Shutoff Scam (High Risk via Override B)
- **Input:** `"URGENT: Power will be disconnected tonight at 9:30 PM. Call verification officer at 98765-43210 or visit http://bit.ly/power-bill"`
- **Triggers:** `URG-01` (30), `IMP-01` (25), `LINK-01` (25).
- **Calculation:** Satisfies Override B (`URG-01` + `IMP-01` + `LINK-01`).
- **Score:** 80 $\rightarrow$ **High Risk**.

---

## 4. Detection Rule Catalog (Positive & Negative Examples)

Every regex rule is defined below with its exact positive match example and negative non-match example:

### `NEG-01` — Bank Advisory Negation
- **Regex:** `\b(?:never|do\s+not|don'?t|should\s+never|will\s+never)\s+(?:share|disclose|give|send|tell|reveal)\b[^.!?;\n]*\b(?:otp|pin|password|cvv|credentials?)\b`
- **Positive Example:** `"Never share your OTP with anyone."` $\rightarrow$ Matches; creates suppression zone.
- **Negative Example:** `"Send us your OTP immediately."` $\rightarrow$ No negation keyword; does not match.

### `CRED-01` — Direct OTP / PIN Solicitation
- **Regex:** `\b(?:send|share|enter|provide|verify|tell|forward)\s+(?:us\s+|me\s+|your\s+)?(?:the\s+)?\b(?:otp|one[- ]time[- ]password|pin|secret\s+code)\b`
- **Positive Example:** `"Please send us your OTP to complete verification."` $\rightarrow$ Matches `CRED-01`.
- **Negative Example:** `"Your OTP is 492810. Valid for 10 minutes."` $\rightarrow$ No solicitation verb; does not match.

### `CRED-02` — Identity & Card Detail Solicitation
- **Regex:** `\b(?:update|verify|re-?verify|submit)\b[^.!?;\n]*\b(?:aadhaar|pan\s+card|pan\s+number|debit\s+card|credit\s+card|cvv)\b`
- **Positive Example:** `"Re-verify your Aadhaar and PAN card details today."` $\rightarrow$ Matches `CRED-02`.
- **Negative Example:** `"PAN card linked successfully to your account."` $\rightarrow$ No solicitation verb; does not match.

### `URG-01` — Utility Shutoff / Blackout Threat
- **Regex:** `\b(?:power|electricity|connection)\b[^.!?;\n]*\b(?:disconnect(?:ed)?|cut[- ]off|blackout)\s+(?:tonight|today|within\s+\d+\s+hours?|immediately)\b`
- **Positive Example:** `"Electricity connection will be disconnected tonight at 9:30 PM."` $\rightarrow$ Matches `URG-01`.
- **Negative Example:** `"Power outage scheduled tomorrow from 2 PM to 4 PM for maintenance."` $\rightarrow$ Informational notice; does not match.

### `URG-02` — Account / Service Suspension Countdown
- **Regex:** `\b(?:account|card|sim|access)\s+(?:will\s+be\s+|has\s+been\s+)?(?:blocked|suspended|terminated|deactivated)\s+(?:within|in)\s+\d+\s+(?:hours?|minutes?|days?)\b`
- **Positive Example:** `"Your SIM card will be deactivated in 24 hours."` $\rightarrow$ Matches `URG-02`.
- **Negative Example:** `"Your subscription was renewed for 30 days."` $\rightarrow$ Does not match.

### `URG-03` — Generic Urgency Cues
- **Regex:** `\b(?:urgent|immediately|act\s+now|last\s+chance|final\s+notice|time\s+sensitive)\b`
- **Positive Example:** `"Final notice: Action required immediately."` $\rightarrow$ Matches `URG-03`.
- **Negative Example:** `"We will review your feedback shortly."` $\rightarrow$ Does not match.

### `FIN-01` — Unpaid Bill Dues Coercion
- **Regex:** `\b(?:unpaid|previous\s+month|pending)\s+(?:bill|electricity\s+bill|dues)\b[^.!?;\n]*\b(?:pay|update|settle|clear)\b`
- **Positive Example:** `"Your previous month electricity bill is unpaid, pay immediately."` $\rightarrow$ Matches `FIN-01`.
- **Negative Example:** `"Your monthly bill of Rs 450 has been paid."` $\rightarrow$ Does not match.

### `FIN-02` — Lottery / Jackpot / Prize Lure
- **Regex:** `\b(?:won|credited|lottery|cashback|reward|tax\s+refund)\b[^.!?;\n]*\b(?:rs\.?|inr|₹|\$)\s*[\d,]+\b`
- **Positive Example:** `"Congratulations you won lottery Rs. 25,00,000 claim now."` $\rightarrow$ Matches `FIN-02`.
- **Negative Example:** `"Your refund of Rs. 150 has been processed to your bank."` $\rightarrow$ Does not match.

### `FIN-03` — Advance Fee Transfer Demand
- **Regex:** `\b(?:send|transfer|deposit|pay)\s+(?:processing\s+fee|token\s+amount|advance|clearance\s+charge)\b`
- **Positive Example:** `"Transfer processing fee Rs 500 to release funds."` $\rightarrow$ Matches `FIN-03`.
- **Negative Example:** `"No processing fee charged for this loan."` $\rightarrow$ Does not match.

### `LINK-01` — Link Shorteners
- **Regex:** `https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9_-]+`
- **Positive Example:** `"http://bit.ly/power-bill-update"` $\rightarrow$ Matches `LINK-01`.
- **Negative Example:** `"https://www.tatapower.com/bill-payment"` $\rightarrow$ Does not match.

### `LINK-02` — Raw IP Address Hostnames
- **Regex:** `https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s]*)?`
- **Positive Example:** `"http://192.168.1.50:8080/sbi"` $\rightarrow$ Matches `LINK-02`.
- **Negative Example:** `"https://100xdevs.com"` $\rightarrow$ Does not match.

### `LINK-03` — Deceptive Brand Domain Mimics
- **Regex:** `https?:\/\/(?=[a-zA-Z0-9.-]*-(?:kyc|bank|support|verify|bill|login))[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?`
- **Positive Example:** `"https://sbi-kyc-verify-portal.in"` $\rightarrow$ Matches `LINK-03`.
- **Negative Example:** `"https://onlinesbi.sbi"` $\rightarrow$ Official structure; does not match.

### `IMP-01` — Persona with Personal 10-Digit Mobile Number
- **Regex:** `\b(?:contact|call|whatsapp|reach)\s+(?:our\s+)?(?:officer|executive|manager|agent)\s+(?:at\s+|on\s+)?(?:[+]?91[- ]?)?[6-9]\d{4}[- ]?\d{5}\b`
- **Positive Example:** `"Contact verification officer at 98765-43210"` $\rightarrow$ Matches `IMP-01`.
- **Negative Example:** `"Contact our toll-free customer care at 1800-11-2211"` $\rightarrow$ Toll-free line; does not match.

---

## 5. Input and Output Contracts

### 5.1 Preservation of Unmodified Original String
- The engine receives `rawMessage: string` and preserves it strictly unmodified.
- Normalization (e.g. `toLowerCase()`) is performed **only** on cloned internal tokens for pattern matching; all character index offsets `[start, end]` are computed against the original string.
- All span offsets are strictly **JavaScript UTF-16 code units**, matching standard JavaScript string operations (`rawMessage.slice(start, end)`).

### 5.2 Scope & Ephemerality of Identifiers
- `id`: Generated per-run via `crypto.randomUUID()`. It is an ephemeral session identifier for React key bindings and accessibility announcements. **Zero database persistence or disk storage is involved.**
- `timestamp`: Generated per-run via `new Date().toISOString()`.

### 5.3 Zod Input Contract (`lib/schemas.ts`)

```typescript
import { z } from "zod";

export const AnalyzeRequestSchema = z.object({
  message: z
    .string({ required_error: "Message is required." })
    .trim()
    .min(5, "Message must contain at least 5 characters.")
    .max(5000, "Message exceeds the maximum limit of 5,000 characters.")
    .refine((val) => val.trim().length > 0, {
      message: "Message cannot consist solely of whitespace.",
    }),
});

export type AnalyzeRequest = z.infer<typeof AnalyzeRequestSchema>;
```

### 5.4 Zod Output Contract (`lib/schemas.ts`)

```typescript
export const RiskLevelSchema = z.enum(["low", "medium", "high"]);

export const SignalCategorySchema = z.enum([
  "credential_theft",
  "urgency_coercion",
  "financial_pressure",
  "suspicious_link",
  "impersonation",
  "security_advisory",
]);

export const EvidenceSpanSchema = z.object({
  start: z.number().int().nonnegative(),
  end: z.number().int().nonnegative(),
  text: z.string().min(1),
});

export const SignalFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  category: SignalCategorySchema,
  title: z.string(),
  description: z.string(),
  severity: z.enum(["low", "medium", "high"]),
  span: EvidenceSpanSchema,
});

export const NextStepItemSchema = z.object({
  id: z.string(),
  text: z.string(),
  actionUrl: z.string().url().optional(),
  actionLabel: z.string().optional(),
});

export const AnalyzeResponseSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string(),
  riskLevel: RiskLevelSchema,
  heuristicScore: z.number().int().min(0).max(100),
  summary: z.string(),
  findings: z.array(SignalFindingSchema),
  recommendedSteps: z.array(NextStepItemSchema),
  metadata: z.object({
    charCount: z.number().int().min(5).max(5000),
    executionTimeMs: z.number().nonnegative(),
    isHeuristic: z.literal(true),
  }),
});

export type AnalyzeResponse = z.infer<typeof AnalyzeResponseSchema>;

export const ErrorResponseSchema = z.object({
  error: z.object({
    code: z.enum(["INVALID_INPUT", "OVER_LENGTH", "INTERNAL_ERROR"]),
    message: z.string(),
    details: z.unknown().optional(),
  }),
});

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
```

### 5.5 Invariant Assertions
The engine asserts two mathematical invariants on every output before returning:
1. `0 <= finding.span.start < finding.span.end <= rawMessage.length`
2. `rawMessage.slice(finding.span.start, finding.span.end) === finding.span.text`

---

## 6. Performance, ReDoS Immunity & Security

### 6.1 Catastrophic Backtracking Prevention
1. **No Nested Repetition:** Patterns like `(a+)+`, `(a|b+)*`, or `.*.*` are strictly prohibited.
2. **Bounded Non-Greedy Quantifiers:** Any wildcard matching within a clause uses `[^.!?;\n]*?` with a hard clause-length upper bound.
3. **No Unanchored Open Lookarounds:** The domain pattern `LINK-03` uses a lookahead anchored directly to `https?:\/\/`.

### 6.2 Deterministic Pathological Testing Strategy
Rather than relying on brittle, environment-dependent wall-clock timers:
1. **Adversarial Corpus Stress Test:**
   - 4,000 repeats of `"urgent urgent urgent "` with no terminal punctuation.
   - 4,000 repeats of `"power power power "` followed by a non-matching word.
   - 4,000 repeats of `"https://sbi-sbi-sbi-sbi..."` with no TLD.
2. **Linearity Assertion:** The test suite verifies that execution time scales linearly $O(n)$, completing within an in-memory budget of < 50ms on standard test workers.
3. **Regex Static Lint:** Unit tests verify that every compiled regex has zero nested quantifier AST nodes.

---

## 7. Expanded Regression Test Plan (26 Concrete Test Cases)

| Test ID | Category / Goal | Input Message Text | Expected Result | Expected Finding / Trigger Detail |
| :--- | :--- | :--- | :---: | :--- |
| `TC-01` | **Pure Warning** | `"State Bank Security: Never share your OTP with anyone."` | **Low** (Score: 0) | `NEG-01` triggers `security_advisory`. Zero `CRED-*` alarms. |
| `TC-02` | **Pure Phishing** | `"Send us your OTP to verify your account and unlock your card."` | **High** (Score: $\ge 55$) | `CRED-01` triggers, quoting `"Send us your OTP"`. |
| `TC-03` | **Mixed (Warning + Scam)** | `"Bank alert: Never share your OTP. But your KYC is expired, please send us your OTP now."` | **High** (Score: $\ge 55$) | Clause 1 suppressed; Clause 2 triggers `CRED-01` + `URG-03`. |
| `TC-04` | **Cautionary Advisory** | `"Caution: do not share your OTP or password with unauthorized callers."` | **Low** (Score: 0) | `NEG-02` active. Credentials suppressed. |
| `TC-05` | **Electricity Cutoff Full** | `"URGENT: Power connection will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer at 98765-43210 or visit http://bit.ly/power-bill"` | **High** (Score: $\ge 75$) | Triggers `URG-01`, `IMP-01`, `LINK-01`, `FIN-01`. Override B applied. |
| `TC-06` | **Bank KYC Suspension** | `"Dear customer, your net banking access will be suspended within 24 hours. Re-verify your Aadhaar and PAN card at https://sbi-kyc-verify-portal.in"` | **High** (Score: $\ge 75$) | Triggers `CRED-02`, `URG-02`, `LINK-03`. Override A applied. |
| `TC-07` | **Lottery Advance Fee** | `"Congratulations you won lottery Rs. 25,00,000! Transfer advance processing fee Rs 1,000 to release prize."` | **High** (Score: $\ge 75$) | Triggers `FIN-02`, `FIN-03`. Override C applied. |
| `TC-08` | **Benign Meeting** | `"Hey Atharva, are we meeting for lunch at 1:30 PM tomorrow at the office cafe?"` | **Low** (Score: 0) | Zero triggers. |
| `TC-09` | **Benign Bank Balance** | `"Your a/c 1234 credited with INR 5,000 on 17-Oct. Available balance: INR 24,500. - HDFC Bank"` | **Low** (Score: 0) | Zero triggers. No call to action. |
| `TC-10` | **Benign Appointment** | `"Reminder: You have an appointment with Dr. Sharma tomorrow at 10 AM. Reschedule: 011-23456789."` | **Low** (Score: 0) | Landline; no mobile impersonation or coercion. |
| `TC-11` | **Benign E-commerce** | `"Hurry! Flash sale ends today. Get 50% discount on shoes at https://myntra.com"` | **Low** (Score: 15) | `URG-03` (15). Stays Low (<25). Legitimate domain. |
| `TC-12` | **Unverified Link Only** | `"Please review your electricity bill dues before the due date at http://state-power.org"` | **Medium** (Score: 35) | `FIN-01` (20) + `LINK-04` (15) = 35. |
| `TC-13` | **Duplicate Signal Spam** | `"URGENT! URGENT! Please act immediately, this is urgent!"` | **Low** (Score: 15) | `URG-03` deduped to single 15-point credit. |
| `TC-14` | **Raw IP Address Phishing** | `"Verify your login credentials at http://192.168.1.100/login"` | **High** (Score: $\ge 55$) | `CRED-03` (25) + `LINK-02` (30) = 55. |
| `TC-15` | **Unicode & Emojis** | `"URGENT 🚨 electricity blackout tonight ⚡ call 98765-43210"` | **High** (Score: $\ge 55$) | `URG-01` + `IMP-01`. UTF-16 span offsets accurately highlight text around emojis. |
| `TC-16` | **Quoted Scam in Article** | `"Security news: Scammers are sending 'Your electricity will be disconnected tonight'."` | **Medium** (Score: 30) | Detects `URG-01`. Surfaces trigger with contextual quotation disclaimer. |
| `TC-17` | **Boundary: Min (5 chars)** | `"Hello"` | **Low** (Score: 0) | Passes Zod validation. Zero findings. |
| `TC-18` | **Boundary: Max (5,000 chars)** | Long legitimate email excerpt (exactly 5,000 characters) | **Low** (Score: 0) | Processes in < 25ms. Validates span bounds. |
| `TC-19` | **Error: Under Min (< 5)** | `"Hi"` | **Error (400)** | Zod validation error: min length 5. |
| `TC-20` | **Error: Over Max (5,001)** | 5,001 characters string | **Error (400)** | Zod validation error: max length 5,000. |
| `TC-21` | **Error: Empty String** | `""` | **Error (400)** | Zod validation error. |
| `TC-22` | **Error: Whitespace Only** | `"   \t\n\r\n   "` | **Error (400)** | Zod validation error: whitespace-only rejected. |
| `TC-23` | **ReDoS Stress: Urgency** | `"urgent "` repeated 1,000 times + `"end"` | **Low** (Score: 15) | Completes in < 30ms. Zero CPU lockup. |
| `TC-24` | **ReDoS Stress: Links** | `"https://sbi-"` repeated 500 times | **Low** (Score: 0) | Completes in < 30ms. Zero backtracking hang. |
| `TC-25` | **Span Slicing Invariant** | Mixed message with multiple triggers | **PASS** | `rawMessage.slice(start, end) === text` verified for every finding. |
| `TC-26` | **Toll-Free Safe Channel** | `"Contact customer care at 1800-11-2211"` | **Low** (Score: 0) | `IMP-01` negative test (toll-free lines do not trigger personal mobile alert). |

---

## 8. Exact Files to Create in Phase 2B

| Target File | Role & Contents |
| :--- | :--- |
| `lib/analyzer/constants.ts` | Rule weights, category caps, override rules, threshold ranges, cybercrime URL. |
| `lib/analyzer/types.ts` | Internal engine interfaces: `RuleDefinition`, `ClauseSpan`, `AdvisoryZone`. |
| `lib/analyzer/rules.ts` | 14 atomic ReDoS-safe regex rule definitions + clause/negation scanner. |
| `lib/analyzer/engine.ts` | Pure function orchestrator: `analyzeMessage(rawInput: string): AnalyzeResponse`. |
| `lib/schemas.ts` | Zod validation schemas for `AnalyzeRequest`, `AnalyzeResponse`, and `ErrorResponse`. |
| `__tests__/lib/analyzer/rules.test.ts` | Unit tests for every rule ID (positive and negative pair verification). |
| `__tests__/lib/analyzer/engine.test.ts` | Comprehensive integration tests executing all 26 test cases. |
| `__tests__/lib/analyzer/redos.test.ts` | Adversarial input stress tests verifying linear execution and ReDoS immunity. |

> **UI Stability Guarantee:** `components/`, `app/page.tsx`, and `lib/mock-data.ts` will **not** be modified during Phase 2B. The engine will be developed and tested in total isolation first.

---

## 9. Status & Release Gate

- **Phase 2A Status:** **REVISED & FULLY SPECIFIED**.
- **Code Changes Made:** **ZERO** (Only this specification document was updated).
- **Phase 2B Implementation Status:** **PAUSED — Awaiting explicit user sign-off.**
