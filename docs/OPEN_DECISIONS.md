# Open Decisions — Sus V1

> **Created:** 2026-10-17  
> **Status:** Requires resolution before or during implementation  
> **Convention:** Each decision is numbered. Mark as `✅ RESOLVED` with the chosen option when decided.

---

## OD-01: Tailwind CSS Version

**Context:** Tailwind CSS v4 (released 2025) uses a fundamentally different configuration approach — CSS-first config with `@theme` instead of `tailwind.config.ts`, and `@tailwindcss/postcss` instead of the old PostCSS plugin. Tailwind v3 uses the legacy `tailwind.config.ts` approach.

**Options:**
1. **Tailwind v4** — CSS-first configuration, `@theme` directive, `@tailwindcss/postcss` plugin. Smaller bundle, modern approach, but newer and less ecosystem support.
2. **Tailwind v3** — Established ecosystem, extensive documentation, `tailwind.config.ts` approach. More tutorials and community answers available.

**Recommendation:** Tailwind v4 if `create-next-app` ships it by default. Tailwind v3 if stability is prioritized. Verify during Phase 1.

**Impact:** Phase 1 — configuration file names and design token approach differ significantly.

**Status:** ✅ RESOLVED (2026-10-18) — Option 1: Tailwind CSS v4 with CSS-first `@theme` configuration in `app/globals.css`. Turbopack integrated seamlessly.

---

## OD-02: Analysis Engine — Rule Architecture

**Context:** The deterministic engine needs a system for defining, running, and scoring detection rules.

**Options:**
1. **Weighted scoring** — Each rule returns a numeric score (0–1). Sum all scores, map to thresholds for Low/Medium/High. Allows fine-grained tuning.
2. **Signal counting** — Each rule returns a signal (present/absent). Count signals, use threshold counts for classification. Simpler, more transparent, easier to explain to users.
3. **Category-weighted hybrid** — Rules belong to categories (urgency, financial, personal data, threats). Each category has a weight. Signals within a category contribute to the category score, then categories are weighted to produce a final score.

**Recommendation:** Option 3 (category-weighted hybrid). It balances explainability ("we detected urgency patterns AND financial requests") with tuning flexibility. Users see which categories triggered, not opaque numbers.

**Impact:** Phase 2 — determines the structure of `engine.ts`, `rules.ts`, and `types.ts`.

**Status:** ⏳ PENDING

---

## OD-03: Evidence Highlighting Strategy

**Context:** The UI must highlight the specific text spans that triggered each rule. This requires mapping analysis results back to character positions in the original message.

**Options:**
1. **Regex match indices** — Each rule returns the regex match with `index` and `length`. UI uses these to wrap spans. Simple, accurate for individual matches.
2. **Substring search on display** — Rules return the matched text string. UI finds and highlights the first occurrence. Simpler but fragile if the same text appears multiple times.
3. **Pre-tokenized spans** — The engine tokenizes the input into spans first, then rules mark spans. More robust but more complex.

**Recommendation:** Option 1 (regex match indices). It is precise, doesn't require tokenization overhead, and JavaScript regex `exec()` with `d` flag provides match indices natively.

**Impact:** Phase 2 (engine returns spans) and Phase 4 (UI renders highlights).

**Status:** ⏳ PENDING

---

## OD-04: Maximum Input Length

**Context:** Must define a hard limit on message input to prevent abuse and ensure fast analysis.

**Options:**
1. **5,000 characters** — Covers most SMS, email, and chat messages. Common scam messages rarely exceed 2,000 characters.
2. **10,000 characters** — Allows longer emails and forwarded message chains.
3. **2,000 characters** — More restrictive, covers SMS and short messages only.

**Recommendation:** 5,000 characters. This covers the vast majority of scam messages while keeping analysis fast and memory bounded. The UI should show a character counter.

**Impact:** Phase 2 (Zod schema) and Phase 4 (UI character counter).

**Status:** ⏳ PENDING

---

## OD-05: Risk Level Thresholds

**Context:** The engine must map its internal score/signal output to Low, Medium, or High risk. The thresholds determine the user experience.

**Trade-off:**
- **Aggressive thresholds** (flag more) → more false positives, users learn to distrust the tool
- **Conservative thresholds** (flag less) → more false negatives, users may be harmed by undetected scams

**Options:**
1. **Err toward caution** — Lower thresholds, flag more messages as Medium/High. Accept more false positives but protect more users.
2. **Balanced** — Tuned thresholds based on test corpus. May require iteration.
3. **Err toward precision** — Higher thresholds, only flag clearly suspicious messages. Fewer false positives but more missed scams.

**Recommendation:** Option 1 (err toward caution) for V1. A security tool should prefer false positives over false negatives. The UI language can soften this: "We noticed some patterns worth checking" is less alarming than "SCAM DETECTED."

**Impact:** Phase 2 (constants.ts thresholds). Requires iteration based on test results.

**Status:** ⏳ PENDING

---

## OD-06: Font Selection

**Context:** The warm-minimalism design direction requires a readable, modern typeface.

**Options:**
1. **Inter** — Widely used, excellent readability, variable font, Google Fonts. ~100 KB for variable weight.
2. **DM Sans** — Softer, slightly warmer feel. Good for the "warm minimalism" direction. ~60 KB.
3. **Outfit** — Geometric, clean, modern. ~70 KB.
4. **System font stack** — No font download cost. Varies across devices.

**Recommendation:** DM Sans or Inter. Both have excellent readability. DM Sans has a warmer character that better matches the design direction. Inter is the safer default.

**Impact:** Phase 1 (layout.tsx font import, Tailwind theme fontFamily).

**Status:** ✅ RESOLVED (2026-10-18) — Option 1: Inter font via `next/font/google` with JetBrains Mono for code/monospace excerpts. Zero external network latency at runtime.

---

## OD-07: API Route Testing Approach

**Context:** Next.js App Router API routes use `NextRequest` / `NextResponse` objects. Testing them requires either mocking these or running them in a test server.

**Options:**
1. **Direct function testing** — Extract the handler logic into a pure function that takes a plain object and returns a plain object. Test the pure function. Thin API route wrapper is untested or minimally tested.
2. **Mock `NextRequest`/`NextResponse`** — Create mock objects that satisfy the API. More realistic but more boilerplate.
3. **Integration test with `next/test-utils`** — Spin up a test server and make real HTTP requests. Most realistic but slowest.

**Recommendation:** Option 1 (direct function testing). The analysis logic is already in `lib/analyzer/`. The API route is a thin adapter. Test the adapter minimally (e.g., verify it returns 400 for invalid JSON) with mocked request objects.

**Impact:** Phase 3 (test strategy).

**Status:** ⏳ PENDING

---

## OD-08: "Next Steps" Content Strategy

**Context:** After analysis, Sus shows actionable advice tailored to the detected signals. This content must be helpful without being alarmist or legally risky.

**Questions to resolve:**
1. Should next steps link to external resources (e.g., government fraud reporting sites)?
2. Should next steps be generic per risk level, or tailored to specific signal categories?
3. Should next steps include a "Report this scam" action (and to whom)?

**Recommendation:**
- Tailored to signal categories, not just risk level. "We detected urgency + financial requests → be cautious about sharing bank details" is more useful than "This might be a scam."
- Include links to official Indian cybercrime reporting (since SETU is India-focused): [cybercrime.gov.in](https://cybercrime.gov.in/).
- Do NOT include a "Report" feature in V1 (no backend to receive reports).

**Impact:** Phase 4 (next-steps.tsx content).

**Status:** ⏳ PENDING

---

## OD-09: Deploy Target

**Context:** The app needs to be deployable for the hackathon demo.

**Options:**
1. **Vercel** — Zero-config for Next.js. Free tier. Fastest path.
2. **Netlify** — Good Next.js support. Free tier.
3. **Local demo only** — No deployment. Present from `localhost`.

**Recommendation:** Vercel for zero-friction deployment. No Vercel-specific code should be introduced (no `@vercel/analytics`, no Vercel Edge functions).

**Impact:** Phase 6 (deployment verification). No code impact — the app should be deployment-target agnostic.

**Status:** ⏳ PENDING

---

## OD-10: Icon Approach

**Context:** Sus needs approximately 5 icons: risk level indicators (Low/Medium/High), a scan/search icon, and a privacy/shield icon.

**Options:**
1. **Inline SVGs** — Zero dependency. Complete control. Slightly more verbose in code.
2. **Lucide React** — Tree-shakeable icon library (~1 KB per icon used). Clean, consistent style.
3. **Heroicons** — Similar to Lucide but slightly heavier. Works well with Tailwind.

**Recommendation:** Inline SVGs for V1. Five icons do not justify an icon library dependency. If more icons are needed later, revisit.

**Impact:** Phase 4 (component implementation).

**Status:** ✅ RESOLVED (2026-10-18) — Option 1: Clean inline SVGs adopted. Zero dependency weight, custom accessible styling.


---

## OD-11: Interior Patterns — Final Selection

**Context:** The [Repository Audit](./REPOSITORY_AUDIT.md) recommends studying 3 Interior patterns. This decision confirms which patterns to adopt and how.

**Patterns under consideration:**

| Pattern | Adopt? | Implementation |
|---------|--------|----------------|
| `useAsyncAction` state machine (loading-button) | Study & reimplement | Custom hook with CSS transitions; no `motion` dependency |
| `useSkeletonSwap` timing logic (skeleton-swap) | Study & reimplement | Custom hook + CSS opacity transition; no `motion` dependency |
| `useAccordion` ARIA patterns (accordion) | Reference only | Use `<details>/<summary>` with CSS animation; reference ARIA patterns |

**Decision needed:** Confirm this approach or select alternatives.

**Impact:** Phase 4 and Phase 5.

**Status:** ⏳ PENDING

---

## Decision Log

| ID | Decision | Resolved Date | Chosen Option |
|----|----------|---------------|---------------|
| OD-01 | Tailwind version | 2026-10-18 | Option 1: Tailwind v4 with CSS-first `@theme` |
| OD-02 | Rule architecture | — | — |
| OD-03 | Highlighting strategy | — | — |
| OD-04 | Max input length | — | — |
| OD-05 | Risk thresholds | — | — |
| OD-06 | Font selection | 2026-10-18 | Option 1: Inter + JetBrains Mono (next/font) |
| OD-07 | API testing approach | — | — |
| OD-08 | Next steps content | — | — |
| OD-09 | Deploy target | — | — |
| OD-10 | Icon approach | 2026-10-18 | Option 1: Zero-dep inline accessible SVGs |
| OD-11 | Interior patterns | — | — |
