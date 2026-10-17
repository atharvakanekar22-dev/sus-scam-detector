# Repository Audit — Sus (Setu-Forge)

> **Audit date:** 2026-10-17  
> **Auditor role:** Senior Software Architect / Security Reviewer / UI-UX Specialist  
> **Repository:** `c:\Users\Atharva\OneDrive\Desktop\Projects\Setu-Forge`

---

## 1. Current Repository Contents

| Path | Type | Size | Purpose |
|------|------|------|---------|
| `Sus_PS01_ScamSpotter_SETU2026.pptx` | File | 8.3 MB | Presentation deck (likely the hackathon pitch) |

**Total source files: 0**  
**Total configuration files: 0**  
**Total test files: 0**  
**Total documentation files: 0** (prior to this audit)

### Verdict

The repository is **empty of application code**. There is no Next.js project, no `package.json`, no TypeScript configuration, no Tailwind setup, no test infrastructure, and no blueprint documents beyond the presentation file. Development starts from scratch.

---

## 2. What Exists

- A `.pptx` presentation file (~8.3 MB), presumably containing the project pitch for SETU 2026 | Forge Realm PS-01.
- No `.gitignore`, no `README.md`, no `LICENSE`.
- No `docs/` directory.
- No `.github/` workflows.

---

## 3. What Is Missing (vs. Agreed V1 Scope)

### 3.1 Project Foundation

| Item | Status | Priority |
|------|--------|----------|
| `package.json` with Next.js, TypeScript, Tailwind, Zod, Vitest | ❌ Missing | **P0** |
| `tsconfig.json` | ❌ Missing | **P0** |
| `next.config.ts` | ❌ Missing | **P0** |
| `tailwind.config.ts` | ❌ Missing | **P0** |
| `postcss.config.mjs` | ❌ Missing | **P0** |
| `.gitignore` | ❌ Missing | **P0** |
| `vitest.config.ts` | ❌ Missing | **P0** |
| `README.md` | ❌ Missing | **P1** |

### 3.2 Application Code

| Item | Status | Priority |
|------|--------|----------|
| `app/layout.tsx` (root layout) | ❌ Missing | **P0** |
| `app/page.tsx` (scanner page) | ❌ Missing | **P0** |
| `app/globals.css` (design tokens) | ❌ Missing | **P0** |
| `app/api/analyze/route.ts` (server-side analysis endpoint) | ❌ Missing | **P0** |
| `lib/analyzer/` (deterministic analysis engine) | ❌ Missing | **P0** |
| `lib/schemas.ts` (Zod validation schemas) | ❌ Missing | **P0** |
| UI components (input, results, risk badge, evidence highlights) | ❌ Missing | **P0** |
| Privacy notice component | ❌ Missing | **P1** |
| Error / empty / loading states | ❌ Missing | **P0** |

### 3.3 Tests

| Item | Status | Priority |
|------|--------|----------|
| Analysis engine unit tests | ❌ Missing | **P0** |
| Zod schema validation tests | ❌ Missing | **P0** |
| API route integration tests | ❌ Missing | **P1** |
| Component render tests | ❌ Missing | **P1** |

### 3.4 Documentation

| Item | Status | Priority |
|------|--------|----------|
| `docs/IMPLEMENTATION_PLAN.md` | ❌ Missing (created in this audit) | **P0** |
| `docs/OPEN_DECISIONS.md` | ❌ Missing (created in this audit) | **P0** |
| `docs/REPOSITORY_AUDIT.md` | ❌ Missing (this file) | **P0** |

---

## 4. Architecture Risks

### 4.1 Privacy

- **No message storage** is required (confirmed). The analysis must be stateless — message content must never be logged, persisted, or transmitted to third parties.
- Server-side analysis via a Next.js API route means message text transits the network to the server and back. The privacy notice must disclose this. HTTPS is mandatory.
- No analytics SDK should capture message content.

### 4.2 Security

- **Input validation is critical.** Without Zod validation, oversized or malicious inputs could cause server-side issues (ReDoS in regex-based analysis, memory exhaustion from very large messages).
- The analysis engine must impose strict length limits on input.
- API route must use rate limiting or at minimum input-size caps.
- No user-controlled content should be rendered with `dangerouslySetInnerHTML`.
- Evidence highlighting must use safe text-node manipulation, not HTML injection.

### 4.3 Accessibility

- Risk classification colors (Low/Medium/High) must not rely solely on color — text labels, icons, and ARIA attributes are required.
- The textarea must have a visible label (not just a placeholder).
- Loading states need `aria-live` regions.
- Focus management after analysis completes.
- Keyboard operability for all interactive elements.

### 4.4 Testing

- Starting from zero tests. The analysis engine is the highest-risk component and must be tested first.
- False-positive and false-negative test cases must be part of the test suite from day one.

### 4.5 Performance

- The deterministic analysis engine runs server-side. For V1 (no AI/API), it should complete in <100ms for typical message lengths.
- Tailwind CSS purging must be configured to avoid shipping unused styles.

---

## 5. Likely False Positives and False Negatives in Deterministic Analysis

### 5.1 False Positives (legitimate messages flagged as risky)

| Scenario | Cause |
|----------|-------|
| Marketing emails with urgency language ("Limited time offer!") | Urgency-pattern regex matches |
| Bank notifications with real account references | Contains financial keywords |
| Password reset emails from legitimate services | Contains URLs and "verify your account" language |
| Job offers mentioning salary or compensation | Financial keywords + personal info requests |
| Charity / donation requests from known organizations | Money-related urgency language |
| Messages containing quoted scam examples (news articles, security training) | Meta-discussion of scam patterns |

### 5.2 False Negatives (actual scams not detected)

| Scenario | Cause |
|----------|-------|
| Social engineering without typical keywords ("Can you do me a favor?") | No keyword match, relies on context |
| Scams in languages other than English | V1 likely only covers English patterns |
| Obfuscated text (zer0 instead of zero, Unicode lookalikes) | Simple regex won't match |
| Image-only scam messages (no text) | V1 is text-only |
| Sophisticated phishing with clean language | Lacks AI contextual understanding |
| Scams using legitimate-looking shortened URLs | No URL resolution in V1 |

### 5.3 Mitigation

The UI **must not** claim certainty. Required language:
- ✅ "This message **shows patterns commonly found** in scam messages"
- ✅ "Low risk **does not guarantee** this message is safe"
- ❌ "This message **is** a scam"
- ❌ "This message **is safe**"

---

## 6. Misleading Claims to Avoid

| Claim | Problem | Fix |
|-------|---------|-----|
| "Message is safe" | Cannot guarantee safety; absence of detected patterns ≠ safety | "No common scam patterns were detected" |
| "Scam detected" | Deterministic analysis cannot prove intent; legal liability risk | "This message exhibits patterns commonly associated with scam messages" |
| "AI-powered analysis" | V1 uses no AI | Remove any AI claims entirely |
| "100% accurate" | No analysis system achieves this | Do not make accuracy claims |
| "Your message is private" without qualification | Message transits to server for analysis | Disclose server-side processing; confirm no storage/logging |

---

## 7. Interior Reference Repository Audit

### 7.1 Overview

| Property | Value |
|----------|-------|
| Repository | [ddoemonn/interior](https://github.com/ddoemonn/interior) |
| Description | "Micro-interactions for React, built for the half-second after a click" |
| License | **MIT** (permissive, compatible) |
| Architecture | Copy-paste single-file components, each exports a headless hook + styled component |
| Runtime dependency | `motion` (Motion for React, formerly Framer Motion) |
| Other deps | `@phosphor-icons/react`, `@vercel/analytics`, Next.js, Tailwind CSS |
| Package manager | Bun |
| Component count | ~50+ components |

### 7.2 Components Catalog (relevant subset)

| Component | File Size | Relevance to Sus |
|-----------|-----------|-----------------|
| `loading-button.tsx` | 7.5 KB | ✅ High — scan button with pending/success/error states |
| `inline-validation.tsx` | 8.2 KB | ✅ High — textarea validation feedback |
| `accordion.tsx` | 10.7 KB | ✅ Medium — expandable evidence sections |
| `skeleton-swap.tsx` | 4.8 KB | ✅ Medium — loading state for results |
| `progress-bar.tsx` | 4.1 KB | ⚠️ Low — indeterminate progress (analysis is fast) |
| `copy-button.tsx` | 7.5 KB | ⚠️ Low — copy message text |
| `floating-label.tsx` | 8.0 KB | ⚠️ Low — input styling |
| `collapsible-banner.tsx` | 9.0 KB | ❌ Not needed |
| `command-palette.tsx` | 15.2 KB | ❌ Not needed |
| `swipe-deck.tsx` | 15.7 KB | ❌ Not needed |

### 7.3 Dependency Analysis

| Dependency | Interior uses | Sus impact |
|------------|--------------|------------|
| `motion` (~30 KB gzipped) | Required by all Interior components | **Significant bundle cost** for a single-page app. Must justify with concrete UX benefit. |
| `@phosphor-icons/react` | Icon system | Sus can use Lucide React (lighter) or inline SVGs |
| `@vercel/analytics` | Vercel-specific | Not needed |

### 7.4 Accessibility Review of Interior Components

| Concern | Finding |
|---------|---------|
| `useReducedMotion()` | ✅ All inspected components check `prefers-reduced-motion` |
| ARIA attributes | ✅ Accordion uses `aria-expanded`, `aria-controls`, `role="region"` correctly |
| Keyboard navigation | ✅ Accordion implements arrow-key navigation between headers |
| Focus management | ⚠️ Loading button does not explicitly manage focus after state change |
| Screen reader announcements | ⚠️ No `aria-live` regions in loading-button or skeleton-swap |

### 7.5 Recommended Patterns (max 3)

| # | Pattern | Intended Use in Sus | Dependency | Accessibility | Recommendation |
|---|---------|-------------------|------------|---------------|----------------|
| 1 | **Loading button** (`useAsyncAction` hook) | "Scan Message" button with idle → pending → success/error states | `motion` | Needs `aria-live` addition | **Study the hook pattern; reimplement with CSS transitions.** The `useAsyncAction` state machine is excellent, but the animated spinner requires `motion`. A CSS-only spinner + the same state machine achieves 95% of the effect at 0 KB bundle cost. |
| 2 | **Skeleton swap** (`useSkeletonSwap` hook) | Show skeleton placeholders while analysis runs; prevent flash of skeleton for fast responses | `motion` (for crossfade) | Needs `aria-busy` and `aria-live` | **Adopt the timing logic; replace animation with CSS `opacity` transition.** The `delay` + `minVisible` pattern prevents skeleton flash on fast loads and avoids jarring pops. Reimplementable in ~30 lines with no dependencies. |
| 3 | **Accordion** (`useAccordion` hook) | Expandable evidence sections in analysis results | `motion` (for height animation) | ✅ Good ARIA | **Study for ARIA patterns; use `<details>/<summary>` + CSS for the animation.** The hook's keyboard nav and ARIA are reference-quality but the height animation can be achieved natively in modern browsers. |

### 7.6 Patterns Better Implemented with Simple CSS

| Interior Pattern | CSS Alternative | Reason |
|-----------------|-----------------|--------|
| Button press depth effect | `transform: scale(0.97)` on `:active` | Trivial CSS, no JS needed |
| Fade-in on results appear | `@keyframes fadeIn` or `opacity` transition | Native CSS, no library needed |
| Risk badge color transitions | `transition: background-color 200ms ease` | Trivial CSS |
| Input focus ring animation | `transition: box-shadow 150ms ease` | Native Tailwind `ring` utilities |
| Skeleton shimmer | `@keyframes shimmer` with gradient | Pure CSS, widely established pattern |

### 7.7 Bundle Impact Assessment

| Approach | Additional bundle size |
|----------|----------------------|
| Import `motion` for 3 components | ~30 KB gzipped (significant for a single-page tool) |
| Reimplement with CSS transitions + hooks | ~0 KB additional dependencies |
| **Recommendation** | **Do not add `motion` as a dependency.** Adopt the hook logic patterns (state machines, timing) and implement animations with CSS transitions and `@keyframes`. |

---

## 8. Summary

### What must be corrected before development

1. **Initialize the Next.js project** — currently no application code exists at all.
2. **Create `.gitignore`** — the `.pptx` file (8.3 MB) should be tracked intentionally or excluded.
3. **Establish the docs directory** — the three planning documents (this audit, implementation plan, open decisions) form the development contract.

### What does NOT need correction

- The `.pptx` presentation file is not part of the application and can remain as-is.
- No existing code to audit for correctness (there is none).
