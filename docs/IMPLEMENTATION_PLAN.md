# Implementation Plan — Sus V1

> **Created:** 2026-10-17  
> **Status:** Pending approval — do not begin Phase 1 without explicit sign-off  
> **Product:** Sus — "Sus? Now you'll know why."  
> **Scope:** SETU 2026 | Forge Realm, PS-01: Scam Spotter

---

## Guiding Principles

1. **Ship the smallest useful thing first.** Every phase must leave the app in a runnable state.
2. **Test the analysis engine first.** It is the product's credibility — untested rules are worse than no rules.
3. **Never claim certainty.** The UI must frame all results as pattern-based observations, not verdicts.
4. **No unnecessary dependencies.** Every addition must justify its bundle cost against a CSS/native alternative.
5. **Accessibility is not a phase — it is built into every phase.**

---

## Minimal Dependency Set

| Package | Purpose | Justification |
|---------|---------|---------------|
| `next` | Framework (App Router, API routes, SSR) | Core requirement |
| `react`, `react-dom` | UI library | Required by Next.js |
| `typescript` | Type safety | Core requirement |
| `tailwindcss`, `postcss`, `autoprefixer` | Styling | Core requirement (warm minimalism design system) |
| `@tailwindcss/postcss` | PostCSS plugin for Tailwind v4 | Required for Tailwind integration |
| `zod` | Input/output validation | Core requirement — validates user input and analysis responses |
| `vitest`, `@testing-library/react`, `@testing-library/jest-dom` | Testing | Core requirement |
| `@vitejs/plugin-react` | Vitest React support | Required for component tests |
| `jsdom` | DOM environment for tests | Required by Vitest for component tests |

**Not included (and why):**

| Package | Why excluded |
|---------|-------------|
| `motion` / `framer-motion` | ~30 KB gzipped for effects achievable with CSS transitions |
| `@phosphor-icons/react` / `lucide-react` | Inline SVGs are sufficient for the ~5 icons Sus needs |
| Any analytics SDK | No user tracking in V1; privacy-first |
| Any database driver | No persistence in V1 |
| `axios` / `swr` / `react-query` | Native `fetch` + React `useTransition` / `useActionState` suffice |
| `eslint` | Can be added later; Vitest + TypeScript provide core safety |

---

## Phase Sequence

### Phase 1 — Project Scaffold & Design Tokens

**Objective:** Bootable Next.js project with warm-minimalism design system. No application logic.

**Files created:**

| File | Purpose |
|------|---------|
| `package.json` | Dependencies and scripts |
| `tsconfig.json` | TypeScript configuration |
| `next.config.ts` | Next.js configuration |
| `tailwind.config.ts` | Tailwind theme (colors, fonts, spacing, radii) |
| `postcss.config.mjs` | PostCSS pipeline |
| `vitest.config.ts` | Test runner configuration |
| `.gitignore` | Ignore node_modules, .next, etc. |
| `app/layout.tsx` | Root layout with HTML `<head>`, font imports, metadata |
| `app/globals.css` | Tailwind directives + custom CSS variables + animations |
| `app/page.tsx` | Placeholder page (confirms the app boots) |
| `README.md` | Project description, setup instructions |

**Dependencies installed:** All from the minimal set above.

**Acceptance criteria:**
- [x] `npm run dev` starts the dev server without errors (Ready in 375ms on localhost:3000)
- [x] `npm run build` completes without errors
- [x] `npm test` executes cleanly (18 passing tests across 4 test suites)
- [x] Page loads at `localhost:3000` with the warm-minimalism background, typography, and accent color visible
- [x] Responsive layout and keyboard-friendly focus rings verified

**Tests required:** None (no logic yet). Vitest must be confirmed operational.

**Risks:** Tailwind v4 configuration differs from v3. Must verify `@tailwindcss/postcss` setup.

**Rollback:** Delete all generated files; the repo returns to its pre-Phase-1 state (only `.pptx`).

---

### Phase 2 — Analysis Engine & Validation

**Objective:** The deterministic scam-analysis engine, fully tested, with Zod schemas. No UI yet.

**Files created:**

| File | Purpose |
|------|---------|
| `lib/schemas.ts` | Zod schemas for `AnalyzeRequest` and `AnalyzeResponse` |
| `lib/analyzer/rules.ts` | Individual detection rules (urgency, financial, personal info, suspicious URLs, threats, etc.) |
| `lib/analyzer/engine.ts` | Orchestrator: runs all rules, computes risk level, returns structured result |
| `lib/analyzer/types.ts` | TypeScript types for rules, signals, risk levels, evidence |
| `lib/analyzer/constants.ts` | Shared constants (risk thresholds, max input length, etc.) |
| `__tests__/lib/analyzer/engine.test.ts` | Engine integration tests |
| `__tests__/lib/analyzer/rules.test.ts` | Individual rule unit tests |
| `__tests__/lib/schemas.test.ts` | Schema validation tests |

**Dependencies:** None new.

**Acceptance criteria:**
- [ ] `npx vitest run` passes all tests
- [ ] Engine correctly classifies known-scam message patterns as Medium or High risk
- [ ] Engine correctly classifies benign messages as Low risk
- [ ] Engine returns evidence with highlighted text spans and human-readable explanations
- [ ] Zod schema rejects inputs exceeding max length, empty strings, and non-string types
- [ ] No regex in rules is vulnerable to ReDoS (test with pathological inputs)
- [ ] Engine completes analysis of a 5000-character message in < 50ms

**Tests required:**

| Test category | Minimum count |
|---------------|---------------|
| Known scam patterns (high confidence) | ≥ 10 |
| Benign messages (must not flag) | ≥ 8 |
| Edge cases (empty, max length, unicode, mixed signals) | ≥ 6 |
| Schema validation (valid + invalid inputs) | ≥ 6 |
| False-positive regression (marketing emails, bank notifications) | ≥ 4 |
| ReDoS resistance (pathological regex inputs) | ≥ 2 |

**Risks:**
- Regex-based detection is inherently imprecise. The test suite must include expected false-positive cases.
- Urgency-language detection will over-trigger on marketing content.

**Rollback:** Remove `lib/analyzer/`, `lib/schemas.ts`, and `__tests__/`. No impact on Phase 1 files.

---

### Phase 3 — API Route

**Objective:** Server-side API endpoint that validates input, runs the engine, and returns structured results.

**Files created:**

| File | Purpose |
|------|---------|
| `app/api/analyze/route.ts` | POST handler: validate → analyze → respond |
| `__tests__/api/analyze.test.ts` | API route tests (valid input, invalid input, oversized input, error handling) |

**Dependencies:** None new.

**Acceptance criteria:**
- [ ] `POST /api/analyze` with valid JSON returns 200 with `AnalyzeResponse`
- [ ] Invalid JSON returns 400 with a structured error
- [ ] Oversized input (> max length) returns 400
- [ ] Empty message returns 400
- [ ] Response includes `Content-Type: application/json`
- [ ] Response headers include appropriate CORS and security headers
- [ ] No message content appears in server logs

**Tests required:**

| Test | Count |
|------|-------|
| Happy path (valid scam message → structured response) | ≥ 2 |
| Validation rejection (empty, too long, wrong type) | ≥ 4 |
| Error handling (malformed JSON) | ≥ 1 |

**Risks:** Next.js API route testing requires either mocking `NextRequest`/`NextResponse` or using a test helper. Decide approach in Phase 2.

**Rollback:** Remove `app/api/analyze/` and its tests. Phase 1+2 remain functional.

---

### Phase 4 — Core UI Components

**Objective:** All UI components rendered with static/mock data. No API integration yet.

**Files created:**

| File | Purpose |
|------|---------|
| `components/scanner-form.tsx` | Textarea + submit button + character count + validation messages |
| `components/risk-badge.tsx` | Low / Medium / High badge with icon, color, and label |
| `components/evidence-card.tsx` | Single finding: rule name, explanation, highlighted text span |
| `components/results-panel.tsx` | Full results view: risk badge + evidence cards + next steps |
| `components/next-steps.tsx` | Actionable advice tailored to detected risk signals |
| `components/privacy-notice.tsx` | Honest disclosure about how messages are processed |
| `components/loading-state.tsx` | Skeleton/spinner shown during analysis |
| `components/empty-state.tsx` | Initial state before any message is entered |
| `components/error-state.tsx` | Error display for API failures |
| `app/page.tsx` | Updated to compose all components with mock data |

**Dependencies:** None new.

**Acceptance criteria:**
- [ ] All components render without errors
- [ ] Risk badge uses text + icon (not color alone) for accessibility
- [ ] Evidence card highlights relevant text within the original message
- [ ] Privacy notice is always visible (not hidden behind a toggle)
- [ ] All interactive elements are keyboard-operable
- [ ] Page is responsive: usable at 320px, 768px, and 1280px widths
- [ ] `prefers-reduced-motion` disables all animations
- [ ] Lighthouse accessibility score ≥ 95

**Tests required:**

| Test | Count |
|------|-------|
| Risk badge renders correct label for each risk level | 3 |
| Evidence card renders highlighted text | ≥ 2 |
| Scanner form shows validation error for empty submit | 1 |
| Privacy notice renders | 1 |

**Risks:** Highlight-within-text logic can break on overlapping spans. Keep highlighting simple — mark one span per evidence item.

**Rollback:** Remove `components/` directory. Phase 1–3 remain functional.

---

### Phase 5 — Integration & Polish

**Objective:** Connect UI to API. End-to-end flow works. Polish micro-interactions.

**Files changed:**

| File | Change |
|------|--------|
| `app/page.tsx` | Add form submission logic, call `/api/analyze`, manage loading/error/success states |
| `components/scanner-form.tsx` | Wire `onSubmit` to API call |
| `components/results-panel.tsx` | Receive real data, animate entry |

**Files created:**

| File | Purpose |
|------|---------|
| `lib/hooks/use-analyze.ts` | Custom hook: manages fetch lifecycle, state machine (idle → pending → success/error) |
| `__tests__/integration/scan-flow.test.ts` | End-to-end test: enter message → submit → see results |

**Dependencies:** None new.

**Acceptance criteria:**
- [ ] User can paste a message, click Scan, and see results
- [ ] Loading state appears during analysis
- [ ] Error state appears on network failure (testable by disabling network)
- [ ] Focus moves to results after analysis completes
- [ ] Results include risk level, evidence list, and next steps
- [ ] "Scan another" resets the form cleanly
- [ ] `aria-live` region announces "Analysis complete" to screen readers
- [ ] All Phase 2 analysis tests still pass
- [ ] Full `npm run build` succeeds with no type errors

**Tests required:**

| Test | Count |
|------|-------|
| Full scan flow (mock API) | ≥ 2 |
| Error handling (API failure) | 1 |
| Reset flow | 1 |

**Risks:** Client-server type mismatch. Zod schemas must be shared between API route and client hook.

**Rollback:** Revert `page.tsx` and hook changes. Components still render with mock data.

---

### Phase 6 — Final QA, Docs & Ship Readiness

**Objective:** Verify the complete application. Write `README.md`. Confirm no misleading claims.

**Files changed:**

| File | Change |
|------|--------|
| `README.md` | Full project documentation: setup, architecture, limitations, privacy |
| `app/layout.tsx` | Final SEO metadata, OpenGraph tags |

**Acceptance criteria:**
- [ ] `npm run build` succeeds
- [ ] `npx vitest run` — all tests pass
- [ ] Lighthouse: Performance ≥ 90, Accessibility ≥ 95, Best Practices ≥ 90, SEO ≥ 90
- [ ] Manual test on Chrome, Firefox, Safari (mobile + desktop)
- [ ] Screen reader test (VoiceOver or NVDA) confirms usable flow
- [ ] No claims of "safe", "AI-powered", or guaranteed accuracy anywhere in the UI
- [ ] Privacy notice accurately describes data handling
- [ ] README includes "Limitations" section acknowledging false positives/negatives
- [ ] Bundle size < 200 KB gzipped (JS)

**Tests required:** All previous tests passing. No new tests unless gaps found.

**Risks:** Time pressure may tempt skipping accessibility or misleading-claim review. These are non-negotiable.

**Rollback:** N/A — this phase only adds documentation and metadata.

---

## Explicit Out-of-Scope Items (V1)

These items are **deliberately excluded** from V1 and must not be implemented:

| Item | Reason |
|------|--------|
| AI/ML-based analysis | V1 is deterministic only |
| User accounts / authentication | No user system in V1 |
| Message history / database | Stateless analysis only |
| Live URL fetching / link scanning | No external requests in V1 |
| Threat intelligence API integration | No external APIs in V1 |
| Multi-language support | V1 covers English only |
| Image/attachment analysis | V1 is text-only |
| Browser extension | V1 is web-only |
| Rate limiting infrastructure | Defer to deployment platform (Vercel, etc.) |
| Dark mode | V1 ships light theme only (warm minimalism) |
| Internationalization (i18n) | Single-language in V1 |

---

## Proposed File Tree (V1 Final State)

```
Setu-Forge/
├── app/
│   ├── api/
│   │   └── analyze/
│   │       └── route.ts
│   ├── globals.css
│   ├── layout.tsx
│   └── page.tsx
├── components/
│   ├── empty-state.tsx
│   ├── error-state.tsx
│   ├── evidence-card.tsx
│   ├── loading-state.tsx
│   ├── next-steps.tsx
│   ├── privacy-notice.tsx
│   ├── results-panel.tsx
│   ├── risk-badge.tsx
│   └── scanner-form.tsx
├── lib/
│   ├── analyzer/
│   │   ├── constants.ts
│   │   ├── engine.ts
│   │   ├── rules.ts
│   │   └── types.ts
│   ├── hooks/
│   │   └── use-analyze.ts
│   └── schemas.ts
├── __tests__/
│   ├── api/
│   │   └── analyze.test.ts
│   ├── integration/
│   │   └── scan-flow.test.ts
│   └── lib/
│       ├── analyzer/
│       │   ├── engine.test.ts
│       │   └── rules.test.ts
│       └── schemas.test.ts
├── docs/
│   ├── IMPLEMENTATION_PLAN.md
│   ├── OPEN_DECISIONS.md
│   └── REPOSITORY_AUDIT.md
├── public/
├── .gitignore
├── next.config.ts
├── package.json
├── postcss.config.mjs
├── README.md
├── tailwind.config.ts
├── tsconfig.json
├── vitest.config.ts
└── Sus_PS01_ScamSpotter_SETU2026.pptx
```

---

## The Precise First Implementation Task

**Phase 1, Task 1:** Initialize the Next.js project with TypeScript and Tailwind CSS.

Specifically:
1. Run `npx -y create-next-app@latest ./ --typescript --tailwind --eslint --app --src-dir=false --import-alias="@/*" --use-npm` (verify flags with `--help` first).
2. Add `zod` and `vitest` (+test utilities) to `package.json`.
3. Create `vitest.config.ts`.
4. Configure `tailwind.config.ts` with the warm-minimalism design tokens.
5. Create `app/globals.css` with design system CSS variables.
6. Update `app/layout.tsx` with proper metadata and font.
7. Update `app/page.tsx` with a minimal placeholder confirming the design system.
8. Create `.gitignore`.
9. Verify `npm run dev`, `npm run build`, and `npx vitest run` all succeed.

**Do not begin this task until this plan is approved.**
