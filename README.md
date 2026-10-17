# SUS — Scam Message Scanner

SUS helps people inspect suspicious SMS, chat messages, and emails. Enter a message to see a risk label, a 0–100 rule score, the warning signs that were found, and simple next steps.

The app is built with Next.js, React, and TypeScript. It can analyze messages with local deterministic rules and, when configured, Google's hosted Gemini API. It does not require Gemini to run.

## Features

- Type or paste a message of 5 to 5,000 characters and analyze it.
- See a low, medium, or high risk assessment with a color-coded score gauge.
- Review plain-language warning signs and the text evidence that triggered them.
- Expand the checked message to see highlighted evidence.
- Copy a short assessment summary or start another scan.
- Use Gemini for optional contextual analysis; if Gemini is not configured or unavailable, continue with local rules.
- Open the SUS home page by selecting the wordmark. Hover or focus the wordmark to reveal its tagline and enlargement effect.

## How analysis works

1. The `/api/analyze` route validates the submitted message.
2. Local deterministic rules check for selected scam patterns, including credential requests, urgency or account threats, payment and prize lures, suspicious links, impersonation, and protective security advice.
3. If `GEMINI_API_KEY` is set, the server also sends the message to the configured Gemini model. The prompt asks the model to assess context and to support English, Hindi, other Indian languages, code-switching, and transliteration.
4. Gemini findings are included only when their quoted evidence exactly matches a substring of the submitted message. When both sources are available, the displayed risk level takes the more severe of the Gemini and local assessments.
5. If Gemini is absent, times out, or returns an unusable response, the scanner falls back to its local rule assessment.

### Understanding the score

The displayed number is the **rule score**, calculated from weighted local rule matches with category caps and a maximum of 100. Selected combinations of strong signals receive a minimum score of 75. Risk labels are assigned from the local score thresholds (medium from 25; high from 55), with certain critical combinations classified as high risk.

This number is a heuristic signal score, **not** a probability that a message is fraudulent, a measure of model confidence, or a validated accuracy percentage. With Gemini enabled, the risk label may be more severe than the score alone suggests. Review the warning signs and verify important requests through a trusted channel.

### Language and accuracy limits

Gemini is prompted to understand multiple languages and code-switched messages. The local rules include selected phrases in several Indian scripts and Hinglish, plus selected examples in other languages. Coverage is incomplete: the scanner may miss scams, misunderstand context, or flag legitimate messages. There is no representative, human-labelled evaluation dataset or training/fine-tuning process for this project, and no system can guarantee 100% correct results.

## Privacy and security

- SUS does not save scans to an application database. The current version does not include a crowdsourced report database.
- Without Gemini configured, analysis runs locally on the application server and the message is not sent to the Gemini API.
- When Gemini is enabled, the submitted message text is sent from the server to Google's Gemini API for analysis. Review Google's applicable terms and privacy policy before using the hosted service.
- Do not submit passwords, one-time passcodes (OTPs), PINs, card security codes, or other sensitive personal information.
- Keep `.env.local` private. The Gemini key is read only by the server; never expose it in browser code, source control, screenshots, or public messages.

## Requirements

- Node.js 20 or later
- npm 10 or later

## Setup

From the repository root, install dependencies:

```powershell
npm install
```

Optionally configure Gemini. Copy the example environment file if you do not already have a local environment file:

```powershell
Copy-Item .env.example .env.local
```

Set the following values in `.env.local`:

```env
GEMINI_API_KEY=your_google_ai_studio_api_key
GEMINI_MODEL=gemini-2.5-flash
```

`GEMINI_API_KEY` is optional. Leave it unset to use the local rule engine only. `GEMINI_MODEL` is optional and defaults to `gemini-2.5-flash`. Obtain API credentials from Google AI Studio, keep them server-side, and restart the app after changing environment variables.

Start the development server:

```powershell
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Keep the development server running while using the app.

For a production build and local production server:

```powershell
npm run build
npm run start
```

## Available commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the Next.js development server. |
| `npm run build` | Create an optimized production build. |
| `npm run start` | Serve the production build. Run `npm run build` first. |
| `npm run lint` | Run ESLint. |
| `npm test` | Run the Vitest suite. |
| `npx tsc --noEmit` | Check TypeScript types without emitting files. |

Tests mock the Gemini API. They do not need an API key and do not send test messages to Google.

## Project structure

```text
app/
  api/analyze/route.ts       Validates requests and runs the analysis pipeline
  globals.css                Global styles and design tokens
  layout.tsx                 Shared document layout, fonts, and metadata
  page.tsx                   Scanner page and client-side scan state
components/
  BrandHeader.tsx            Clickable SUS wordmark and hover/focus treatment
  ScannerForm.tsx            Message entry, validation, loading, and error UI
  ResultsPanel.tsx           Risk score, findings, highlighted evidence, and actions
lib/
  analyzer/
    constants.ts             Score thresholds and analysis limits
    engine.ts                Deterministic rules, scoring, findings, and recommendations
    gemini.ts                Optional Gemini client and evidence validation
    rules.ts                 Scam and protective-advice detection patterns
  schemas.ts                 Request and response validation schemas
  types.ts                   Shared UI and analysis types
__tests__/                   Component, API, and analyzer tests
```

## Troubleshooting

- **The page cannot connect to the scanner:** make sure `npm run dev` is still running and reload `http://localhost:3000`.
- **Gemini analysis is unavailable:** verify `GEMINI_API_KEY` and `GEMINI_MODEL` in `.env.local`, check that the key is active and has access to the selected model, then restart the server. The scanner should still return local rule-based results.
- **A message is rejected:** enter between 5 and 5,000 characters. Whitespace-only text is not accepted.
- **The result seems wrong:** treat it as an aid, not a final determination. Check the quoted warning signs and independently verify requests using an official app, website, or known contact number.

## Main implementation files

- [`app/api/analyze/route.ts`](./app/api/analyze/route.ts) — API validation, local analysis, and optional Gemini orchestration.
- [`lib/analyzer/engine.ts`](./lib/analyzer/engine.ts) — deterministic scoring, risk classification, findings, and recommendations.
- [`lib/analyzer/rules.ts`](./lib/analyzer/rules.ts) — local detection and protective-advisory patterns.
- [`lib/analyzer/gemini.ts`](./lib/analyzer/gemini.ts) — server-side Gemini request, response validation, and evidence grounding.
- [`components/ScannerForm.tsx`](./components/ScannerForm.tsx) — message input and submission UI.
- [`components/ResultsPanel.tsx`](./components/ResultsPanel.tsx) — analysis result and user actions.
