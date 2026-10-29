# Sus — Scam Detector 

**Sus? Now you'll know why.**

  [Live Project 🚀](https://sus-scam-detector-4vsz.onrender.com/)    
  [Video Overview 📹](https://drive.google.com/file/d/1Q9onqYjlLTrNYzt1Ygk-QDndsOKjV6Le/view?usp=drive_link)   
  

Sus helps people inspect suspicious text messages, chats, and emails. It highlights potential warning signs and explains what to look out for, so users can make more informed decisions before responding or clicking.

## Overview

Suspicious messages can use misleading claims, unusual links, requests for private information, or pressure to act quickly. Sus checks a submitted message for these and other known patterns, then presents a risk assessment with clear findings and practical safety advice.

## Key Features

- **Expanded Scam Recognition**: Detects modern deception patterns across UPI payment traps, QR receipt scams, KYC/PAN expiry countdowns, fake courier and customs fees, fake job offers, investment/crypto fraud, government or law enforcement impersonation, and remote desktop lures.
- **Context-Aware Negation**: Reduces false positives by recognizing protective security advisories (e.g., "Never share your OTP"), official scam warnings, and routine delivery updates.
- **Dedicated Link & Website Intelligence**: Safely extracts URLs (HTTP, HTTPS, www, Punycode/Unicode) and inspects them for IP-address hosts, URL shorteners, unusual ports, open redirect parameters, sensitive paths, and lookalike domain mimicry.
- **Brand Lookalike Detection**: Evaluates hostnames against curated reference domains for major banks, fintech apps, couriers, and platforms, detecting deceptive hyphenated keywords and typosquatting variations.
- **Explainable Findings & Defanged Display**: Displays defanged hostnames as non-clickable plain text, highlights character-exact message evidence spans, and provides plain-language safety recommendations.
- **Deterministic Risk Scoring**: 0–100 score with Low (0–24), Medium (25–54), and High (55–100) tiers. High risk requires meaningful evidence and avoids single-word or benign URL false alarms.
- **Local & Privacy-Preserving by Default**: Analyzes messages and URLs locally on the server without making outbound requests to user-submitted links, preventing Server-Side Request Forgery (SSRF) and data leakage.

## How It Works

1. Paste or type a message you want to check (5 to 5,000 characters).
2. Select **Analyze Message**.
3. Review the overall risk assessment, rule score, and detected warning signs.
4. Inspect the **Links in message** section to see extracted hostnames, potential brand impersonation, and observable technical reasons for concern.
5. Follow the recommendations and verify important requests through official channels.

### Heuristic Analysis vs. Threat Intelligence

- **Local Heuristics (Default)**: Inspects structural patterns, brand databases, and deceptive domain formations entirely within the application without querying external websites.
- **Optional Threat-Intelligence Enrichment**: If configured on the server via `THREAT_INTEL_API_URL` and `THREAT_INTEL_API_KEY`, the server can optionally query reputable reputation feeds with strict SSRF validation and timeout protection. No raw user message text or sensitive query parameters are ever transmitted to third-party reputation providers.

## Technology Stack

- **Next.js 16** and **React 19** for the web application.
- **TypeScript** for application code and strict types.
- **Tailwind CSS 4** for styling.
- **Zod** for validating analysis requests and results.
- **Vitest** and **Testing Library** for automated tests.

## Getting Started

### Prerequisites

- Node.js 20.9 or later
- npm

### Run locally

```bash
git clone https://github.com/atharvakanekar22-dev/sus-scam-detector.git
cd sus-scam-detector
npm ci
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

Other available project checks:

```bash
npm test
npm run lint
npm run build
```
### Screenshots from the Live Web - Application

<img width="216" height="116" alt="image" src="https://github.com/user-attachments/assets/cbf5d436-403a-433e-81cc-0ac87f4b1804" />

<img width="959" height="563" alt="image" src="https://github.com/user-attachments/assets/dbf02977-8c85-4865-a704-2b28df2334cf" />

<img width="959" height="563" alt="image" src="https://github.com/user-attachments/assets/afa57237-9d70-44fa-80d7-5296dcabec39" />

<img width="959" height="597" alt="image" src="https://github.com/user-attachments/assets/fc4e3785-18fd-4dc2-9d44-0ad47321435d" />

<img width="383" height="344" alt="image" src="https://github.com/user-attachments/assets/3801c74f-1641-4029-a190-cacf9fd8f83e" />




## Project Structure

```text
app/
  api/analyze/route.ts    Message analysis request handler
  page.tsx                Main scanner page
components/
  BrandHeader.tsx         SUS wordmark
  ScannerForm.tsx         Message input and validation
  ResultsPanel.tsx        Assessment, findings, URL cards, and recommendations
lib/
  analyzer/               Detection rules, multi-signal overrides, scoring engine
    url/                  URL extractor, brand registry, heuristics, and SSRF guards
  schemas.ts              Request and result validation (Zod)
__tests__/                Unit, component, ReDoS, SSRF, category, and integration tests
```

## Privacy & Limitations

- **Heuristic Indicators, Not Proof**: Sus flags suspicious patterns and observable risk factors. Findings do not constitute definitive legal or cryptographic proof that a message is fraudulent or safe.
- **Local Inspection Only**: Sus does not visit or execute code from untrusted websites. It cannot verify live page content or dynamic redirects that require live browsing.
- **Verify Independently**: Always confirm urgent communications, payment requests, or account alerts directly through official mobile apps, banking helplines, or verified domains you independently navigate to.
