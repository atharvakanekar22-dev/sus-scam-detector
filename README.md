# Sus — Scam Detector

**Sus? Now you'll know why.**

[Live Demo](https://sus-scam-detector-4vsz.onrender.com/)

Sus helps people inspect suspicious text messages, chats, and emails. It highlights potential warning signs and explains what to look out for, so users can make more informed decisions before responding or clicking.

## Overview

Suspicious messages can use misleading claims, unusual links, requests for private information, or pressure to act quickly. Sus checks a submitted message for these and other known patterns, then presents a risk assessment with clear findings and practical safety advice.

## Key Features

- Scan a message by typing or pasting between 5 and 5,000 characters.
- View a low, medium, or high risk classification and a 0–100 rule score.
- Review detected warning signs and their matching message text.
- Expand the checked message to see relevant evidence highlighted.
- Get simple recommendations based on the assessment.
- Use a responsive interface with input validation, clear error feedback, and options to copy the summary or start another scan.

## How It Works

1. Paste or type a message you want to check.
2. Select **Analyze Message**.
3. Review the risk assessment, score, and highlighted warning signs.
4. Follow the recommendations and verify important requests through a trusted channel.

## Technology Stack

- **Next.js 16** and **React 19** for the web application.
- **TypeScript** for application code and types.
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

## Project Structure

```text
app/
  api/analyze/route.ts    Message analysis request handler
  page.tsx                Main scanner page
components/
  BrandHeader.tsx         SUS wordmark
  ScannerForm.tsx         Message input and validation
  ResultsPanel.tsx        Assessment, findings, and recommendations
lib/
  analyzer/               Detection rules and scoring logic
  schemas.ts              Request and result validation
__tests__/                Component, API, and analysis tests
```

## Disclaimer

Sus provides indicators to help assess suspicious messages. Its score and findings are not proof that a message is fraudulent or safe. Verify important requests independently using official websites, apps, or contact details you already trust.
