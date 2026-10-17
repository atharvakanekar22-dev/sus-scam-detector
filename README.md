# SUS — Scam Message Scanner

SUS checks suspicious messages for scam signals and explains the evidence behind its assessment. Messages can be typed or pasted, and the scanner accepts up to 5,000 characters.

## How analysis works

- Local deterministic rules check known scam patterns.
- When configured, the server also sends the message to Google's Gemini API for contextual analysis. The default model is `gemini-2.5-flash`; change it with `GEMINI_MODEL`.
- Gemini is prompted to assess Hindi, other Indian languages, code-switching, and transliteration. Local rules cover selected phrases and examples in several scripts and Hinglish, but do not provide complete language coverage; accuracy for any language is not guaranteed.
- Model findings are included only when their quoted evidence can be matched to the original message. The final risk level considers both Gemini and local rule results.
- If Gemini is not configured or unavailable, the app falls back to deterministic rule analysis. The result view keeps backend/provider notices out of the user-facing assessment.
- The displayed rule score is the capped weighted total of matching local rules, from 0 to 100. Certain combinations of account threats, suspicious links, credential requests, and payment/prize lures receive a minimum score of 75. The score is a heuristic signal score, not a probability or measured accuracy score; compare it with the risk label and warning signs.
- Gemini is a pre-trained hosted model; this project does not train or fine-tune it. Language support and detection accuracy have not been measured against a representative, human-labelled dataset, and no AI system can guarantee 100% correct scam decisions. Verify important requests independently.

**Privacy:** When Gemini is enabled, submitted message text is sent to Google's Gemini API. Avoid entering passwords, OTPs, or other sensitive personal information. SUS does not save scans to an application database.

## Getting started

Requirements: Node.js 20+ and npm 10+.

```powershell
npm install
Copy-Item .env.example .env.local
```

Add your Google AI Studio Gemini API key to `.env.local`:

```env
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash
```

Keep `.env.local` private; it is ignored by Git. Never put the key in browser code, screenshots, source control, or chat. Restart the development server after changing environment variables.

Run the app:

```powershell
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The server must remain running while you use the scanner.

## Verification

```powershell
npm test
npm run lint
npm run build
```

Tests mock the Gemini API; they do not require an API key or send real messages to Google.

## Main files

- `app/api/analyze/route.ts` — validates requests and coordinates model and rule-based analysis.
- `lib/analyzer/gemini.ts` — Gemini API client, structured-output validation, and evidence grounding.
- `lib/analyzer/engine.ts` — deterministic message analysis rules.
- `components/ScannerForm.tsx` — typing, sample messages, validation, and submission.
- `components/ResultsPanel.tsx` — risk summary, verified evidence, and recommended actions.
