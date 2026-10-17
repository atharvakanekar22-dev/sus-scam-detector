import { AnalysisResult } from "./types";

/**
 * PHASE 1 MOCK DATA BOUNDARY
 * 
 * IMPORTANT: These results are strictly simulated fixtures for Phase 1 UI/UX
 * verification and layout testing. Real deterministic heuristic evaluation
 * will be implemented in Phase 2.
 */

export interface SampleMessage {
  id: string;
  label: string;
  expectedRisk: "high" | "medium" | "low";
  text: string;
}

export const SAMPLE_MESSAGES: SampleMessage[] = [
  {
    id: "sample-electricity",
    label: "Urgent electricity bill",
    expectedRisk: "high",
    text: "URGENT: Dear customer, your electricity power connection will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity verification officer at 98765-43210 or click http://bit.ly/power-bill-update to prevent immediate blackout.",
  },
  {
    id: "sample-kyc",
    label: "Bank account suspension",
    expectedRisk: "medium",
    text: "Dear SBI User, your account KYC has expired. Your net banking access will be suspended within 24 hours. Please click https://sbi-kyc-verify-portal.in to re-verify your Aadhaar and PAN card details today.",
  },
  {
    id: "sample-benign",
    label: "Personal lunch invite",
    expectedRisk: "low",
    text: "Hey Atharva, are we still meeting for lunch at 1:30 PM tomorrow at the cafe near the office? Let me know if that time works for you or if you'd prefer Thursday instead.",
  },
];

export const MOCK_HIGH_RISK_RESULT: AnalysisResult = {
  id: "mock-high-001",
  timestamp: new Date().toISOString(),
  riskLevel: "high",
  riskScorePercent: 88,
  summary:
    "This message displays multiple strong pressure tactics commonly associated with utility bill scams, including strict artificial deadlines, threats of disconnection, and unofficial contact channels.",
  findings: [
    {
      id: "f-1",
      category: "urgency",
      title: "Immediate Threat & Deadline Pressure",
      description:
        "Creates acute fear of utility shutoff within hours ('disconnected tonight at 9:30 PM') to bypass critical reasoning.",
      highlightedText: "disconnected tonight at 9:30 PM",
      severity: "high",
    },
    {
      id: "f-2",
      category: "suspicious_link",
      title: "Obfuscated / Shortened URL",
      description:
        "Directs the recipient to a generic link shortener ('bit.ly') instead of an authenticated utility provider portal.",
      highlightedText: "http://bit.ly/power-bill-update",
      severity: "high",
    },
    {
      id: "f-3",
      category: "impersonation",
      title: "Unverified Personal Phone Number",
      description:
        "Official utility providers do not instruct customers to resolve billing emergencies via personal mobile numbers.",
      highlightedText: "98765-43210",
      severity: "medium",
    },
  ],
  recommendedSteps: [
    {
      id: "step-1",
      text: "Do NOT click the link or dial the personal mobile number provided in the message.",
    },
    {
      id: "step-2",
      text: "Log in directly to your official electricity board portal or check your latest physical bill.",
    },
    {
      id: "step-3",
      text: "Report the mobile number and message to the National Cyber Crime Reporting Portal.",
      actionUrl: "https://cybercrime.gov.in",
      actionLabel: "Visit cybercrime.gov.in",
    },
  ],
  isMock: true,
};

export const MOCK_MEDIUM_RISK_RESULT: AnalysisResult = {
  id: "mock-medium-001",
  timestamp: new Date().toISOString(),
  riskLevel: "medium",
  riskScorePercent: 58,
  summary:
    "This message exhibits urgency cues regarding account suspension and asks for sensitive credentials via an unverified external link.",
  findings: [
    {
      id: "f-m1",
      category: "personal_data",
      title: "Sensitive Credential Solicitation",
      description:
        "Requests Aadhaar and PAN verification via an unverified link. Banks never solicit credentials through unsolicited SMS.",
      highlightedText: "re-verify your Aadhaar and PAN card details",
      severity: "high",
    },
    {
      id: "f-m2",
      category: "urgency",
      title: "Artificial 24-Hour Countdown",
      description:
        "Pressures the recipient with short suspension deadlines ('within 24 hours').",
      highlightedText: "suspended within 24 hours",
      severity: "medium",
    },
    {
      id: "f-m3",
      category: "suspicious_link",
      title: "Unofficial Domain Structure",
      description:
        "The domain 'sbi-kyc-verify-portal.in' mimics bank naming but is not an official banking URL.",
      highlightedText: "https://sbi-kyc-verify-portal.in",
      severity: "high",
    },
  ],
  recommendedSteps: [
    {
      id: "step-m1",
      text: "Do not submit any Aadhaar, PAN, or OTP information on external websites.",
    },
    {
      id: "step-m2",
      text: "Visit your bank branch or use the verified official banking app directly to check KYC status.",
    },
  ],
  isMock: true,
};

export const MOCK_LOW_RISK_RESULT: AnalysisResult = {
  id: "mock-low-001",
  timestamp: new Date().toISOString(),
  riskLevel: "low",
  riskScorePercent: 12,
  summary:
    "No typical scam indicators or coercive pressure patterns were detected in this message. It reads as conversational personal communication.",
  findings: [
    {
      id: "f-l1",
      category: "urgency",
      title: "No Coercive Urgency Detected",
      description:
        "Message uses polite scheduling language with flexible options rather than manufactured crisis cues.",
      highlightedText: "Let me know if that time works for you",
      severity: "low",
    },
  ],
  recommendedSteps: [
    {
      id: "step-l1",
      text: "This message appears benign, but always verify unfamiliar requests through trusted channels.",
    },
  ],
  isMock: true,
};

export async function simulateMockAnalysis(text: string, forceError = false): Promise<AnalysisResult> {
  // Simulate network latency (400ms - 600ms)
  await new Promise((resolve) => setTimeout(resolve, 500));

  if (forceError) {
    throw new Error("Simulated network timeout: Unable to reach the analysis service. Please try again.");
  }

  const lower = text.toLowerCase();
  if (lower.includes("disconnect") || lower.includes("blackout") || lower.includes("electricity") || lower.includes("bit.ly")) {
    return MOCK_HIGH_RISK_RESULT;
  }
  if (lower.includes("kyc") || lower.includes("suspend") || lower.includes("pan") || lower.includes("aadhaar") || lower.includes("bank")) {
    return MOCK_MEDIUM_RISK_RESULT;
  }
  return MOCK_LOW_RISK_RESULT;
}
