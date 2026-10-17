import { RuleDefinition, AdvisoryZone, ClauseSpan } from "./types";
import { CLAUSE_DELIMITER_REGEX } from "./constants";

export const NEGATION_RULES: RuleDefinition[] = [
  {
    id: "NEG-01",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Protective Security Advisory",
    description: "Contains legitimate educational advice warning the recipient never to share passwords or OTPs.",
    pattern: /\b(?:never|do\s+not|don'?t|should\s+never|will\s+never)\s+(?:share|disclose|give|send|tell|reveal|ask\s+for)\b[^.!?;\n]*?\b(?:otp|one[- ]time[- ]password|pin|password|cvv|credentials?)\b/gi,
    isNegation: true,
  },
  {
    id: "NEG-02",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Security Caution Warning",
    description: "Contains precautionary warning against sharing credentials or clicking unauthorized links.",
    pattern: /\b(?:beware\s+of|caution:?\s+do\s+not|alert:?\s+never)\b[^.!?;\n]*?\b(?:otp|links?|calls?|password)\b/gi,
    isNegation: true,
  },
];

export const DETECTION_RULES: RuleDefinition[] = [
  {
    id: "CRED-01",
    category: "credential_theft",
    weight: 35,
    severity: "high",
    title: "Direct OTP / PIN Solicitation",
    description: "Asks recipient to communicate or submit sensitive one-time passwords or security PINs.",
    pattern: /\b(?:send|share|enter|provide|verify|tell|forward)\s+(?:(?:us|me)\s+)?(?:your\s+)?(?:the\s+)?\b(?:otp|one[- ]time[- ]password|pin|secret\s+code)\b/gi,
  },
  {
    id: "CRED-02",
    category: "credential_theft",
    weight: 30,
    severity: "high",
    title: "Identity & Card Credential Demand",
    description: "Requests submission or re-verification of sensitive national identity cards or card security codes.",
    pattern: /\b(?:update|verify|re-?verify|submit)\b[^.!?;\n]*?\b(?:aadhaar|pan\s+card|pan\s+number|debit\s+card|credit\s+card|cvv)\b/gi,
  },
  {
    id: "CRED-03",
    category: "credential_theft",
    weight: 25,
    severity: "high",
    title: "Banking Password Solicitation",
    description: "Prompts for confidential net-banking or mobile-banking login credentials.",
    pattern: /\b(?:net\s*banking|mobile\s*banking|account)\s+(?:password|login\s+credentials?|pin)\b/gi,
  },
  {
    id: "URG-01",
    category: "urgency_coercion",
    weight: 30,
    severity: "high",
    title: "Utility Disconnection Threat",
    description: "Threatens imminent termination of essential electric power or utility services within hours.",
    pattern: /\b(?:power|electricity|connection)\b[^.!?;\n]*?\b(?:disconnect(?:ed)?|cut[- ]off|blackout)\s+(?:tonight|today|within\s+\d+\s+hours?|immediately)\b/gi,
  },
  {
    id: "URG-02",
    category: "urgency_coercion",
    weight: 25,
    severity: "high",
    title: "Artificial Suspension Countdown",
    description: "Imposes an artificial countdown to block banking access, cards, or SIM cards to bypass critical scrutiny.",
    pattern: /\b(?:account|card|sim|access)\s+(?:will\s+be\s+|has\s+been\s+)?(?:blocked|suspended|terminated|deactivated)(?:\s+(?:within|in)\s+\d+\s+(?:hours?|minutes?|days?))?\b|\b(?:card\s+block|blocked\s+card|unlock\s+(?:your\s+)?(?:account|card|access))\b/gi,
  },
  {
    id: "URG-03",
    category: "urgency_coercion",
    weight: 15,
    severity: "medium",
    title: "Urgency Pressure Language",
    description: "Employs high-pressure urgency words to induce hurried emotional reactions.",
    pattern: /\b(?:urgent|immediately|act\s+now|right\s+now|last\s+chance|final\s+notice|time\s+sensitive|now)\b/gi,
  },
  {
    id: "FIN-01",
    category: "financial_pressure",
    weight: 20,
    severity: "medium",
    title: "Unpaid Bill Dues Claim",
    description: "Claims existing dues or pending utility payments must be settled immediately.",
    pattern: /\b(?:unpaid|previous\s+month|pending|overdue)\s+(?:bill|electricity\s+bill|dues)\b|\b(?:previous\s+month\s+)?(?:electricity\s+)?bill\s+(?:is\s+)?unpaid\b|\b(?:electricity\s+)?bill\s+dues\b/gi,
  },
  {
    id: "FIN-02",
    category: "financial_pressure",
    weight: 25,
    severity: "medium",
    title: "Unsolicited Prize or Refund Lure",
    description: "Announces unexpected lottery winnings, large cash rewards, or tax refunds to lure engagement.",
    pattern: /\b(?:won|lottery|cashback|reward|tax\s+refund)\b[^.!?;\n]*?\b(?:rs\.?|inr|₹|\$)\s*[\d,]+\b/gi,
  },
  {
    id: "FIN-03",
    category: "financial_pressure",
    weight: 25,
    severity: "high",
    title: "Advance Fee Demand",
    description: "Demands an upfront fee or deposit to release supposed prizes or loan amounts.",
    pattern: /\b(?:send|transfer|deposit|pay)\s+(?:processing\s+fee|token\s+amount|advance|clearance\s+charge)\b/gi,
  },
  {
    id: "LINK-01",
    category: "suspicious_link",
    weight: 25,
    severity: "high",
    title: "Obfuscated / Shortened Link",
    description: "Uses public URL shorteners that obscure the real final destination domain.",
    pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9_-]+/gi,
  },
  {
    id: "LINK-02",
    category: "suspicious_link",
    weight: 30,
    severity: "high",
    title: "Raw IP Address Link",
    description: "Directs recipient to a raw IP address rather than a registered, branded domain name.",
    pattern: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s]*)?/gi,
  },
  {
    id: "LINK-03",
    category: "suspicious_link",
    weight: 30,
    severity: "high",
    title: "Deceptive Brand Mimic Link",
    description: "Directs to a domain name containing hyphenated brand mimicry words commonly used in phishing portals.",
    pattern: /https?:\/\/(?=[a-zA-Z0-9.-]*-(?:kyc|bank|support|verify|bill|login))[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/gi,
  },
  {
    id: "LINK-04",
    category: "suspicious_link",
    weight: 15,
    severity: "medium",
    title: "Unencrypted HTTP Link",
    description: "Uses insecure, unencrypted HTTP protocol for sensitive portal access.",
    pattern: /http:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/gi,
  },
  {
    id: "IMP-01",
    category: "impersonation",
    weight: 25,
    severity: "high",
    title: "Unofficial Personal Contact Channel",
    description: "Instructs resolution of official billing or service disputes via a personal 10-digit mobile number.",
    pattern: /\b(?:contact|call|whatsapp|reach)\s+(?:our\s+)?(?:[a-zA-Z]+\s+)?(?:officer|executive|manager|agent)\s+(?:at\s+|on\s+)?(?:[+]?91[- ]?)?[6-9]\d{4}[- ]?\d{5}\b/gi,
  },
  {
    id: "IMP-02",
    category: "impersonation",
    weight: 20,
    severity: "medium",
    title: "Personal Mobile as Helpline",
    description: "Presents a personal mobile number as an official corporate or utility customer desk.",
    pattern: /\b(?:customer\s+care|helpline|support\s+desk)\s+(?:at\s+|on\s+)?[6-9]\d{9}\b/gi,
  },
];

/**
 * Segment raw message into clause spans using sentence/clause delimiters.
 */
export function segmentClauses(text: string): ClauseSpan[] {
  const clauses: ClauseSpan[] = [];
  let currentStart = 0;

  const delimiterRegex = new RegExp(CLAUSE_DELIMITER_REGEX.source, "gi");
  let match: RegExpExecArray | null;

  while ((match = delimiterRegex.exec(text)) !== null) {
    const end = match.index;
    if (end > currentStart) {
      clauses.push({
        start: currentStart,
        end,
        text: text.slice(currentStart, end),
      });
    }
    currentStart = match.index + match[0].length;
  }

  if (currentStart < text.length) {
    clauses.push({
      start: currentStart,
      end: text.length,
      text: text.slice(currentStart),
    });
  }

  return clauses;
}

/**
 * Detect advisory suppression zones where protective negation is active.
 */
export function findAdvisoryZones(text: string): AdvisoryZone[] {
  const clauses = segmentClauses(text);
  const zones: AdvisoryZone[] = [];

  for (const clause of clauses) {
    for (const rule of NEGATION_RULES) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
      const match = regex.exec(clause.text);
      if (match) {
        zones.push({
          start: clause.start,
          end: clause.end,
          matchedText: match[0],
          ruleId: rule.id as "NEG-01" | "NEG-02",
        });
        break; // One negation match per clause is sufficient
      }
    }
  }

  return zones;
}
