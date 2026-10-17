import {
  AnalyzeRequestSchema,
  AnalyzeResponse,
  AnalyzeResponseSchema,
  SignalFinding,
  NextStepItem,
  RiskLevel,
} from "@/lib/schemas";
import { DETECTION_RULES, findAdvisoryZones } from "./rules";
import { RuleDefinition, RuleMatch } from "./types";
import {
  CATEGORY_CAPS,
  RISK_THRESHOLDS,
  CYBERCRIME_PORTAL_URL,
} from "./constants";

/**
 * Pure, deterministic analysis engine for scam message heuristics.
 */
export function analyzeMessage(rawInput: string): AnalyzeResponse {
  const startTime = performance.now();

  // Validate input schema
  AnalyzeRequestSchema.parse({ message: rawInput });

  // Input string is preserved strictly unmodified
  const message = rawInput;

  // Step 1: Detect Advisory Suppression Zones (Clause-Scoped Negation)
  const advisoryZones = findAdvisoryZones(message);

  // Step 2: Multi-Category Rule Execution
  const allMatches: RuleMatch[] = [];

  for (const rule of DETECTION_RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(message)) !== null) {
      const start = match.index;
      const end = match.index + match[0].length;
      const matchedText = match[0];

      // Check if this credential match falls within an active advisory suppression zone
      let isSuppressed = false;
      if (rule.category === "credential_theft") {
        isSuppressed = advisoryZones.some(
          (zone) =>
            (start >= zone.start && start < zone.end) ||
            (end > zone.start && end <= zone.end) ||
            (start <= zone.start && end >= zone.end)
        );
      }

      allMatches.push({
        rule,
        start,
        end,
        matchedText,
        isSuppressed,
      });

      // Avoid infinite loops with zero-length matches (regex safeguard)
      if (match.index === regex.lastIndex) {
        regex.lastIndex++;
      }
    }
  }

  // Step 3: De-duplicate unsuppressed matches by Rule ID
  const activeMatches = allMatches.filter((m) => !m.isSuppressed);
  const uniqueTriggeredRules = new Map<string, { rule: RuleDefinition; match: RuleMatch }>();

  for (const match of activeMatches) {
    if (!uniqueTriggeredRules.has(match.rule.id)) {
      uniqueTriggeredRules.set(match.rule.id, { rule: match.rule, match });
    }
  }

  // Step 4: Scoring with Category Caps
  const categoryScores: Record<string, number> = {
    credential_theft: 0,
    urgency_coercion: 0,
    financial_pressure: 0,
    suspicious_link: 0,
    impersonation: 0,
  };

  for (const { rule } of uniqueTriggeredRules.values()) {
    categoryScores[rule.category] = (categoryScores[rule.category] || 0) + rule.weight;
  }

  // Apply category saturation caps
  let rawCompositeScore = 0;
  for (const [category, uncappedScore] of Object.entries(categoryScores)) {
    const cap = CATEGORY_CAPS[category as keyof typeof CATEGORY_CAPS] ?? 100;
    rawCompositeScore += Math.min(uncappedScore, cap);
  }
  let compositeScore = Math.min(100, rawCompositeScore);

  // Step 5: Critical Trigger Overrides & Risk Precedence
  const activeIds = new Set(Array.from(uniqueTriggeredRules.keys()));

  const hasCred =
    activeIds.has("CRED-01") ||
    activeIds.has("CRED-02") ||
    activeIds.has("CRED-03") ||
    activeIds.has("CRED-04") ||
    activeIds.has("CRED-05");
  const hasUrg =
    activeIds.has("URG-01") ||
    activeIds.has("URG-02") ||
    activeIds.has("URG-03") ||
    activeIds.has("URG-04") ||
    activeIds.has("URG-05");
  const hasUtilityCutoff = activeIds.has("URG-01");
  const hasSuspiciousLink =
    activeIds.has("LINK-01") ||
    activeIds.has("LINK-03") ||
    activeIds.has("LINK-05") ||
    activeIds.has("LINK-06");
  const hasPersonalPhone = activeIds.has("IMP-01");
  const hasLottery = activeIds.has("FIN-02") || activeIds.has("FIN-04");
  const hasAdvanceFee =
    activeIds.has("FIN-03") || activeIds.has("FIN-05");

  // Critical Overrides
  const overrideA = hasCred && hasUrg; // Credential demand + urgency threat
  const overrideB = hasUtilityCutoff && (hasSuspiciousLink || hasPersonalPhone); // Power shutoff + fake link/phone
  const overrideC = hasLottery && hasAdvanceFee; // Lottery lure + advance processing fee
  const overrideD = hasUrg && hasSuspiciousLink; // Urgent account/delivery threat + action link
  const overrideE = hasLottery && hasCred; // Prize claim + request for personal or bank details
  const overrideF = hasAdvanceFee && hasSuspiciousLink; // Advance fee or promised return + link

  const isCriticalOverride =
    overrideA || overrideB || overrideC || overrideD || overrideE || overrideF;

  let riskLevel: RiskLevel;

  if (activeIds.size === 0 && advisoryZones.length > 0) {
    // Advisory Only Precedence
    riskLevel = "low";
    compositeScore = 0;
  } else if (isCriticalOverride) {
    // Critical Override Precedence
    riskLevel = "high";
    compositeScore = Math.max(compositeScore, RISK_THRESHOLDS.OVERRIDE_FLOOR_SCORE);
  } else if (compositeScore >= RISK_THRESHOLDS.HIGH_MIN) {
    riskLevel = "high";
  } else if (compositeScore >= RISK_THRESHOLDS.MEDIUM_MIN) {
    riskLevel = "medium";
  } else {
    riskLevel = "low";
  }

  // Step 6: Assemble Findings
  const findings: SignalFinding[] = [];

  // Add benign advisory findings if detected
  for (const zone of advisoryZones) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: zone.ruleId,
      category: "security_advisory",
      title: "Legitimate Security Advisory",
      description: "Contains standard educational advice cautioning the recipient against disclosing sensitive credentials.",
      severity: "low",
      span: {
        start: zone.start,
        end: zone.end,
        text: message.slice(zone.start, zone.end),
      },
    });
  }

  // Add active scam findings
  for (const match of activeMatches) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: match.rule.id,
      category: match.rule.category,
      title: match.rule.title,
      description: match.rule.description,
      severity: match.rule.severity,
      span: {
        start: match.start,
        end: match.end,
        text: match.matchedText,
      },
    });
  }

  // Invariant Assertion: Verify every span matches unmodified string bounds
  for (const f of findings) {
    if (
      f.span.start < 0 ||
      f.span.end > message.length ||
      f.span.start >= f.span.end ||
      message.slice(f.span.start, f.span.end) !== f.span.text
    ) {
      throw new Error(
        `Internal invariant violation: span [${f.span.start}, ${f.span.end}] does not match slice of input string.`
      );
    }
  }

  // Step 7: Summary & Guidance Synthesis
  let summary = "";
  if (riskLevel === "high") {
    summary =
      "This message exhibits strong patterns commonly associated with fraudulent coercion, including urgent threats, unverified contact channels, or direct credential requests.";
  } else if (riskLevel === "medium") {
    summary =
      "This message contains moderate urgency, billing claims, or unverified links that warrant caution before interacting.";
  } else if (advisoryZones.length > 0) {
    summary =
      "This message contains standard protective security advice. No common deception patterns were detected.";
  } else {
    summary =
      "No common scam patterns were detected in this message. Low risk does not guarantee the message is authentic; always verify unfamiliar requests independently.";
  }

  // Recommendations
  const recommendedSteps: NextStepItem[] = [];

  if (hasCred) {
    recommendedSteps.push({
      id: "step-cred",
      text: "Never share OTPs, PINs, or card CVVs. Legitimate banks and service providers never ask for security codes via SMS or chat.",
    });
  }

  if (hasUtilityCutoff) {
    recommendedSteps.push({
      id: "step-util",
      text: "Verify any power disconnection or utility billing claims directly on your official state electricity board portal.",
    });
  }

  if (hasSuspiciousLink) {
    recommendedSteps.push({
      id: "step-link",
      text: "Do not open unverified links or shortened URLs. Type official domain addresses directly into your browser.",
    });
  }

  if (hasPersonalPhone) {
    recommendedSteps.push({
      id: "step-phone",
      text: "Do not call personal 10-digit mobile numbers claiming to represent corporate billing departments.",
    });
  }

  if (riskLevel === "high") {
    recommendedSteps.push({
      id: "step-report",
      text: "Report fraudulent numbers and deceptive messages to the National Cyber Crime Reporting Portal.",
      actionUrl: CYBERCRIME_PORTAL_URL,
      actionLabel: "Visit cybercrime.gov.in",
    });
  }

  if (recommendedSteps.length === 0) {
    recommendedSteps.push({
      id: "step-default",
      text: "Exercise standard digital caution. Never send money or sensitive details to unverified contacts.",
    });
  }

  const executionTimeMs = Math.round((performance.now() - startTime) * 100) / 100;

  const response: AnalyzeResponse = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    riskLevel,
    heuristicScore: compositeScore,
    summary,
    findings,
    recommendedSteps,
    metadata: {
      charCount: message.length,
      executionTimeMs,
      isHeuristic: true,
      analysisMode: "rules",
    },
  };

  // Validate output against Zod contract
  return AnalyzeResponseSchema.parse(response);
}
