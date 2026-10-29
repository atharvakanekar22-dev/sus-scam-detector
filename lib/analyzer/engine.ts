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
import { analyzeUrlsInMessage, AnalyzedUrl } from "./url";

/**
 * Pure, deterministic analysis engine for scam message and URL heuristics.
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

      // Check clause-scoped negation suppression
      let isSuppressed = false;

      for (const zone of advisoryZones) {
        const overlaps =
          (start >= zone.start && start < zone.end) ||
          (end > zone.start && end <= zone.end) ||
          (start <= zone.start && end >= zone.end);

        if (overlaps) {
          if (zone.ruleId === "NEG-01" || zone.ruleId === "NEG-02") {
            // Suppress credential solicitation in protective advice clauses
            if (rule.category === "credential_theft") {
              isSuppressed = true;
              break;
            }
          } else if (zone.ruleId === "NEG-03") {
            // Suppress delivery scam alerts in confirmed delivery notices
            if (rule.category === "delivery_scam" || rule.id === "URG-05" || rule.id === "FIN-05") {
              isSuppressed = true;
              break;
            }
          } else if (zone.ruleId === "NEG-04") {
            // General scam awareness / cybercrime bulletin suppresses all detection rules in clause
            isSuppressed = true;
            break;
          } else if (zone.ruleId === "NEG-05") {
            // Routine transaction balance notification suppresses financial pressure in clause
            if (rule.category === "financial_pressure" || rule.category === "upi_payment_scam") {
              isSuppressed = true;
              break;
            }
          }
        }
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

  // Step 3: URL Extraction & Suspicious Link Intelligence
  const analyzedUrls: AnalyzedUrl[] = analyzeUrlsInMessage(message);

  // Integrate URL-level findings without double counting
  const urlFindings: SignalFinding[] = [];
  let urlScoreContribution = 0;

  for (const urlItem of analyzedUrls) {
    if (!urlItem.isSuspicious && urlItem.threatLevel === "safe") {
      continue;
    }

    // Brand impersonation finding
    if (urlItem.brandCheck?.isLookalike && urlItem.span) {
      urlFindings.push({
        id: crypto.randomUUID(),
        ruleId: "LINK-MIMIC",
        category: "impersonation",
        title: "Deceptive Brand Impersonation Domain",
        description: urlItem.brandCheck.explanation,
        severity: "high",
        span: urlItem.span,
      });
    }

    // Technical indicator findings if not already captured by existing link rules
    for (const indicator of urlItem.indicators) {
      if (
        indicator.code === "BRAND_LOOKALIKE" ||
        indicator.code === "INSECURE_HTTP" // Insecure HTTP is a weak signal, summarized in URL panel
      ) {
        continue;
      }

      // Check if this URL span is already flagged by an active regex link rule
      const alreadyCoveredByRule = allMatches.some(
        (m) =>
          !m.isSuppressed &&
          m.rule.category === "suspicious_link" &&
          urlItem.span &&
          m.start <= urlItem.span.start &&
          m.end >= urlItem.span.end
      );

      if (!alreadyCoveredByRule && urlItem.span) {
        urlFindings.push({
          id: crypto.randomUUID(),
          ruleId: `URL-${indicator.code}`,
          category: "suspicious_link",
          title: indicator.title,
          description: indicator.description,
          severity: indicator.severity,
          span: urlItem.span,
        });
      }
    }

    // Add appropriate score weight if not already covered by LINK-01..06
    if (urlItem.threatLevel === "high") {
      urlScoreContribution = Math.max(urlScoreContribution, 30);
    } else if (urlItem.threatLevel === "medium") {
      urlScoreContribution = Math.max(urlScoreContribution, 20);
    }
  }

  // Step 4: De-duplicate unsuppressed matches by Rule ID
  const activeMatches = allMatches.filter((m) => !m.isSuppressed);
  const uniqueTriggeredRules = new Map<string, { rule: RuleDefinition; match: RuleMatch }>();

  for (const match of activeMatches) {
    if (!uniqueTriggeredRules.has(match.rule.id)) {
      uniqueTriggeredRules.set(match.rule.id, { rule: match.rule, match });
    }
  }

  // Step 5: Scoring with Category Caps
  const categoryScores: Record<string, number> = {
    credential_theft: 0,
    urgency_coercion: 0,
    financial_pressure: 0,
    suspicious_link: 0,
    impersonation: 0,
    job_scam: 0,
    investment_fraud: 0,
    delivery_scam: 0,
    government_impersonation: 0,
    remote_access: 0,
    tech_support: 0,
    malicious_attachment: 0,
    upi_payment_scam: 0,
    utility_cutoff: 0,
  };

  for (const { rule } of uniqueTriggeredRules.values()) {
    categoryScores[rule.category] = (categoryScores[rule.category] || 0) + rule.weight;
  }

  // Add URL analysis contribution to suspicious_link category score
  if (urlScoreContribution > 0) {
    categoryScores.suspicious_link = Math.max(
      categoryScores.suspicious_link,
      urlScoreContribution
    );
  }

  // Apply category saturation caps
  let rawCompositeScore = 0;
  for (const [category, uncappedScore] of Object.entries(categoryScores)) {
    const cap = CATEGORY_CAPS[category as keyof typeof CATEGORY_CAPS] ?? 35;
    rawCompositeScore += Math.min(uncappedScore, cap);
  }
  let compositeScore = Math.min(100, rawCompositeScore);

  // Step 6: Critical Trigger Overrides & Risk Precedence
  const activeIds = new Set(Array.from(uniqueTriggeredRules.keys()));

  const hasCred =
    activeIds.has("CRED-01") ||
    activeIds.has("CRED-02") ||
    activeIds.has("CRED-03") ||
    activeIds.has("CRED-04") ||
    activeIds.has("CRED-05") ||
    activeIds.has("AUTH-01") ||
    activeIds.has("AUTH-02") ||
    activeIds.has("KYC-01");
  const hasUrg =
    activeIds.has("URG-01") ||
    activeIds.has("URG-02") ||
    activeIds.has("URG-03") ||
    activeIds.has("URG-04") ||
    activeIds.has("URG-05");
  const hasUtilityCutoff = activeIds.has("URG-01");
  const hasSuspiciousLink =
    activeIds.has("LINK-01") ||
    activeIds.has("LINK-02") ||
    activeIds.has("LINK-03") ||
    activeIds.has("LINK-05") ||
    activeIds.has("LINK-06") ||
    analyzedUrls.some((u) => u.threatLevel === "high" || u.threatLevel === "medium");
  const hasPersonalPhone = activeIds.has("IMP-01");
  const hasLottery = activeIds.has("FIN-02") || activeIds.has("FIN-04");
  const hasAdvanceFee =
    activeIds.has("FIN-03") ||
    activeIds.has("FIN-05") ||
    activeIds.has("JOB-02") ||
    activeIds.has("DELIV-01") ||
    activeIds.has("DELIV-02");
  const hasJobOffer = activeIds.has("JOB-01");
  const hasInvestmentScam = activeIds.has("INV-01") || activeIds.has("INV-02");
  const hasDeliveryScam =
    activeIds.has("DELIV-01") || activeIds.has("DELIV-02") || activeIds.has("URG-05");
  const hasGovThreat = activeIds.has("GOV-01") || activeIds.has("GOV-02");
  const hasRemoteAccess = activeIds.has("REMOTE-01");
  const hasMaliciousApk = activeIds.has("ATTACH-01");
  const hasTechAlert = activeIds.has("TECH-01");
  const hasUpiTrap =
    activeIds.has("UPI-01") || activeIds.has("UPI-02") || activeIds.has("UPI-03");
  const hasBrandLookalike =
    activeIds.has("LINK-03") || analyzedUrls.some((u) => u.brandCheck?.isLookalike);

  // Critical Overrides
  const overrideA = hasCred && hasUrg; // Credential demand + urgency threat
  const overrideB = hasUtilityCutoff && (hasSuspiciousLink || hasPersonalPhone); // Power shutoff + fake link/phone
  const overrideC = hasLottery && hasAdvanceFee; // Lottery lure + advance processing fee
  const overrideD = hasUrg && hasSuspiciousLink; // Urgent account/delivery threat + action link
  const overrideE = hasLottery && hasCred; // Prize claim + request for personal or bank details
  const overrideF = hasAdvanceFee && hasSuspiciousLink; // Advance fee or promised return + link
  const overrideG = activeIds.has("GOV-01"); // Digital arrest / police arrest warrant threat
  const overrideH = Boolean(hasRemoteAccess); // Demands installation of remote desktop app
  const overrideI = Boolean(hasUpiTrap); // UPI PIN to receive money / QR code receive trap
  const overrideJ = hasDeliveryScam && (hasSuspiciousLink || hasAdvanceFee || activeIds.has("DELIV-02")); // Fake delivery + link or fee or customs
  const overrideK = hasJobOffer && hasAdvanceFee; // Job offer + registration fee
  const overrideL = hasInvestmentScam && (hasSuspiciousLink || hasAdvanceFee || activeIds.has("INV-01")); // Guaranteed investment return + link
  const overrideM = Boolean(hasMaliciousApk); // Direct prompt to download .apk file
  const overrideN =
    hasBrandLookalike &&
    (hasCred || hasUrg || activeIds.has("BANK-01") || activeIds.has("KYC-01"));
  const overrideP = hasTechAlert && (hasPersonalPhone || hasUrg || activeIds.has("IMP-02"));

  const isCriticalOverride =
    overrideA ||
    overrideB ||
    overrideC ||
    overrideD ||
    overrideE ||
    overrideF ||
    overrideG ||
    overrideH ||
    overrideI ||
    overrideJ ||
    overrideK ||
    overrideL ||
    overrideM ||
    overrideN ||
    overrideP;

  let riskLevel: RiskLevel;

  if (activeIds.size === 0 && urlFindings.length === 0 && advisoryZones.length > 0) {
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

  // Step 7: Assemble Findings
  const findings: SignalFinding[] = [];

  // Add benign advisory findings if detected
  for (const zone of advisoryZones) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: zone.ruleId,
      category: "security_advisory",
      title: "Legitimate Security Advisory",
      description:
        "Contains standard educational advice cautioning the recipient against disclosing sensitive credentials.",
      severity: "low",
      span: {
        start: zone.start,
        end: zone.end,
        text: message.slice(zone.start, zone.end),
      },
    });
  }

  // Add active scam rule matches
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

  // Add URL analysis findings
  for (const urlFinding of urlFindings) {
    findings.push(urlFinding);
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

  // Step 8: Summary & Guidance Synthesis
  let summary = "";
  if (riskLevel === "high") {
    if (hasGovThreat) {
      summary =
        "This message exhibits patterns of government or law enforcement coercion (such as digital arrest or fake warrants) used to intimidate victims into compliance.";
    } else if (hasUpiTrap) {
      summary =
        "This message attempts to exploit payment mechanics by asking you to enter a UPI PIN or scan a QR code to receive money, which results in funds being debited.";
    } else if (hasRemoteAccess) {
      summary =
        "This message directs you to install remote desktop software. Scammers use these tools to gain complete remote control over your device and bank accounts.";
    } else if (hasMaliciousApk) {
      summary =
        "This message prompts you to download an unauthorized application package (.apk). Sideloaded apps frequently contain spyware or banking trojans.";
    } else {
      summary =
        "This message exhibits strong patterns commonly associated with fraudulent coercion, including urgent threats, unverified contact channels, or direct credential requests.";
    }
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

  if (hasUpiTrap) {
    recommendedSteps.push({
      id: "step-upi",
      text: "Remember: Entering your UPI PIN or scanning a QR code is ONLY for sending money, never for receiving money or refunds.",
    });
  }

  if (hasRemoteAccess) {
    recommendedSteps.push({
      id: "step-remote",
      text: "Never install AnyDesk, TeamViewer, or QuickSupport on instructions from callers or text messages. Delete any downloaded installation files.",
    });
  }

  if (hasMaliciousApk) {
    recommendedSteps.push({
      id: "step-apk",
      text: "Do NOT install APK files sent via text or WhatsApp. Only download apps from official app stores like Google Play or Apple App Store.",
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

  if (hasGovThreat) {
    recommendedSteps.push({
      id: "step-gov",
      text: "Police, CBI, Customs, and courts NEVER conduct digital arrests or demand money transfers over video calls or messaging apps.",
    });
  }

  if (hasJobOffer && hasAdvanceFee) {
    recommendedSteps.push({
      id: "step-job",
      text: "Legitimate companies never demand upfront registration or kit fees to secure part-time or work-from-home employment.",
    });
  }

  if (hasDeliveryScam) {
    recommendedSteps.push({
      id: "step-deliv",
      text: "Check package tracking directly on the courier's official website. Never pay delivery fees via SMS or chat links.",
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
    analyzedUrls,
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
