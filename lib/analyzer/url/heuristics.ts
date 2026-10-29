import { ExtractedUrl, UrlIndicator, AnalyzedUrl } from "./types";
import { evaluateBrandImpersonation } from "./brands";

const KNOWN_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "ow.ly",
  "tiny.cc",
  "clck.ru",
  "rebrand.ly",
  "buff.ly",
]);

const SUSPICIOUS_TLDS = new Set([
  "xyz",
  "top",
  "work",
  "click",
  "buzz",
  "club",
  "live",
  "link",
  "cam",
  "rest",
  "ru",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
]);

const SENSITIVE_PATH_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "verification",
  "kyc",
  "pan-update",
  "aadhaar",
  "banking",
  "netbanking",
  "account-update",
  "reset-password",
  "claim",
  "redeem",
  "reward",
  "bill-pay",
  "auth",
];

const REDIRECT_PARAM_KEYS = new Set([
  "url",
  "redirect",
  "redirect_url",
  "redirect_to",
  "dest",
  "destination",
  "next",
  "target",
  "link",
  "return_to",
  "to",
]);

/**
 * Checks whether a hostname is an IPv4 or IPv6 literal.
 */
export function isIpAddress(hostname: string): boolean {
  // IPv4 format
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return true;
  }
  // IPv6 format (inside brackets or raw hex colons)
  if (/^\[?[a-fA-F0-9:]+\]?$/.test(hostname) && hostname.includes(":")) {
    return true;
  }
  return false;
}

/**
 * Inspects an extracted URL for deceptive structure, brand lookalikes, and technical indicators.
 */
export function analyzeExtractedUrl(extracted: ExtractedUrl): AnalyzedUrl {
  // Handle invalid / unparseable URLs safely
  if (!extracted.isValid || !extracted.parsed) {
    return {
      originalUrl: extracted.originalText,
      normalizedUrl: extracted.normalizedUrl,
      hostname: "unparseable",
      protocol: "unknown",
      isSuspicious: true,
      threatLevel: "medium",
      indicators: [
        {
          code: "MALFORMED_URL",
          title: "Malformed URL Structure",
          description: extracted.parseError || "The URL could not be parsed as a valid web address.",
          severity: "medium",
        },
      ],
      span: extracted.span,
      parseError: extracted.parseError,
    };
  }

  const url = extracted.parsed;
  const hostname = url.hostname.toLowerCase();
  const protocol = url.protocol.toLowerCase();
  const pathname = url.pathname.toLowerCase();
  const indicators: UrlIndicator[] = [];

  // 1. IP Address Host
  if (isIpAddress(hostname)) {
    indicators.push({
      code: "IP_ADDRESS_HOST",
      title: "Direct IP Address Host",
      description: `Links to a numeric IP address (${hostname}) instead of a registered domain name. Legitimate organizations use branded domain names.`,
      severity: "high",
    });
  }

  // 2. URL Shorteners
  if (KNOWN_SHORTENERS.has(hostname)) {
    indicators.push({
      code: "URL_SHORTENER",
      title: "Concealed Destination (URL Shortener)",
      description: `Uses a public link shortener service (${hostname}) that hides the true destination host from the recipient.`,
      severity: "medium",
    });
  }

  // 3. Userinfo (@ component) trick
  if (url.username || url.password || extracted.originalText.includes("@")) {
    // Check if the original text contained an @ trick before the host
    const authorityPart = extracted.originalText.split("/")[2] || "";
    if (authorityPart.includes("@")) {
      indicators.push({
        code: "USERINFO_TRICK",
        title: "Misleading Authority Formatting (@ component)",
        description: "Uses '@' formatting to confuse users into believing they are visiting the domain before the '@' symbol.",
        severity: "high",
      });
    }
  }

  // 4. Unusual Ports
  if (url.port && url.port !== "80" && url.port !== "443" && url.port !== "") {
    indicators.push({
      code: "UNUSUAL_PORT",
      title: "Non-Standard Network Port",
      description: `Connects to an unusual port (:${url.port}) rather than the standard web ports (80/443).`,
      severity: "medium",
    });
  }

  // 5. Insecure HTTP
  if (protocol === "http:") {
    indicators.push({
      code: "INSECURE_HTTP",
      title: "Unencrypted HTTP Protocol",
      description: "Uses unencrypted HTTP connection. While not proof of fraud, official payment and banking portals require HTTPS.",
      severity: "low",
    });
  }

  // 6. Punycode / Homoglyph Characters
  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    indicators.push({
      code: "PUNYCODE_DOMAIN",
      title: "Internationalized / Punycode Domain",
      description: `Uses an internationalized Punycode domain (${hostname}) which may visually mimic Latin letters of trusted brands.`,
      severity: "medium",
    });
  }

  // 7. Credential / Sensitive Path
  const matchingPath = SENSITIVE_PATH_KEYWORDS.find((keyword) => pathname.includes(keyword));
  if (matchingPath) {
    indicators.push({
      code: "CREDENTIAL_PATH",
      title: "Credential or Verification Path",
      description: `Directs to a sensitive path ('/${matchingPath}') often targeted in credential harvesting or phishing portals.`,
      severity: "medium",
    });
  }

  // 8. Suspicious Open Redirect Parameters
  const params = Array.from(url.searchParams.keys());
  const redirectParam = params.find((param) => REDIRECT_PARAM_KEYS.has(param.toLowerCase()));
  if (redirectParam) {
    const val = url.searchParams.get(redirectParam) || "";
    if (val.startsWith("http://") || val.startsWith("https://") || val.startsWith("//")) {
      indicators.push({
        code: "SUSPICIOUS_REDIRECT",
        title: "Open Redirect Parameter",
        description: `Contains a destination redirect parameter ('?${redirectParam}=...') that may route the user to an unverified secondary site.`,
        severity: "medium",
      });
    }
  }

  // 9. High-Risk TLD paired with sensitive keywords
  const hostParts = hostname.split(".");
  const tld = hostParts[hostParts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    const hasSensitiveWord = SENSITIVE_PATH_KEYWORDS.some(
      (kw) => hostname.includes(kw) || pathname.includes(kw)
    );
    if (hasSensitiveWord) {
      indicators.push({
        code: "SUSPICIOUS_TLD",
        title: "High-Risk Domain Extension",
        description: `Uses domain extension '.${tld}' paired with verification or account-related keywords, a common combination in throwaway phishing sites.`,
        severity: "medium",
      });
    }
  }

  // 10. Excessive Subdomain Depth
  if (hostParts.length >= 4 && !isIpAddress(hostname)) {
    indicators.push({
      code: "EXCESSIVE_SUBDOMAINS",
      title: "Deeply Nested Subdomains",
      description: `Contains ${hostParts.length} domain levels, which can be used to hide the true registered domain name.`,
      severity: "low",
    });
  }

  // 11. Brand Impersonation & Lookalike Evaluation
  const brandCheck = evaluateBrandImpersonation(hostname);
  if (brandCheck.isLookalike) {
    indicators.push({
      code: "BRAND_LOOKALIKE",
      title: "Possible Brand Impersonation",
      description: brandCheck.explanation,
      severity: "high",
    });
  }

  // Compute threat level based on indicator severities
  const highCount = indicators.filter((i) => i.severity === "high").length;
  const medCount = indicators.filter((i) => i.severity === "medium").length;
  const lowCount = indicators.filter((i) => i.severity === "low").length;

  let threatLevel: "safe" | "low" | "medium" | "high";

  if (brandCheck.isOfficialDomain && indicators.length === 0) {
    threatLevel = "safe";
  } else if (highCount >= 1 || medCount >= 2) {
    threatLevel = "high";
  } else if (medCount === 1) {
    threatLevel = "medium";
  } else if (lowCount >= 1) {
    threatLevel = "low";
  } else {
    threatLevel = "safe";
  }

  const isSuspicious = threatLevel === "high" || threatLevel === "medium";

  return {
    originalUrl: extracted.originalText,
    normalizedUrl: extracted.normalizedUrl,
    hostname,
    protocol: protocol.replace(":", ""),
    isSuspicious,
    threatLevel,
    indicators,
    brandCheck,
    span: extracted.span,
  };
}
