import { BrandReference, UrlBrandCheck } from "./types";

export const BRAND_REGISTRY: BrandReference[] = [
  {
    id: "sbi",
    name: "State Bank of India",
    category: "bank",
    officialDomains: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbi.in", "onlinesbi.com"],
    keywords: ["sbi", "onlinesbi", "statebank"],
  },
  {
    id: "hdfc",
    name: "HDFC Bank",
    category: "bank",
    officialDomains: ["hdfcbank.com", "hdfc.com"],
    keywords: ["hdfc", "hdfcbank"],
  },
  {
    id: "icici",
    name: "ICICI Bank",
    category: "bank",
    officialDomains: ["icicibank.com", "icicidirect.com"],
    keywords: ["icici", "icicibank"],
  },
  {
    id: "axis",
    name: "Axis Bank",
    category: "bank",
    officialDomains: ["axisbank.com"],
    keywords: ["axisbank", "axis-bank"],
  },
  {
    id: "pnb",
    name: "Punjab National Bank",
    category: "bank",
    officialDomains: ["pnbindia.in", "netpnb.com"],
    keywords: ["pnb", "pnbindia"],
  },
  {
    id: "bob",
    name: "Bank of Baroda",
    category: "bank",
    officialDomains: ["bankofbaroda.in", "bobibanking.com"],
    keywords: ["bankofbaroda", "bobworld"],
  },
  {
    id: "kotak",
    name: "Kotak Mahindra Bank",
    category: "bank",
    officialDomains: ["kotak.com"],
    keywords: ["kotak", "kotakbank", "kotak811"],
  },
  {
    id: "rbi",
    name: "Reserve Bank of India",
    category: "bank",
    officialDomains: ["rbi.org.in"],
    keywords: ["rbi"],
  },
  {
    id: "paytm",
    name: "Paytm",
    category: "fintech",
    officialDomains: ["paytm.com", "paytmbank.com"],
    keywords: ["paytm"],
  },
  {
    id: "phonepe",
    name: "PhonePe",
    category: "fintech",
    officialDomains: ["phonepe.com"],
    keywords: ["phonepe"],
  },
  {
    id: "google_pay",
    name: "Google Pay",
    category: "fintech",
    officialDomains: ["pay.google.com", "google.com"],
    keywords: ["gpay", "googlepay"],
  },
  {
    id: "npci_bhim",
    name: "BHIM / NPCI",
    category: "fintech",
    officialDomains: ["bhimupi.org.in", "npci.org.in"],
    keywords: ["bhim", "npci", "upi"],
  },
  {
    id: "paypal",
    name: "PayPal",
    category: "fintech",
    officialDomains: ["paypal.com", "paypal.me"],
    keywords: ["paypal"],
  },
  {
    id: "cred",
    name: "CRED",
    category: "fintech",
    officialDomains: ["cred.club"],
    keywords: ["cred"],
  },
  {
    id: "indiapost",
    name: "India Post",
    category: "delivery",
    officialDomains: ["indiapost.gov.in", "postnlp.gov.in"],
    keywords: ["indiapost", "speedpost", "dakghar"],
  },
  {
    id: "dhl",
    name: "DHL",
    category: "delivery",
    officialDomains: ["dhl.com", "dhl.de"],
    keywords: ["dhl"],
  },
  {
    id: "fedex",
    name: "FedEx",
    category: "delivery",
    officialDomains: ["fedex.com"],
    keywords: ["fedex"],
  },
  {
    id: "bluedart",
    name: "Blue Dart",
    category: "delivery",
    officialDomains: ["bluedart.com"],
    keywords: ["bluedart"],
  },
  {
    id: "delhivery",
    name: "Delhivery",
    category: "delivery",
    officialDomains: ["delhivery.com"],
    keywords: ["delhivery"],
  },
  {
    id: "dtdc",
    name: "DTDC",
    category: "delivery",
    officialDomains: ["dtdc.in"],
    keywords: ["dtdc"],
  },
  {
    id: "cybercrime",
    name: "National Cyber Crime Reporting Portal",
    category: "government",
    officialDomains: ["cybercrime.gov.in"],
    keywords: ["cybercrime", "cyberpolice"],
  },
  {
    id: "incometax",
    name: "Income Tax Department of India",
    category: "government",
    officialDomains: ["incometax.gov.in", "incometaxindia.gov.in"],
    keywords: ["incometax", "itdepartment"],
  },
  {
    id: "uidai",
    name: "UIDAI (Aadhaar)",
    category: "government",
    officialDomains: ["uidai.gov.in", "eaadhaar.uidai.gov.in"],
    keywords: ["uidai", "aadhaar"],
  },
  {
    id: "parivahan",
    name: "Parivahan (e-Challan)",
    category: "government",
    officialDomains: ["parivahan.gov.in", "echallan.parivahan.gov.in"],
    keywords: ["parivahan", "echallan"],
  },
  {
    id: "amazon",
    name: "Amazon",
    category: "tech",
    officialDomains: ["amazon.in", "amazon.com", "amzn.to"],
    keywords: ["amazon"],
  },
  {
    id: "apple",
    name: "Apple",
    category: "tech",
    officialDomains: ["apple.com", "icloud.com"],
    keywords: ["apple", "icloud"],
  },
  {
    id: "microsoft",
    name: "Microsoft",
    category: "tech",
    officialDomains: ["microsoft.com", "live.com", "office.com"],
    keywords: ["microsoft", "office365"],
  },
  {
    id: "netflix",
    name: "Netflix",
    category: "tech",
    officialDomains: ["netflix.com"],
    keywords: ["netflix"],
  },
];

/**
 * Calculates Levenshtein distance between two strings for typosquatting detection.
 */
function levenshteinDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 1) {
    return 99;
  }

  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array(b.length + 1).fill(0);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) {
        curr[j] = prev[j - 1];
      } else {
        curr[j] = Math.min(
          prev[j] + 1, // deletion
          curr[j - 1] + 1, // insertion
          prev[j - 1] + 1 // substitution
        );
      }
    }
    const temp = prev;
    prev = curr;
    curr = temp;
  }

  return prev[b.length];
}

/**
 * Normalizes host strings for comparison (removes port, lowercase).
 */
export function normalizeHost(hostname: string): string {
  return hostname.trim().toLowerCase().split(":")[0];
}

/**
 * Checks if a hostname is an exact match or legitimate subdomain of an official domain.
 */
export function isOfficialSubdomain(hostname: string, officialDomain: string): boolean {
  const normHost = normalizeHost(hostname);
  const normOfficial = normalizeHost(officialDomain);
  return normHost === normOfficial || normHost.endsWith(`.${normOfficial}`);
}

/**
 * Inspects a parsed hostname against known brand reference domains.
 */
export function evaluateBrandImpersonation(hostname: string): UrlBrandCheck {
  const normHost = normalizeHost(hostname);

  // Check if hostname is an IP address
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(normHost)) {
    return {
      isOfficialDomain: false,
      isLookalike: false,
      confidence: "inconclusive",
      explanation: "Destination uses an IP address instead of a domain name.",
    };
  }

  // Check against all registered brands
  for (const brand of BRAND_REGISTRY) {
    // 1. Check if it matches an official domain or legitimate subdomain
    for (const officialDomain of brand.officialDomains) {
      if (isOfficialSubdomain(normHost, officialDomain)) {
        return {
          claimedBrand: brand.name,
          isOfficialDomain: true,
          isLookalike: false,
          confidence: "confirmed",
          explanation: `Verified official domain or authorized subdomain of ${brand.name}.`,
        };
      }
    }

    // 2. Check for deceptive inclusion of brand keywords in unrelated domain
    // Examples: sbi-kyc-update.com, hdfc.account-verify.in, paytm-cash.net
    const hostParts = normHost.split(".");
    const registrablePart = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : normHost;

    for (const keyword of brand.keywords) {
      // Direct keyword match in subdomain or registrable domain
      const containsKeyword = normHost.includes(keyword);

      if (containsKeyword) {
        // We know it is NOT an official domain (passed above)
        // Check if the keyword appears as a hyphenated lure (e.g. sbi-kyc, verify-hdfc)
        const isHyphenatedMimic = new RegExp(`(?:^|[.-])${keyword}(?:[.-]|$)`).test(normHost);
        const isSubdomainTrap = hostParts.some((part, idx) => idx < hostParts.length - 2 && part.includes(keyword));

        if (isHyphenatedMimic || isSubdomainTrap || registrablePart.includes(keyword)) {
          return {
            claimedBrand: brand.name,
            isOfficialDomain: false,
            isLookalike: true,
            confidence: "likely",
            explanation: `The domain '${normHost}' appears to imitate ${brand.name}, but does not match its official domain (${brand.officialDomains[0]}).`,
          };
        }
      }

      // Check for Levenshtein typo-squatting on registrable part if length >= 4 and lengths are within 1 char
      if (
        keyword.length >= 4 &&
        registrablePart.length >= 4 &&
        registrablePart.length <= 63 &&
        Math.abs(registrablePart.length - keyword.length) <= 1
      ) {
        const dist = levenshteinDistance(registrablePart, keyword);
        if (dist === 1 && registrablePart !== keyword) {
          return {
            claimedBrand: brand.name,
            isOfficialDomain: false,
            isLookalike: true,
            confidence: "likely",
            explanation: `Possible typosquatting variation of ${brand.name}: '${registrablePart}' closely resembles '${keyword}'.`,
          };
        }
      }
    }
  }

  return {
    isOfficialDomain: false,
    isLookalike: false,
    confidence: "inconclusive",
    explanation: "Domain does not match known official brand reference lists.",
  };
}
