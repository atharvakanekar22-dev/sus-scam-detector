import { UrlThreatIntel } from "./types";
import { validateUrlForOutboundFetch } from "./ssrf";

interface CacheEntry {
  intel: UrlThreatIntel;
  expiresAt: number;
}

// In-memory cache with 10-minute TTL to avoid redundant lookups and respect rate limits
const reputationCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 10 * 60 * 1000;

/**
 * Checks external threat intelligence for a specific URL if configured.
 *
 * Privacy & Security Guarantees:
 * - Only the sanitized URL is queried; message text is never sent.
 * - Local heuristic inspection is primary; external lookups are strictly optional.
 * - Server credentials never leave the server.
 * - Outbound destinations are strictly validated against SSRF.
 */
export async function checkUrlReputation(
  rawUrl: string,
  apiKey = process.env.URL_THREAT_INTEL_API_KEY || process.env.GOOGLE_SAFE_BROWSING_API_KEY
): Promise<UrlThreatIntel> {
  // If no external service is configured, explicitly state that local heuristics are active
  if (!apiKey) {
    return {
      checked: false,
      provider: "local_heuristics",
      details: "External threat intelligence is not configured. Results derived from local heuristics.",
    };
  }

  // SSRF and safety check before any network interaction
  const ssrfCheck = validateUrlForOutboundFetch(rawUrl);
  if (!ssrfCheck.safe || !ssrfCheck.parsedUrl) {
    return {
      checked: false,
      provider: "local_heuristics",
      details: `Destination not checked externally: ${ssrfCheck.reason}`,
    };
  }

  const cacheKey = ssrfCheck.parsedUrl.origin + ssrfCheck.parsedUrl.pathname;
  const cached = reputationCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.intel;
  }

  try {
    // Example: Google Safe Browsing Lookup v4 or generic threat intelligence lookup
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "sus-scam-detector",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: rawUrl }],
        },
      }),
      signal: AbortSignal.timeout(3000),
      cache: "no-store",
    });

    if (!response.ok) {
      return {
        checked: false,
        provider: "threat_intel",
        details: `Threat intelligence provider responded with status ${response.status}. Fallback to local heuristics.`,
      };
    }

    const data = await response.json();
    const hasMatches = Array.isArray(data?.matches) && data.matches.length > 0;

    const intel: UrlThreatIntel = {
      checked: true,
      provider: "google_safe_browsing",
      malicious: hasMatches,
      details: hasMatches
        ? `Identified as malicious or phishing by external threat intelligence (${data.matches[0]?.threatType || "MATCH"}).`
        : "Not listed as active threat in external threat intelligence database.",
    };

    reputationCache.set(cacheKey, {
      intel,
      expiresAt: Date.now() + CACHE_TTL_MS,
    });

    return intel;
  } catch {
    return {
      checked: false,
      provider: "threat_intel",
      details: "Threat intelligence query timed out or was unreachable. Using local heuristics.",
    };
  }
}
