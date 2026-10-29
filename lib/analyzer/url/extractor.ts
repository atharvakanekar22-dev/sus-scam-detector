import { ExtractedUrl } from "./types";

const MAX_URLS_PER_MESSAGE = 10;

// Trailing punctuation characters that are not part of a URL when at the end
const TRAILING_PUNCTUATION_REGEX = /[.,;:!?)>"'}\]]+$/;

// Leading punctuation characters that should be stripped if matched
const LEADING_PUNCTUATION_REGEX = /^[("'<{[]+/;

/**
 * Robust regex matching http(s):// or www. URLs within unstructured text.
 * Uses bounded character sets to avoid catastrophic backtracking.
 */
const URL_CANDIDATE_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;

/**
 * Extracts URLs from message text, maintaining strict UTF-16 span bounds.
 */
export function extractUrls(text: string): ExtractedUrl[] {
  if (!text || text.length === 0) {
    return [];
  }

  const results: ExtractedUrl[] = [];
  const regex = new RegExp(URL_CANDIDATE_REGEX.source, URL_CANDIDATE_REGEX.flags);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (results.length >= MAX_URLS_PER_MESSAGE) {
      break;
    }

    let rawMatch = match[0];
    let matchStart = match.index;
    let matchEnd = match.index + rawMatch.length;

    // Strip leading punctuation (e.g. parenthesis or quote)
    const leadingMatch = LEADING_PUNCTUATION_REGEX.exec(rawMatch);
    if (leadingMatch) {
      matchStart += leadingMatch[0].length;
      rawMatch = rawMatch.slice(leadingMatch[0].length);
    }

    // Strip trailing punctuation (e.g. period at end of sentence, closing parenthesis)
    const trailingMatch = TRAILING_PUNCTUATION_REGEX.exec(rawMatch);
    if (trailingMatch) {
      matchEnd -= trailingMatch[0].length;
      rawMatch = rawMatch.slice(0, rawMatch.length - trailingMatch[0].length);
    }

    if (rawMatch.length < 4) {
      continue;
    }

    // Verify invariant on sliced bounds
    const exactSlice = text.slice(matchStart, matchEnd);
    if (exactSlice !== rawMatch) {
      continue;
    }

    // Normalize URL for parsing
    let normalized = rawMatch;
    if (rawMatch.toLowerCase().startsWith("www.")) {
      normalized = `https://${rawMatch}`;
    }

    try {
      const parsed = new URL(normalized);
      results.push({
        originalText: rawMatch,
        normalizedUrl: normalized,
        span: {
          start: matchStart,
          end: matchEnd,
          text: rawMatch,
        },
        isValid: true,
        parsed,
      });
    } catch (err: unknown) {
      // Safely preserve unparseable URL as an invalid finding rather than crashing
      const message = err instanceof Error ? err.message : "Malformed URL structure";
      results.push({
        originalText: rawMatch,
        normalizedUrl: normalized,
        span: {
          start: matchStart,
          end: matchEnd,
          text: rawMatch,
        },
        isValid: false,
        parseError: message,
      });
    }
  }

  return results;
}
