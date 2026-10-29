import { extractUrls } from "./extractor";
import { analyzeExtractedUrl } from "./heuristics";
import { AnalyzedUrl } from "./types";

export * from "./types";
export * from "./extractor";
export * from "./brands";
export * from "./heuristics";
export * from "./ssrf";
export * from "./reputation";

/**
 * High-level pure function to extract and evaluate all URLs found in a message.
 */
export function analyzeUrlsInMessage(text: string): AnalyzedUrl[] {
  const extracted = extractUrls(text);
  return extracted.map((item) => analyzeExtractedUrl(item));
}
