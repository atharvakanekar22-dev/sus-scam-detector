import { EvidenceSpan, UrlIndicator, UrlBrandCheck, UrlThreatIntel, AnalyzedUrl } from "@/lib/schemas";

export interface ExtractedUrl {
  originalText: string;
  normalizedUrl: string;
  span: EvidenceSpan;
  isValid: boolean;
  parseError?: string;
  parsed?: URL;
}

export interface BrandReference {
  id: string;
  name: string;
  category: "bank" | "fintech" | "tech" | "delivery" | "government" | "utility";
  officialDomains: string[];
  keywords: string[];
}

export type { EvidenceSpan, UrlIndicator, UrlBrandCheck, UrlThreatIntel, AnalyzedUrl };
