import { z } from "zod";

export const AnalyzeRequestSchema = z.object({
  message: z
    .string({ message: "Message is required." })
    .trim()
    .min(5, "Message must contain at least 5 characters.")
    .max(5000, "Message exceeds the maximum limit of 5,000 characters.")
    .refine((val) => val.trim().length > 0, {
      message: "Message cannot consist solely of whitespace.",
    }),
});

export type AnalyzeRequest = z.infer<typeof AnalyzeRequestSchema>;

export const RiskLevelSchema = z.enum(["low", "medium", "high"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const SignalCategorySchema = z.enum([
  "credential_theft",
  "urgency_coercion",
  "financial_pressure",
  "suspicious_link",
  "impersonation",
  "security_advisory",
  "job_scam",
  "investment_fraud",
  "delivery_scam",
  "government_impersonation",
  "remote_access",
  "tech_support",
  "malicious_attachment",
  "upi_payment_scam",
  "utility_cutoff",
]);
export type SignalCategory = z.infer<typeof SignalCategorySchema>;

export const EvidenceSpanSchema = z.object({
  start: z.number().int().nonnegative(),
  end: z.number().int().nonnegative(),
  text: z.string().min(1),
});
export type EvidenceSpan = z.infer<typeof EvidenceSpanSchema>;

export const SignalFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  category: SignalCategorySchema,
  title: z.string(),
  description: z.string(),
  severity: z.enum(["low", "medium", "high"]),
  span: EvidenceSpanSchema,
});
export type SignalFinding = z.infer<typeof SignalFindingSchema>;

export const NextStepItemSchema = z.object({
  id: z.string(),
  text: z.string(),
  actionUrl: z.string().url().optional(),
  actionLabel: z.string().optional(),
});
export type NextStepItem = z.infer<typeof NextStepItemSchema>;

export const UrlIndicatorSchema = z.object({
  code: z.string(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(["low", "medium", "high"]),
});
export type UrlIndicator = z.infer<typeof UrlIndicatorSchema>;

export const UrlBrandCheckSchema = z.object({
  claimedBrand: z.string().optional(),
  isOfficialDomain: z.boolean(),
  isLookalike: z.boolean(),
  confidence: z.enum(["confirmed", "likely", "inconclusive"]),
  explanation: z.string(),
});
export type UrlBrandCheck = z.infer<typeof UrlBrandCheckSchema>;

export const UrlThreatIntelSchema = z.object({
  checked: z.boolean(),
  provider: z.string().optional(),
  malicious: z.boolean().optional(),
  details: z.string().optional(),
});
export type UrlThreatIntel = z.infer<typeof UrlThreatIntelSchema>;

export const AnalyzedUrlSchema = z.object({
  originalUrl: z.string(),
  normalizedUrl: z.string(),
  hostname: z.string(),
  protocol: z.string(),
  isSuspicious: z.boolean(),
  threatLevel: z.enum(["safe", "low", "medium", "high"]),
  indicators: z.array(UrlIndicatorSchema),
  brandCheck: UrlBrandCheckSchema.optional(),
  threatIntel: UrlThreatIntelSchema.optional(),
  span: EvidenceSpanSchema.optional(),
  parseError: z.string().optional(),
});
export type AnalyzedUrl = z.infer<typeof AnalyzedUrlSchema>;

export const AnalyzeResponseSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  riskLevel: RiskLevelSchema,
  heuristicScore: z.number().int().min(0).max(100),
  summary: z.string(),
  findings: z.array(SignalFindingSchema),
  recommendedSteps: z.array(NextStepItemSchema),
  metadata: z.object({
    charCount: z.number().int().min(5).max(5000),
    executionTimeMs: z.number().nonnegative(),
    isHeuristic: z.literal(true),
    analysisMode: z.enum(["gemini", "rules"]),
    analysisNotice: z.string().max(300).optional(),
  }),
  analyzedUrls: z.array(AnalyzedUrlSchema).optional(),
});
export type AnalyzeResponse = z.infer<typeof AnalyzeResponseSchema>;

export const ErrorResponseSchema = z.object({
  error: z.object({
    code: z.enum(["INVALID_INPUT", "OVER_LENGTH", "INTERNAL_ERROR"]),
    message: z.string(),
    details: z.unknown().optional(),
  }),
});
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
