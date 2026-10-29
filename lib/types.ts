import { AnalyzedUrl } from "./schemas";

export type RiskLevel = "low" | "medium" | "high";

export interface SignalFinding {
  id: string;
  category: string;
  ruleId?: string;
  title: string;
  description: string;
  highlightedText?: string;
  span?: {
    start: number;
    end: number;
    text: string;
  };
  severity: "low" | "medium" | "high";
}

export interface NextStepItem {
  id: string;
  text: string;
  actionUrl?: string;
  actionLabel?: string;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  riskLevel: RiskLevel;
  riskScorePercent: number; // 0 to 100
  summary: string;
  findings: SignalFinding[];
  recommendedSteps: NextStepItem[];
  isMock: boolean;
  rawMessage?: string;
  analyzedUrls?: AnalyzedUrl[];
  metadata?: {
    charCount: number;
    executionTimeMs: number;
    isHeuristic: boolean;
    analysisMode?: "gemini" | "rules";
    analysisNotice?: string;
  };
}

export type ScanStatus = "idle" | "validating" | "analyzing" | "success" | "error";
