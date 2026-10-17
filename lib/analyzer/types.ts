import { SignalCategory } from "@/lib/schemas";

export type RuleId =
  | "NEG-01"
  | "NEG-02"
  | "CRED-01"
  | "CRED-02"
  | "CRED-03"
  | "URG-01"
  | "URG-02"
  | "URG-03"
  | "FIN-01"
  | "FIN-02"
  | "FIN-03"
  | "LINK-01"
  | "LINK-02"
  | "LINK-03"
  | "LINK-04"
  | "IMP-01"
  | "IMP-02";

export interface RuleDefinition {
  id: RuleId;
  category: SignalCategory;
  weight: number;
  severity: "low" | "medium" | "high";
  title: string;
  description: string;
  pattern: RegExp;
  isNegation?: boolean;
}

export interface ClauseSpan {
  start: number;
  end: number;
  text: string;
}

export interface AdvisoryZone {
  start: number;
  end: number;
  matchedText: string;
  ruleId: "NEG-01" | "NEG-02";
}

export interface RuleMatch {
  rule: RuleDefinition;
  start: number;
  end: number;
  matchedText: string;
  isSuppressed: boolean;
}
