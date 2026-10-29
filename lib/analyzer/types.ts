import { SignalCategory } from "@/lib/schemas";

export type RuleId =
  | "NEG-01"
  | "NEG-02"
  | "NEG-03"
  | "NEG-04"
  | "NEG-05"
  | "CRED-01"
  | "CRED-02"
  | "CRED-03"
  | "CRED-04"
  | "CRED-05"
  | "URG-01"
  | "URG-02"
  | "URG-03"
  | "URG-04"
  | "URG-05"
  | "FIN-01"
  | "FIN-02"
  | "FIN-03"
  | "FIN-04"
  | "FIN-05"
  | "LINK-01"
  | "LINK-02"
  | "LINK-03"
  | "LINK-04"
  | "LINK-05"
  | "LINK-06"
  | "IMP-01"
  | "IMP-02"
  | "AUTH-01"
  | "AUTH-02"
  | "AUTH-03"
  | "BANK-01"
  | "BANK-02"
  | "UPI-01"
  | "UPI-02"
  | "UPI-03"
  | "KYC-01"
  | "DELIV-01"
  | "DELIV-02"
  | "JOB-01"
  | "JOB-02"
  | "INV-01"
  | "INV-02"
  | "PRIZE-01"
  | "GOV-01"
  | "GOV-02"
  | "REMOTE-01"
  | "SUPPORT-01"
  | "REFUND-01"
  | "EMERG-01"
  | "ATTACH-01"
  | "TECH-01"
  | (string & {});

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
  ruleId: string;
}

export interface RuleMatch {
  rule: RuleDefinition;
  start: number;
  end: number;
  matchedText: string;
  isSuppressed: boolean;
}
