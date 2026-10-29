import { SignalCategory } from "@/lib/schemas";

export const CATEGORY_CAPS: Record<SignalCategory, number> = {
  credential_theft: 45,
  urgency_coercion: 35,
  financial_pressure: 30,
  suspicious_link: 35,
  impersonation: 30,
  security_advisory: 0,
  job_scam: 35,
  investment_fraud: 35,
  delivery_scam: 30,
  government_impersonation: 35,
  remote_access: 35,
  tech_support: 35,
  malicious_attachment: 35,
  upi_payment_scam: 40,
  utility_cutoff: 35,
};

export const RISK_THRESHOLDS = {
  LOW_MAX: 24,
  MEDIUM_MIN: 25,
  MEDIUM_MAX: 54,
  HIGH_MIN: 55,
  OVERRIDE_FLOOR_SCORE: 75,
} as const;

export const INPUT_LIMITS = {
  MIN_CHARS: 5,
  MAX_CHARS: 5000,
} as const;

export const CYBERCRIME_PORTAL_URL = "https://cybercrime.gov.in";

export const CLAUSE_DELIMITER_REGEX = /[.!?;\n\r]+|\b(?:however|although|whereas)\b/i;
