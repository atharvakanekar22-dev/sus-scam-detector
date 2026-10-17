import { describe, it, expect } from "vitest";
import {
  DETECTION_RULES,
  NEGATION_RULES,
  segmentClauses,
  findAdvisoryZones,
} from "@/lib/analyzer/rules";

describe("Detection Rules Unit Tests (Positive & Negative Pairs)", () => {
  const getRule = (id: string) => {
    const rule = DETECTION_RULES.find((r) => r.id === id) || NEGATION_RULES.find((r) => r.id === id);
    if (!rule) throw new Error(`Rule ${id} not found`);
    return rule;
  };

  const testRuleMatch = (id: string, text: string) => {
    const rule = getRule(id);
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    return regex.test(text);
  };

  describe("Advisory Negation Rules", () => {
    it("NEG-01 matches protective advice (Positive) and ignores scam solicitations (Negative)", () => {
      expect(testRuleMatch("NEG-01", "Never share your OTP with anyone.")).toBe(true);
      expect(testRuleMatch("NEG-01", "Bank will never ask for your password.")).toBe(true);
      expect(testRuleMatch("NEG-01", "Do not disclose your PIN to callers.")).toBe(true);

      // Negative: Active demand without negation
      expect(testRuleMatch("NEG-01", "Please share your OTP immediately.")).toBe(false);
      expect(testRuleMatch("NEG-01", "Send us your OTP now.")).toBe(false);
    });

    it("NEG-02 matches caution advisories (Positive) and ignores unnegated text (Negative)", () => {
      expect(testRuleMatch("NEG-02", "Caution: do not share your OTP with strangers.")).toBe(true);
      expect(testRuleMatch("NEG-02", "Beware of suspicious links and calls.")).toBe(true);

      // Negative
      expect(testRuleMatch("NEG-02", "Click this link to see your statement.")).toBe(false);
    });
  });

  describe("Category 1: Credential Theft", () => {
    it("CRED-01 matches OTP/PIN solicitation (Positive) and ignores benign OTP notifications (Negative)", () => {
      expect(testRuleMatch("CRED-01", "Send us your OTP to verify your account.")).toBe(true);
      expect(testRuleMatch("CRED-01", "Please enter your one-time password.")).toBe(true);
      expect(testRuleMatch("CRED-01", "Share the secret code sent to your phone.")).toBe(true);

      // Negative: Bank merely sending an OTP to user
      expect(testRuleMatch("CRED-01", "Your OTP is 492810. Valid for 10 minutes.")).toBe(false);
      expect(testRuleMatch("CRED-01", "Use OTP 991823 to log in.")).toBe(false);
    });

    it("CRED-02 matches Aadhaar/PAN/Card CVV demands (Positive) and ignores status alerts (Negative)", () => {
      expect(testRuleMatch("CRED-02", "Re-verify your Aadhaar and PAN card details today.")).toBe(true);
      expect(testRuleMatch("CRED-02", "Submit your debit card CVV to proceed.")).toBe(true);

      // Negative: Confirmation of existing linking
      expect(testRuleMatch("CRED-02", "Your PAN card is linked to your bank account.")).toBe(false);
    });

    it("CRED-03 matches net-banking password requests (Positive) and ignores password change receipts (Negative)", () => {
      expect(testRuleMatch("CRED-03", "Provide your net banking password to confirm.")).toBe(true);
      expect(testRuleMatch("CRED-03", "Enter your account login credentials.")).toBe(true);

      // Negative
      expect(testRuleMatch("CRED-03", "Your password was changed successfully on 10-Oct.")).toBe(false);
    });
  });

  describe("Category 2: Urgency Coercion", () => {
    it("URG-01 matches utility cutoff threats (Positive) and ignores maintenance notices (Negative)", () => {
      expect(testRuleMatch("URG-01", "Electricity connection will be disconnected tonight at 9:30 PM.")).toBe(true);
      expect(testRuleMatch("URG-01", "Power will be cut-off today immediately.")).toBe(true);

      // Negative: Scheduled maintenance
      expect(testRuleMatch("URG-01", "Power outage scheduled for routine grid maintenance.")).toBe(false);
    });

    it("URG-02 matches account suspension countdowns (Positive) and ignores regular renewals (Negative)", () => {
      expect(testRuleMatch("URG-02", "Your net banking access will be suspended within 24 hours.")).toBe(true);
      expect(testRuleMatch("URG-02", "Your SIM card has been blocked in 2 hours.")).toBe(true);

      // Negative
      expect(testRuleMatch("URG-02", "Your access is valid for 365 days.")).toBe(false);
    });

    it("URG-03 matches generic urgency keywords (Positive) and ignores calm requests (Negative)", () => {
      expect(testRuleMatch("URG-03", "URGENT: action required.")).toBe(true);
      expect(testRuleMatch("URG-03", "Act now to claim.")).toBe(true);
      expect(testRuleMatch("URG-03", "Final notice before penalty.")).toBe(true);

      // Negative
      expect(testRuleMatch("URG-03", "Whenever you get some free time, let me know.")).toBe(false);
    });
  });

  describe("Category 3: Financial Pressure", () => {
    it("FIN-01 matches unpaid bill dues (Positive) and ignores payment receipts (Negative)", () => {
      expect(testRuleMatch("FIN-01", "Your previous month electricity bill was not updated, pay now.")).toBe(true);
      expect(testRuleMatch("FIN-01", "Pending dues must be cleared.")).toBe(true);

      // Negative: Payment completed receipt
      expect(testRuleMatch("FIN-01", "Thank you, your bill payment of Rs 500 is complete.")).toBe(false);
    });

    it("FIN-02 matches lottery/prize lures (Positive) and ignores small legitimate cashbacks (Negative)", () => {
      expect(testRuleMatch("FIN-02", "Congratulations you won lottery Rs. 25,00,000 claim now.")).toBe(true);
      expect(testRuleMatch("FIN-02", "Tax refund of INR 45,000 pending approval.")).toBe(true);

      // Negative
      expect(testRuleMatch("FIN-02", "No rewards available for this transaction.")).toBe(false);
    });

    it("FIN-03 matches advance fee demands (Positive) and ignores zero-fee disclosures (Negative)", () => {
      expect(testRuleMatch("FIN-03", "Pay processing fee Rs 500 to release prize.")).toBe(true);
      expect(testRuleMatch("FIN-03", "Transfer advance token amount.")).toBe(true);

      // Negative
      expect(testRuleMatch("FIN-03", "Zero advance fee required.")).toBe(false);
    });
  });

  describe("Category 4: Suspicious Links", () => {
    it("LINK-01 matches URL shorteners (Positive) and ignores legitimate corporate domains (Negative)", () => {
      expect(testRuleMatch("LINK-01", "http://bit.ly/power-bill-update")).toBe(true);
      expect(testRuleMatch("LINK-01", "https://tinyurl.com/sbi-verify")).toBe(true);

      // Negative
      expect(testRuleMatch("LINK-01", "https://www.tatapower.com/bill")).toBe(false);
    });

    it("LINK-02 matches raw IP address links (Positive) and ignores valid brand domains (Negative)", () => {
      expect(testRuleMatch("LINK-02", "http://192.168.1.100/login")).toBe(true);
      expect(testRuleMatch("LINK-02", "http://10.0.0.1:8080/auth")).toBe(true);

      // Negative
      expect(testRuleMatch("LINK-02", "https://google.com")).toBe(false);
    });

    it("LINK-03 matches deceptive brand mimic subdomains (Positive) and ignores official domains (Negative)", () => {
      expect(testRuleMatch("LINK-03", "https://sbi-kyc-verify-portal.in/update")).toBe(true);
      expect(testRuleMatch("LINK-03", "https://hdfc-bank-support-login.com")).toBe(true);

      // Negative
      expect(testRuleMatch("LINK-03", "https://onlinesbi.sbi")).toBe(false);
      expect(testRuleMatch("LINK-03", "https://hdfcbank.com")).toBe(false);
    });

    it("LINK-04 matches unencrypted HTTP links (Positive) and ignores HTTPS (Negative)", () => {
      expect(testRuleMatch("LINK-04", "http://unsecured-portal.com")).toBe(true);

      // Negative
      expect(testRuleMatch("LINK-04", "https://secure-portal.com")).toBe(false);
    });
  });

  describe("Category 5: Impersonation", () => {
    it("IMP-01 matches persona with 10-digit mobile (Positive) and ignores 1800 toll-free lines (Negative)", () => {
      expect(testRuleMatch("IMP-01", "Contact verification officer at 98765-43210")).toBe(true);
      expect(testRuleMatch("IMP-01", "Call our executive on 919876543210")).toBe(true);

      // Negative: Toll-free numbers
      expect(testRuleMatch("IMP-01", "Call our executive at 1800-11-2211")).toBe(false);
    });

    it("IMP-02 matches mobile presented as helpline (Positive) and ignores landline helplines (Negative)", () => {
      expect(testRuleMatch("IMP-02", "Customer care at 9811122233")).toBe(true);

      // Negative: Standard city landline (011-...)
      expect(testRuleMatch("IMP-02", "Customer care at 01123456789")).toBe(false);
    });
  });

  describe("Clause Segmentation and Advisory Zone Detection", () => {
    it("segments clauses properly by punctuation and conjunctions", () => {
      const text = "Never share your OTP. However, your account is suspended; call us now!";
      const clauses = segmentClauses(text);
      expect(clauses.length).toBeGreaterThanOrEqual(3);
      expect(clauses[0].text.trim()).toBe("Never share your OTP");
    });

    it("creates an advisory zone only for the clause containing the negation", () => {
      const text = "State Bank says: Never share your OTP with anyone. Send us your OTP now.";
      const zones = findAdvisoryZones(text);
      expect(zones.length).toBe(1);
      expect(zones[0].matchedText).toContain("Never share your OTP");

      // The zone covers only the first clause
      expect(zones[0].end).toBeLessThanOrEqual(text.indexOf("Send us your OTP"));
    });
  });
});
