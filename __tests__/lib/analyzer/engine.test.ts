import { describe, it, expect } from "vitest";
import { analyzeMessage } from "@/lib/analyzer/engine";

describe("Analysis Engine Integration & Regression Suite (26 Cases)", () => {
  it("TC-01: Pure Warning - Never share your OTP with anyone", () => {
    const input = "State Bank Security: Never share your OTP with anyone.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings.some((f) => f.category === "credential_theft")).toBe(false);
    expect(result.findings.some((f) => f.category === "security_advisory")).toBe(true);
  });

  it("TC-02: Pure Phishing - Send us your OTP to verify account", () => {
    const input = "Send us your OTP to verify your account and unlock your card.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(55);
    const credFinding = result.findings.find((f) => f.ruleId === "CRED-01");
    expect(credFinding).toBeDefined();
    expect(credFinding?.span.text.toLowerCase()).toContain("send us your otp");
  });

  it("TC-03: Mixed - Warning followed by scam in separate clause", () => {
    const input =
      "Bank alert: Never share your OTP. However, your KYC has expired, please send us your OTP to avoid card block.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    // Verify Clause 1 resulted in advisory
    expect(result.findings.some((f) => f.category === "security_advisory")).toBe(true);
    // Verify Clause 2 was NOT suppressed and caught active solicitation
    expect(result.findings.some((f) => f.ruleId === "CRED-01")).toBe(true);
  });

  it("TC-04: Cautionary Advisory - do not share password", () => {
    const input = "Caution: do not share your OTP or password with unauthorized callers.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings.some((f) => f.category === "credential_theft")).toBe(false);
  });

  it("TC-05: Electricity Cutoff Extortion", () => {
    const input =
      "URGENT: Power connection will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer at 98765-43210 or visit http://bit.ly/power-bill";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("URG-01");
    expect(ruleIds).toContain("IMP-01");
    expect(ruleIds).toContain("LINK-01");
    expect(ruleIds).toContain("FIN-01");
  });

  it("TC-06: Bank KYC Suspension Phishing", () => {
    const input =
      "Dear customer, your net banking access will be suspended within 24 hours. Re-verify your Aadhaar and PAN card at https://sbi-kyc-verify-portal.in";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("CRED-02");
    expect(ruleIds).toContain("URG-02");
    expect(ruleIds).toContain("LINK-03");
  });

  it("flags an urgently locked account paired with a deceptive verification link as high risk", () => {
    const input =
      "URGENT: Your bank account has been locked due to suspicious activity. Verify your identity immediately at https://secure-bank-verify.example-login.com. Failure to verify within 24 hours will result in permanent account closure.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBe(75);
    expect(result.findings.map((finding) => finding.ruleId)).toContain("URG-02");
    expect(result.findings.map((finding) => finding.ruleId)).toContain("LINK-03");
  });

  it.each([
    [
      "English account phishing",
      "Your account will be suspended in 24 hours. Verify your details immediately: https://secure-verify.example-login.com",
    ],
    [
      "Hindi account phishing",
      "आपका बैंक खाता अस्थायी रूप से बंद कर दिया गया है। खाता सक्रिय करने के लिए तुरंत लॉगिन करें: https://bank-verify.example.com",
    ],
    [
      "Hindi prize claim",
      "बधाई हो! आपका मोबाइल नंबर 10 लाख रुपये की लॉटरी में चुना गया है। पुरस्कार पाने के लिए अपना नाम और बैंक विवरण भेजें।",
    ],
    [
      "Hindi delivery fee",
      "आपका पार्सल डिलीवरी के लिए तैयार है। ₹29 शुल्क भरें और पता अपडेट करें: http://parcel-update.example.com",
    ],
    [
      "Marathi account phishing",
      "तुमचे बँक खाते असुरक्षित आहे. खाते सुरू ठेवण्यासाठी लगेच तपासा: https://secure-bank.example.com",
    ],
    [
      "Marathi prize claim",
      "अभिनंदन! तुमचा मोबाइल नंबर 5 लाख रुपयांच्या बक्षिसासाठी निवडला गेला आहे. माहिती पाठवा.",
    ],
    [
      "Hinglish account phishing",
      "Sir, aapka KYC pending hai. Account block hone se bachne ke liye abhi update karein: https://kyc-update.example.com",
    ],
    [
      "Hinglish prize claim",
      "Congratulations! Aapka number lottery mein select hua hai. ₹5 lakh claim karne ke liye details bhejo.",
    ],
    [
      "Bengali account phishing",
      "আপনার অ্যাকাউন্ট সাসপেন্ড হয়েছে। এখনই যাচাই করুন: https://account-check.example.com",
    ],
    [
      "Tamil account phishing",
      "உங்கள் வங்கிக் கணக்கு பாதுகாப்பற்றது. உடனே சரிபார்க்கவும்: https://bank-alert.example.com",
    ],
    [
      "Telugu account phishing",
      "మీ ఖాతా తాత్కালికంగా నిలిపివేయబడింది. వెంటనే ధృవీకరించండి: https://verify-account.example.com",
    ],
    [
      "Gujarati account phishing",
      "તમારું બેંક ખાતું બંધ થઈ શકે છે. તરત ચકાસો: https://bank-secure.example.com",
    ],
    [
      "French prize claim",
      "Félicitations ! Vous avez gagné 500 000 €. Envoyez vos coordonnées bancaires pour recevoir votre prix.",
    ],
    [
      "Spanish delivery fee",
      "¡Tu paquete está retenido! Paga 2,99 € para reprogramar la entrega: http://paquete.example.com",
    ],
    [
      "German delivery link",
      "Ihr Paket konnte nicht zugestellt werden. Bestätigen Sie Ihre Adresse hier: http://paket-example.com",
    ],
    [
      "Chinese prize claim",
      "恭喜！您的手机号码中奖，获得100万元奖金。请提供银行信息以领取奖励。",
    ],
    [
      "Russian account phishing",
      "Ваш банковский счёт заблокирован. Подтвердите личные данные: https://bank-secure.example.com",
    ],
    [
      "Arabic prize claim",
      "مبروك! تم اختيار رقمك للفوز بجائزة قدرها 100,000 دولار. أرسل بياناتك البنكية لاستلام الجائزة.",
    ],
    [
      "English cryptocurrency investment",
      "Only today—invest ₹1,000 and get 10x return guaranteed! Join fast: http://crypto-profit.example.com",
    ],
  ])("scores %s as high risk", (_label, message) => {
    const result = analyzeMessage(message);

    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
  });

  it.each([
    "MEGA SALE! 80% OFF everything today only. Shop now: http://deals.example.com Reply STOP to opt out.",
    "धमाकेदार ऑफर! आज सभी मोबाइल रिचार्ज पर 50% कैशबैक पाएं। अभी क्लिक करें: http://offer.example.com",
    "Hi, this is Rahul from the college coding club. Meeting moved to 5 PM.",
    "Your verification code is 482913. Never share this code. Support will never ask for it.",
  ])("does not inflate a promotion or legitimate message score: %s", (message) => {
    const result = analyzeMessage(message);

    expect(result.riskLevel).not.toBe("high");
    expect(result.heuristicScore).toBeLessThan(55);
  });

  it("does not treat an ordinary parcel-ready notification as a scam", () => {
    const result = analyzeMessage(
      "Your parcel is ready for delivery tomorrow. No action is needed."
    );

    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
  });

  it("TC-07: Lottery Advance Fee Scam", () => {
    const input =
      "Congratulations you won lottery Rs. 25,00,000! Transfer advance processing fee Rs 1,000 to release prize.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("FIN-02");
    expect(ruleIds).toContain("FIN-03");
  });

  it("TC-08: Benign Meeting Invite", () => {
    const input = "Hey Atharva, are we meeting for lunch at 1:30 PM tomorrow at the office cafe?";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("TC-09: Benign Bank Credit SMS", () => {
    const input = "Your a/c 1234 credited with INR 5,000 on 17-Oct. Available balance: INR 24,500. - HDFC Bank";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
  });

  it("TC-10: Benign Clinic Appointment Reminder", () => {
    const input = "Reminder: You have an appointment with Dr. Sharma tomorrow at 10 AM. Reschedule: 011-23456789.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
  });

  it("TC-11: Benign E-commerce Flash Sale", () => {
    const input = "Hurry! Flash sale ends today. Get 50% discount on shoes at https://myntra.com";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBeLessThanOrEqual(24);
  });

  it("TC-12: Unverified Link with Pending Dues", () => {
    const input = "Please review your pending electricity bill dues before the due date at http://state-power.org";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("medium");
    expect(result.heuristicScore).toBe(35);
  });

  it("TC-13: Duplicate Signal Spamming (Deduplication Check)", () => {
    const input = "URGENT! URGENT! Please act immediately, this is urgent!";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    // URG-03 contributes only once (15 points)
    expect(result.heuristicScore).toBe(15);
  });

  it("TC-14: Raw IP Address Phishing", () => {
    const input = "Provide your net banking password at http://192.168.1.100/login";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "LINK-02")).toBe(true);
    expect(result.findings.some((f) => f.ruleId === "CRED-03")).toBe(true);
  });

  it("TC-15: Unicode and Emojis Highlight Offset Accuracy", () => {
    const input = "URGENT 🚨 electricity blackout tonight ⚡ call officer at 98765-43210";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    // Verify each finding matches its slice exactly
    for (const f of result.findings) {
      expect(input.slice(f.span.start, f.span.end)).toBe(f.span.text);
    }
  });

  it("TC-16: Quoted Scam Text", () => {
    const input = 'Security news: Scammers are sending "Your electricity connection will be disconnected tonight".';
    const result = analyzeMessage(input);
    expect(result.findings.some((f) => f.ruleId === "URG-01")).toBe(true);
  });

  it("TC-17: Boundary: Minimum 5 characters", () => {
    const input = "Hello";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
  });

  it("TC-18: Boundary: Exactly 5,000 characters", () => {
    const input = "A".repeat(5000);
    expect(input.length).toBe(5000);
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.metadata.charCount).toBe(5000);
  });

  it("TC-19: Error: Under Minimum Length (<5 chars)", () => {
    expect(() => analyzeMessage("Hi")).toThrow(/at least 5 characters/i);
  });

  it("TC-20: Error: Over Maximum Length (5,001 chars)", () => {
    const overLength = "A".repeat(5001);
    expect(() => analyzeMessage(overLength)).toThrow(/maximum limit/i);
  });

  it("TC-21: Error: Empty String", () => {
    expect(() => analyzeMessage("")).toThrow(/at least 5 characters/i);
  });

  it("TC-22: Error: Whitespace Only", () => {
    expect(() => analyzeMessage("   \t\n\r\n   ")).toThrow(/at least 5 characters/i);
  });

  it("TC-23: Stress: Repetitive Urgency Words", () => {
    const input = "urgent ".repeat(500) + "end now";
    const start = performance.now();
    const result = analyzeMessage(input);
    const duration = performance.now() - start;
    expect(result.riskLevel).toBe("low");
    expect(duration).toBeLessThan(100);
  });

  it("TC-24: Stress: Repetitive Subdomain Mimics", () => {
    const input = "https://sbi-" + "verify-".repeat(300) + "portal.in";
    const start = performance.now();
    const result = analyzeMessage(input);
    const duration = performance.now() - start;
    expect(duration).toBeLessThan(100);
    expect(result).toBeDefined();
    expect(result.metadata.charCount).toBe(input.length);
  });

  it("TC-25: Span Slicing Invariant across all findings", () => {
    const input =
      "URGENT: your electricity power connection will be cut-off tonight at 9:30 PM. Pay dues at http://bit.ly/pay and call 98765-43210.";
    const result = analyzeMessage(input);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(input.slice(f.span.start, f.span.end)).toBe(f.span.text);
      expect(f.span.start).toBeGreaterThanOrEqual(0);
      expect(f.span.end).toBeLessThanOrEqual(input.length);
    }
  });

  it("TC-26: Toll-Free Safe Channel does not trigger IMP-01", () => {
    const input = "Please contact our customer care at 1800-11-2211 for assistance with your bank.";
    const result = analyzeMessage(input);
    expect(result.findings.some((f) => f.ruleId === "IMP-01")).toBe(false);
  });
});
