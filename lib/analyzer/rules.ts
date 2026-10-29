import { RuleDefinition, AdvisoryZone, ClauseSpan } from "./types";
import { CLAUSE_DELIMITER_REGEX } from "./constants";

export const NEGATION_RULES: RuleDefinition[] = [
  {
    id: "NEG-01",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Protective Security Advisory",
    description: "Contains legitimate educational advice warning the recipient never to share passwords or OTPs.",
    pattern: /\b(?:never|do\s+not|don'?t|should\s+never|will\s+never)\s+(?:share|disclose|give|send|tell|reveal|ask\s+for)\b[^.!?;\n]*?\b(?:otp|one[- ]time[- ]password|pin|password|cvv|credentials?)\b/gi,
    isNegation: true,
  },
  {
    id: "NEG-02",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Security Caution Warning",
    description: "Contains precautionary warning against sharing credentials or clicking unauthorized links.",
    pattern: /\b(?:beware\s+of|caution:?\s+do\s+not|alert:?\s+never)\b[^.!?;\n]*?\b(?:otp|links?|calls?|password)\b/gi,
    isNegation: true,
  },
  {
    id: "NEG-03",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Legitimate Delivery Notice",
    description: "Contains standard delivery confirmation or tracking update without fee demands.",
    pattern: /\b(?:your\s+)?(?:package|parcel|order|shipment)\s+(?:has\s+been|was)\s+delivered(?:\s+successfully|\s+today|\s+to\s+your)?\b|\b(?:order|package|parcel)\s+(?:is\s+)?out\s+for\s+delivery\b[^.!?;\n]*?\b(?:tracking\s+(?:id|number)|track\s+(?:your\s+)?package)\b/gi,
    isNegation: true,
  },
  {
    id: "NEG-04",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Scam Awareness Advisory",
    description: "Official educational bulletin or scam awareness alert explaining fraud tactics.",
    pattern: /\b(?:cybercrime\s+(?:advisory|alert)|scam\s+(?:alert|warning)|security\s+(?:awareness|tip)|public\s+advisory|rbi\s+(?:says|caution))\b/gi,
    isNegation: true,
  },
  {
    id: "NEG-05",
    category: "security_advisory",
    weight: 0,
    severity: "low",
    title: "Routine Bank Transaction Alert",
    description: "Routine account credit or debit notification with available balance statement.",
    pattern: /\b(?:your\s+)?(?:a\/c|account)\s+[\dx*]+\s+(?:credited|debited)\s+(?:with|by)\s+(?:rs\.?|inr|₹)\s*[\d,]+[^.!?;\n]*?\b(?:available|avl)\s+bal(?:ance)?\b/gi,
    isNegation: true,
  },
];

export const DETECTION_RULES: RuleDefinition[] = [
  {
    id: "CRED-01",
    category: "credential_theft",
    weight: 35,
    severity: "high",
    title: "Direct OTP / PIN Solicitation",
    description: "Asks recipient to communicate or submit sensitive one-time passwords or security PINs.",
    pattern: /\b(?:send|share|enter|provide|verify|tell|forward)\s+(?:(?:us|me)\s+)?(?:your\s+)?(?:the\s+)?\b(?:otp|one[- ]time[- ]password|pin|secret\s+code)\b/gi,
  },
  {
    id: "CRED-02",
    category: "credential_theft",
    weight: 30,
    severity: "high",
    title: "Identity & Card Credential Demand",
    description: "Requests submission or re-verification of sensitive national identity cards or card security codes.",
    pattern: /\b(?:update|verify|re-?verify|submit)\b[^.!?;\n]*?\b(?:aadhaar|pan\s+card|pan\s+number|debit\s+card|credit\s+card|cvv)\b/gi,
  },
  {
    id: "CRED-03",
    category: "credential_theft",
    weight: 25,
    severity: "high",
    title: "Banking Password Solicitation",
    description: "Prompts for confidential net-banking or mobile-banking login credentials.",
    pattern: /\b(?:net\s*banking|mobile\s*banking|account)\s+(?:password|login\s+credentials?|pin)\b/gi,
  },
  {
    id: "CRED-04",
    category: "credential_theft",
    weight: 35,
    severity: "high",
    title: "Request for Bank or Identity Details",
    description: "Asks for banking or identity details in another language.",
    pattern:
      /(?:अपना|अपने|बैंक|बँक|ব্যাংক|ব্যাঙ্ক|வங்கி|బ్యాంకు|બેંક|बँक).{0,45}(?:बैंक विवरण|बैंक जानकारी|विवरण भेजें|जानकारी भेजें|माहिती पाठवा|माहिती द्या|ব্যাংক তথ্য|ব্যাংকের তথ্য|তথ্য পাঠান|வங்கி விவரங்கள்|வங்கி தகவல்|விவரங்களை அனுப்ப|బ్యాంకు వివరాలు|వివరాలు పంప|બેંકની વિગતો|બેંક વિગતો|માહિતી મોકલો|bank details|bank info|banking details|aapki details|details bhejo|details bhej|datos bancarios|coordonnées bancaires|bancaires|bankdaten|bankangaben|банковские данные|данные банка|بياناتك البنكية|بيانات بنكية|銀行信息|银行信息|银行卡信息|銀行卡資料)/giu,
  },
  {
    id: "CRED-05",
    category: "credential_theft",
    weight: 35,
    severity: "high",
    title: "Request for Personal Details",
    description: "Asks the recipient to send personal details to claim a reward or offer.",
    pattern:
      /(?:details bhejo|details bhej|अपनी जानकारी भेजें|अपना नाम.{0,25}भेजें|जानकारी भेजें|માહિતી મોકલો|தகவல்களை அனுப்ப|వివరాలు పంప|तपशील पाठवा|send your (?:name|address|details)|(?:बक्षीस|बक्षिस|पुरस्कार|इनाम|लॉटरी|अभिनंदन).{0,100}(?:माहिती पाठवा|माहिती द्या|तपशील पाठवा|जानकारी भेजें|विवरण भेजें)|(?:félicitations|gagné|prize|lottery|congratulations).{0,100}(?:coordonnées bancaires|bank details|bankdaten|datos bancarios)|(?:बधाई|मबروك|مبروك|جائزة).{0,100}(?:بياناتك البنكية|بيانات بنكية)|(?:中奖了|中奖|奖金|恭喜).{0,80}(?:提供|发送).{0,12}(?:银行信息|银行卡信息|銀行信息))/giu,
  },
  {
    id: "AUTH-01",
    category: "credential_theft",
    weight: 30,
    severity: "high",
    title: "Card Security Code (CVV) or Expiry Request",
    description: "Demands credit or debit card CVV, expiry date, or ATM PIN under guise of verification.",
    pattern: /\b(?:enter|provide|submit|share)\s+(?:your\s+)?(?:cvv|cvv2|security\s+code|card\s+pin|atm\s+pin|expiry\s+date)\b/gi,
  },
  {
    id: "AUTH-02",
    category: "credential_theft",
    weight: 25,
    severity: "high",
    title: "Deceptive Password Reset / Verification Bait",
    description: "Prompts recipient to confirm current password or click to resolve unauthorized password reset.",
    pattern: /\b(?:confirm|verify|enter)\s+(?:your\s+)?(?:current\s+password|login\s+password|email\s+password)\b/gi,
  },
  {
    id: "URG-01",
    category: "urgency_coercion",
    weight: 30,
    severity: "high",
    title: "Utility Disconnection Threat",
    description: "Threatens imminent termination of essential electric power or utility services within hours.",
    pattern: /\b(?:power|electricity|connection)\b[^.!?;\n]*?\b(?:disconnect(?:ed)?|cut[- ]off|blackout)\s+(?:tonight|today|within\s+\d+\s+hours?|immediately)\b/gi,
  },
  {
    id: "URG-02",
    category: "urgency_coercion",
    weight: 25,
    severity: "high",
    title: "Artificial Suspension Countdown",
    description: "Imposes an artificial countdown to block banking access, cards, or SIM cards to bypass critical scrutiny.",
    pattern: /\b(?:account|card|sim|access)\s+(?:will\s+be\s+|has\s+been\s+)?(?:blocked|locked|suspended|terminated|deactivated)(?:\s+(?:within|in)\s+\d+\s+(?:hours?|minutes?|days?))?\b|\b(?:card\s+block|blocked\s+card|unlock\s+(?:your\s+)?(?:account|card|access))\b/gi,
  },
  {
    id: "URG-03",
    category: "urgency_coercion",
    weight: 15,
    severity: "medium",
    title: "Urgency Pressure Language",
    description: "Employs high-pressure urgency words to induce hurried emotional reactions.",
    pattern: /\b(?:urgent|immediately|act\s+now|right\s+now|last\s+chance|final\s+notice|time\s+sensitive|now)\b/gi,
  },
  {
    id: "URG-04",
    category: "urgency_coercion",
    weight: 35,
    severity: "high",
    title: "Account Security Threat",
    description: "Claims an account is blocked, unsafe, or at risk of suspension.",
    pattern:
      /(?:खाता|अकाउंट|बैंक खाता|बँक खाते|खाते|অ্যাকাউন্ট|ব্যাঙ্ক অ্যাকাউন্ট|வங்கிக் கணக்கு|கணக்கு|బ్యాంకు ఖాతా|ఖాతా|બેંક ખાતું|ખાતું).{0,45}(?:बंद|निलंबित|ब्लॉक|लॉक|असुरक्षित|स्थगित|বন্ধ|স্থগিত|ব্লক|பாதுகாப்பற்ற|முடக்க|நிறுத்தி|నిలిపివేయ|బ్లాక్|మూసివేయ|અસુરક્ષિત|બંધ|થંભી)|(?:अकाउंट|खाता|बँक खाते|অ্যাকাউন্ট|வங்கிக் கணக்கு|ఖాతా|ખાતું).{0,35}(?:तुरंत|अभी|लॉगिन|सक्रिय|जांच|सत्यापित|যাচাই|এখনই|সাসপেন্ড|உடனே|சரிபார்க்க|వెంటనే|ధృవీకరించ|તરત|ચકાસો)|(?:aapka|tumhara|apka).{0,20}(?:bank\\s+)?(?:account|khata|khaata).{0,35}(?:locked|block|blocked|suspend|band)|(?:your\\s+)?(?:account|bank\\s+account).{0,25}(?:has\\s+been\\s+)?(?:locked|suspended|blocked|unsafe)|(?:cuenta|compte|konto|сч[её]т|账户|賬戶|حسابك).{0,28}(?:suspend|bloquead|bloqué|gesperrt|заблокирован|暂停|冻结|停用|محظور|मغلق)/giu,
  },
  {
    id: "URG-05",
    category: "urgency_coercion",
    weight: 15,
    severity: "medium",
    title: "Delivery or Parcel Held",
    description: "Claims a delivery is held or failed and asks the recipient to act.",
    pattern:
      /(?:parcel|package|delivery).{0,45}(?:held|could not be delivered|failed)|(?:paquete).{0,35}(?:retenido|reprogramar)|(?:paket).{0,40}(?:nicht zugestellt|bestätigen)|(?:पार्सल).{0,35}(?:रुका)|(?:பார்சல்).{0,35}(?:நிறுத்த)|(?:పార్సల్).{0,35}(?:ఆగి)/giu,
  },
  {
    id: "FIN-01",
    category: "financial_pressure",
    weight: 20,
    severity: "medium",
    title: "Unpaid Bill Dues Claim",
    description: "Claims existing dues or pending utility payments must be settled immediately.",
    pattern: /\b(?:unpaid|previous\s+month|pending|overdue)\s+(?:bill|electricity\s+bill|dues)\b|\b(?:previous\s+month\s+)?(?:electricity\s+)?bill\s+(?:is\s+)?unpaid\b|\b(?:electricity\s+)?bill\s+dues\b/gi,
  },
  {
    id: "FIN-02",
    category: "financial_pressure",
    weight: 25,
    severity: "medium",
    title: "Unsolicited Prize or Refund Lure",
    description: "Announces unexpected lottery winnings, large cash rewards, or tax refunds to lure engagement.",
    pattern: /\b(?:won|lottery|cashback|reward|tax\s+refund)\b[^.!?;\n]*?\b(?:rs\.?|inr|₹|\$)\s*[\d,]+\b/gi,
  },
  {
    id: "FIN-03",
    category: "financial_pressure",
    weight: 25,
    severity: "high",
    title: "Advance Fee Demand",
    description: "Demands an upfront fee or deposit to release supposed prizes or loan amounts.",
    pattern: /\b(?:send|transfer|deposit|pay)\s+(?:processing\s+fee|token\s+amount|advance|clearance\s+(?:charge|fee|duty)|customs\s+duty|clearance\s+charge)\b/gi,
  },
  {
    id: "FIN-04",
    category: "financial_pressure",
    weight: 30,
    severity: "high",
    title: "Prize or Lottery Claim",
    description: "Claims a prize or lottery win and asks the recipient to claim it.",
    pattern:
      /(?:बधाई|लॉटरी|पुरस्कार|इनाम|अभिनंदन).{0,100}(?:लाख|रुपये|बैंक|ब्योरा|विवरण|जानकारी|भेजें|पाने|पुरस्कार|इनाम)|(?:অভিনন্দন|লটারি|পুরস্কার).{0,100}(?:লাখ|টাকা|ব্যাংক|তথ্য|পাঠান|জিতেছেন)|(?:வாழ்த்துக்கள்|பரிசு|லாட்டரி).{0,100}(?:ரூபாய்|வங்கி|விவரம்|அனுப்ப)|(?:అభినందనలు|బహుమతి|లాటరీ).{0,100}(?:లక్ష|రూపాయ|బ్యాంకు|వివరాలు|పంప)|(?:અભિનંદન|ઇનામ|લોટરી).{0,100}(?:લાખ|રૂપિયા|બેંક|વિગત|મોકલો)|(?:congratulations|lottery|prize).{0,100}(?:won|selected|claim|bank details|send your details|\\$|₹|€|£)|(?:félicitations|gewonnen|gagné|выиграл|恭喜|中奖|مبروك).{0,100}(?:gagné|gewonnen|приз|奖金|جائزة|coordonnées|bankdaten|банковские|بيانات|信息)/giu,
  },
  {
    id: "FIN-05",
    category: "financial_pressure",
    weight: 30,
    severity: "high",
    title: "Fee to Release a Delivery or Job Offer",
    description: "Requests an advance fee for a delivery, job, or promised return.",
    pattern:
      /(?:pay|send|transfer|registration|processing).{0,35}(?:fee|charge|₹|rs\\.?\\s*\\d)|(?:₹|rs\\.?\\s*\\d).{0,35}(?:registration|fee|charge)|(?:पार्सल|डिलीवरी|वितरण|शुल्क|फीस|नौकरी|रजिस्ट्रेशन|निवेश).{0,70}(?:₹|रुपये|शुल्क|फीस|भरें|भुगतान|कमाएं|कमाएँ|गारंटी|लाभ)|(?:delivery|parcel|paquete|paket|envío|envoi|lieferung|رسوم|طرد|शुल्क|ఫీజు|கட்டணம்).{0,60}(?:fee|charge|pay|₹|€|rs\\.?|paga|pagar|bezahlen|frais|paye|₹|€)|(?:invest|investment|10x|guaranteed return).{0,60}(?:₹|rs\\.?|return|profit|guaranteed|invest)|(?:invest|crypto|return).{0,60}(?:कमाई|लाभ|गारंटीड|निवेश|नफा|નફો|లాભం|లాભాలు)/giu,
  },
  {
    id: "LINK-01",
    category: "suspicious_link",
    weight: 25,
    severity: "high",
    title: "Obfuscated / Shortened Link",
    description: "Uses public URL shorteners that obscure the real final destination domain.",
    pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)\/[a-zA-Z0-9_-]+/gi,
  },
  {
    id: "LINK-02",
    category: "suspicious_link",
    weight: 30,
    severity: "high",
    title: "Raw IP Address Link",
    description: "Directs recipient to a raw IP address rather than a registered, branded domain name.",
    pattern: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s]*)?/gi,
  },
  {
    id: "LINK-03",
    category: "suspicious_link",
    weight: 30,
    severity: "high",
    title: "Deceptive Brand Mimic Link",
    description: "Directs to a domain name containing hyphenated brand mimicry words commonly used in phishing portals.",
    pattern: /https?:\/\/(?=[a-zA-Z0-9.-]*-(?:kyc|bank|support|verify|bill|login|account|secure|alert|check))[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/gi,
  },
  {
    id: "LINK-04",
    category: "suspicious_link",
    weight: 15,
    severity: "medium",
    title: "Unencrypted HTTP Link",
    description: "Uses insecure, unencrypted HTTP protocol for sensitive portal access.",
    pattern: /http:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?/gi,
  },
  {
    id: "LINK-05",
    category: "suspicious_link",
    weight: 25,
    severity: "high",
    title: "Link Paired with a Request to Act",
    description: "Pairs a link with a payment, prize, verification, or delivery request.",
    pattern:
      /(?:pay|fee|charge|prize|lottery|won|invest|return|₹|रुपये|शुल्क|फीस|भुगतान|लॉटरी|पुरस्कार|इनाम|कमाएं|कमाएँ|निवेश|கட்டணம்|ಫೀಜು|ఫీజు|પેમેન્ટ|€|رسوم|رسوم|信息).{0,100}https?:\/\/[^\s]+|https?:\/\/[^\s]+.{0,100}(?:pay|fee|charge|prize|lottery|won|invest|return|₹|रुपये|शुल्क|फीस|भुगतान|लॉटरी|पुरस्कार|इनाम|कमाएं|कमाएँ|निवेश|கட்டணம்|ఫీజు|પેમેન્ટ|€|رسوم)/giu,
  },
  {
    id: "LINK-06",
    category: "suspicious_link",
    weight: 25,
    severity: "high",
    title: "Link Paired with an Account or Delivery Action",
    description: "Pairs a link with an account-verification or delivery instruction.",
    pattern:
      /(?:verify|login|confirm.{0,15}address|लॉगिन|सत्यापित|सक्रिय|जांच|तुरंत|अभी|যাচাই|এখনই|சரிபார்க்க|உடனே|ధృవీకరించ|వెంటనే|ચકાસો|તરત|verificar|confirmar|bestätigen|prüfen|vérifier|подтверд|确认|تأكيد|تأکيد|update karein).{0,100}https?:\/\/[^\s]+|https?:\/\/[^\s]+.{0,100}(?:verify|login|confirm.{0,15}address|लॉगिन|सत्यापित|सक्रिय|जांच|तुरंत|अभी|যাচাই|এখনই|சரிபார்க்க|உடனே|ధృవీకరించ|వెంటనే|ચકાસો|તરત|verificar|confirmar|bestätigen|prüfen|vérifier|подтверд|确认|تأكيد|تأکيد|update karein)/giu,
  },
  {
    id: "IMP-01",
    category: "impersonation",
    weight: 25,
    severity: "high",
    title: "Unofficial Personal Contact Channel",
    description: "Instructs resolution of official billing or service disputes via a personal 10-digit mobile number.",
    pattern: /\b(?:contact|call|whatsapp|reach)\s+(?:our\s+)?(?:[a-zA-Z]+\s+)?(?:officer|executive|manager|agent)\s+(?:at\s+|on\s+)?(?:[+]?91[- ]?)?[6-9]\d{4}[- ]?\d{5}\b/gi,
  },
  {
    id: "IMP-02",
    category: "impersonation",
    weight: 20,
    severity: "medium",
    title: "Personal Mobile as Helpline",
    description: "Presents a personal mobile number as an official corporate or utility customer desk.",
    pattern: /\b(?:customer\s+care|helpline|support\s+desk)\s+(?:at\s+|on\s+)?[6-9]\d{9}\b/gi,
  },
  {
    id: "UPI-01",
    category: "upi_payment_scam",
    weight: 35,
    severity: "high",
    title: "QR Code Money Receipt Trap",
    description: "Instructs recipient to scan a QR code to receive money. Scanning a QR code can only debit funds, never credit them.",
    pattern: /\b(?:scan\s+(?:this\s+)?(?:qr|qr\s*code)\s+(?:to\s+)?(?:receive|get|credit|claim)\s+(?:money|cash|payment|amount|funds|₹|rs))\b|\b(?:qr\s*code\s+scan\s+karein\s+(?:paise\s+)?(?:paane|lene|credit)\s+ke\s+liye)\b/gi,
  },
  {
    id: "UPI-02",
    category: "upi_payment_scam",
    weight: 35,
    severity: "high",
    title: "UPI PIN for Receiving Funds Deception",
    description: "Prompts entry of UPI PIN / MPIN to receive payments or refunds. Entering a UPI PIN always authorizes an outgoing payment.",
    pattern: /\b(?:enter|put|submit|provide)\s+(?:your\s+)?(?:upi\s*pin|mpin)\s+(?:to\s+)?(?:receive|credit|accept|claim|get)\s+(?:money|payment|cash|refund|amount|₹|rs)\b/gi,
  },
  {
    id: "UPI-03",
    category: "upi_payment_scam",
    weight: 30,
    severity: "high",
    title: "Deceptive UPI Collect Request",
    description: "Prompts approval of a UPI collect or debit request under the guise of receiving payments.",
    pattern: /\b(?:approve|accept)\s+(?:the\s+)?(?:upi\s+)?(?:collect\s+request|payment\s+request)\s+(?:to\s+)?(?:receive|claim|credit|get)\b/gi,
  },
  {
    id: "KYC-01",
    category: "credential_theft",
    weight: 30,
    severity: "high",
    title: "KYC Expiry / Account Suspension Threat",
    description: "Threatens that banking access or SIM card will be deactivated due to pending KYC or PAN update.",
    pattern: /\b(?:kyc|pan\s+(?:card|number)|aadhaar)\s+(?:has\s+expired|is\s+pending|incomplete|deactivated|needs\s+update|not\s+updated)\b/gi,
  },
  {
    id: "BANK-01",
    category: "impersonation",
    weight: 25,
    severity: "high",
    title: "Bank Account Freeze Alert",
    description: "Claims bank account has been frozen, blocked, or suspended due to security violations.",
    pattern: /\b(?:dear\s+customer\b[^.!?;\n]*?\b(?:sbi|hdfc|icici|axis|pnb|bob|kotak|canara|bank)\s+(?:account|a\/c)\s+(?:has\s+been|is)\s+(?:blocked|suspended|frozen|deactivated|locked))\b/gi,
  },
  {
    id: "BANK-02",
    category: "financial_pressure",
    weight: 25,
    severity: "medium",
    title: "Expiring Card Points / Limit Lure",
    description: "Claims credit card reward points are expiring today and prompts urgent redemption for cash.",
    pattern: /\b(?:credit\s+card\s+)?(?:reward\s+points?|card\s+points?)\s+(?:worth\s+(?:rs|inr|₹)[\d,]+)?\s*(?:are\s+expiring|expire\s+today|expiring\s+soon)\b[^.!?;\n]*?\b(?:redeem|cash\s+out|claim\s+now)\b/gi,
  },
  {
    id: "DELIV-01",
    category: "delivery_scam",
    weight: 25,
    severity: "high",
    title: "Detained Package Address/Rescheduling Fee",
    description: "Claims a parcel cannot be delivered due to incomplete address and demands a fee or link click to reschedule.",
    pattern: /\b(?:package|parcel|shipment|courier)\s+(?:is\s+held|detained|stopped|failed|undeliverable|could\s+not\s+be\s+delivered)\b[^.!?;\n]*?\b(?:incomplete\s+address|reschedule|update\s+address|pay\s+(?:redelivery|fee|charge))\b/gi,
  },
  {
    id: "DELIV-02",
    category: "delivery_scam",
    weight: 30,
    severity: "high",
    title: "Customs Duty / Border Detention Extortion",
    description: "Demands urgent customs duty or clearance fees to release supposed international parcel or gift.",
    pattern: /\b(?:customs|border\s+control|customs\s+office)\b[^.!?;\n]*?\b(?:parcel|consignment|gift|package)\s+(?:held|detained|seized)\b/gi,
  },
  {
    id: "JOB-01",
    category: "job_scam",
    weight: 30,
    severity: "high",
    title: "Deceptive Part-Time / WFH Daily Earning Lure",
    description: "Advertises unrealistic daily income for simple tasks such as liking videos, rating hotels, or basic typing.",
    pattern: /\b(?:part[- ]time\s+job|work\s+from\s+home\s+job|daily\s+earning\s+job)\b[^.!?;\n]*?\b(?:earn\s+(?:rs\.?|inr|₹|\$)\s*[\d,]+(?:\s*-\s*[\d,]+)?\s*(?:daily|per\s+day|every\s+day))\b|\b(?:like\s+(?:youtube\s+)?videos?|rate\s+hotels?|google\s+reviews?)\s+(?:and\s+earn|for\s+(?:daily\s+)?income|earn\s+(?:rs\.?|inr|₹))\b/gi,
  },
  {
    id: "JOB-02",
    category: "job_scam",
    weight: 30,
    severity: "high",
    title: "Upfront Job Registration / Security Fee",
    description: "Requires job applicants to transfer an advance registration fee, interview deposit, or training kit fee.",
    pattern: /\b(?:pay|deposit|transfer|send)\s+(?:refundable\s+)?(?:registration\s+fee|security\s+deposit|joining\s+fee|processing\s+charge|kit\s+fee)\b[^.!?;\n]*?\b(?:for\s+(?:the\s+)?job|to\s+start\s+work|offer\s+letter|selection)\b/gi,
  },
  {
    id: "INV-01",
    category: "investment_fraud",
    weight: 30,
    severity: "high",
    title: "Guaranteed High-Yield Investment / Crypto Scheme",
    description: "Promises guaranteed multiplication of capital or risk-free daily returns on crypto/forex trading.",
    pattern: /\b(?:guaranteed|assured|risk[- ]free)\s+(?:return|profit|daily\s+(?:income|profit)|100%|200%|double)\b|\b(?:double|triple)\s+(?:your\s+)?(?:crypto|cryptocurrency|bitcoin|money|investment)\b|\b(?:invest\s+(?:rs\.?|inr|₹|\$)\s*[\d,]+\s+and\s+get\s+(?:rs\.?|inr|₹|\$)\s*[\d,]+)\b/gi,
  },
  {
    id: "INV-02",
    category: "investment_fraud",
    weight: 20,
    severity: "medium",
    title: "VIP Insider Trading Channel Lure",
    description: "Invites recipient to exclusive Telegram or WhatsApp groups promising guaranteed insider trading profits.",
    pattern: /\b(?:join\s+(?:our\s+)?(?:vip|exclusive)\s+(?:telegram|whatsapp)\s+(?:channel|group)|insider\s+(?:stock|trading)\s+signals?|guaranteed\s+(?:stock\s+tips|profit\s+group))\b/gi,
  },
  {
    id: "GOV-01",
    category: "government_impersonation",
    weight: 35,
    severity: "high",
    title: "Digital Arrest / Police / CBI Threat",
    description: "Impersonates law enforcement or judicial bodies alleging arrest warrants or illegal parcel involvement.",
    pattern: /\b(?:digital\s+arrest|police\s+headquarters|cbi|central\s+bureau|enforcement\s+directorate|supreme\s+court|high\s+court|interpol|customs\s+narcotics)\b[^.!?;\n]*?\b(?:arrest\s+warrant|fir\s+registered|money\s+laundering|illegal\s+(?:parcel|drugs|consignment)|legal\s+action)\b/gi,
  },
  {
    id: "GOV-02",
    category: "government_impersonation",
    weight: 25,
    severity: "high",
    title: "Unsolicited Income Tax Refund Lure",
    description: "Claims an income tax refund is approved and demands account verification or credential entry.",
    pattern: /\b(?:income\s*tax\s+department|it\s+department|income\s*tax\s+refund)\b[^.!?;\n]*?\b(?:refund\s+of\s+(?:rs\.?|inr|₹)\s*[\d,]+|refund\s+approved|claim\s+your\s+tax\s+refund)\b/gi,
  },
  {
    id: "REMOTE-01",
    category: "remote_access",
    weight: 35,
    severity: "high",
    title: "Remote Access Software Installation Lure",
    description: "Instructs recipient to install remote-desktop applications (AnyDesk, TeamViewer, QuickSupport, RustDesk) allowing device takeover.",
    pattern: /\b(?:install|download|open)\s+(?:the\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk|airdroid|screenshare)\b/gi,
  },
  {
    id: "SUPPORT-01",
    category: "tech_support",
    weight: 20,
    severity: "medium",
    title: "Unsolicited Support Executive Connection",
    description: "Instructs recipient to resolve pending refunds, transactions, or account issues with an unverified executive.",
    pattern: /\b(?:support\s+executive|helpdesk\s+officer)\s+(?:will\s+assist|to\s+process\s+(?:refund|cancellation|reversal)|call\s+back)\b/gi,
  },
  {
    id: "REFUND-01",
    category: "financial_pressure",
    weight: 25,
    severity: "high",
    title: "Accidental Money Credit / Overpayment Reversal Lure",
    description: "Claims money was erroneously credited to recipient's account and demands immediate return or refund action.",
    pattern: /\b(?:(?:mistakenly|accidentally|wrongly)\s+(?:credited|transferred|sent)|(?:was\s+)?(?:mistakenly|accidentally|wrongly)\s+credited|(?:credited|transferred)\s+by\s+mistake)\b/gi,
  },
  {
    id: "EMERG-01",
    category: "financial_pressure",
    weight: 30,
    severity: "high",
    title: "Urgent Family / Medical Emergency Money Wire",
    description: "Fakes an urgent medical emergency, hospital bill, or arrest scenario to extort funds from relatives or friends.",
    pattern: /\b(?:in\s+hospital|hospital\s+emergency|police\s+custody|urgent\s+medical\s+bill)\b[^.!?;\n]*?\b(?:send\s+(?:money|cash|funds)|transfer\s+(?:immediately|urgent|rs\.?|inr|₹|\$)|need\s+urgent\s+money)\b/gi,
  },
  {
    id: "ATTACH-01",
    category: "malicious_attachment",
    weight: 35,
    severity: "high",
    title: "Suspicious Android Application (.apk) Download",
    description: "Prompts direct download of Android application package (.apk) file outside official app stores.",
    pattern: /\b(?:download|install)\s+(?:the\s+)?(?:sbi|bank|update|bill|rewards?|support|challan|payment)[a-zA-Z0-9_-]*\.apk\b|\b[a-zA-Z0-9_-]+\.apk\b/gi,
  },
  {
    id: "TECH-01",
    category: "tech_support",
    weight: 30,
    severity: "high",
    title: "Fake Virus Infection / Security Alert",
    description: "Claims device is infected with viruses or compromised to coerce user into calling fake support or downloading software.",
    pattern: /\b(?:(?:virus(?:es)?|trojan|malware|spyware)\s+detected|device\s+(?:is\s+)?(?:infected|compromised)|critical\s+security\s+breach)\b/gi,
  },
];

/**
 * Segment raw message into clause spans using sentence/clause delimiters.
 */
export function segmentClauses(text: string): ClauseSpan[] {
  const clauses: ClauseSpan[] = [];
  let currentStart = 0;

  const delimiterRegex = new RegExp(CLAUSE_DELIMITER_REGEX.source, "gi");
  let match: RegExpExecArray | null;

  while ((match = delimiterRegex.exec(text)) !== null) {
    const end = match.index;
    if (end > currentStart) {
      clauses.push({
        start: currentStart,
        end,
        text: text.slice(currentStart, end),
      });
    }
    currentStart = match.index + match[0].length;
  }

  if (currentStart < text.length) {
    clauses.push({
      start: currentStart,
      end: text.length,
      text: text.slice(currentStart),
    });
  }

  return clauses;
}

/**
 * Detect advisory suppression zones where protective negation is active.
 */
export function findAdvisoryZones(text: string): AdvisoryZone[] {
  const clauses = segmentClauses(text);
  const zones: AdvisoryZone[] = [];

  for (const clause of clauses) {
    for (const rule of NEGATION_RULES) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
      const match = regex.exec(clause.text);
      if (match) {
        zones.push({
          start: clause.start,
          end: clause.end,
          matchedText: match[0],
          ruleId: rule.id,
        });
        break; // One negation match per clause is sufficient
      }
    }
  }

  return zones;
}
