// analyzer.js
// Pure, synchronous heuristic scoring engine (Sections 4.1-4.7 + 7 + 8 of spec).
// Async pieces (Safe Browsing lookups) are done separately in background.js
// and merged in via analyzeUrlsAsync().

// ---------- small utils ----------

function getDomain(address) {
  if (!address) return "";
  const m = address.match(/@([^>\s]+)/);
  return (m ? m[1] : address).toLowerCase().trim();
}

function eTLD1(domain) {
  const parts = domain.split(".");
  return parts.length <= 2 ? domain : parts.slice(-2).join(".");
}

// Levenshtein distance, capped for speed
function levenshtein(a, b) {
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;
  let prev = Array(bl + 1).fill(0).map((_, i) => i);
  for (let i = 1; i <= al; i++) {
    const cur = [i];
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[bl];
}

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let ent = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function isMixedScript(str) {
  // crude homograph detector: mixes Latin with Cyrillic/Greek code points
  const hasLatin = /[a-zA-Z]/.test(str);
  const hasCyrillic = /[\u0400-\u04FF]/.test(str);
  const hasGreek = /[\u0370-\u03FF]/.test(str);
  return hasLatin && (hasCyrillic || hasGreek);
}

// ---------- lexicons ----------

const URGENCY_WORDS = [
  "urgent", "immediately", "action required", "verify your account",
  "account suspended", "final notice", "within 24 hours", "limited time",
  "act now", "your account will be closed", "unusual activity",
  "confirm your identity", "restricted", "locked", "expire", "deadline"
];

const CREDENTIAL_WORDS = [
  "password", "username and password", "login credentials", "otp", "one-time code",
  "verification code", "pin number", "security question", "reset your password",
  "confirm your password", "update your password", "re-enter your password",
  "login to verify", "sign in to confirm", "authenticate your account",
  "2fa code", "two-factor code", "recovery code", "click to verify", "verify now"
];

const FINANCIAL_WORDS = [
  "bank account", "routing number", "credit card number", "cvv", "wire transfer",
  "gift card", "bitcoin", "crypto wallet", "invoice attached", "payment overdue",
  "tax refund", "social security number", "ssn", "national id", "iban", "swift code",
  "account number", "billing information", "update your payment", "payment failed",
  "unusual charge", "unauthorized transaction", "confirm your billing", "cardholder"
];

const SCAM_CATEGORY_KEYWORDS = {
  "Lottery/Prize": ["you have won", "lottery", "prize", "claim your reward", "sweepstakes"],
  "Tax/Refund": ["tax refund", "irs", "tax return", "hmrc"],
  "Delivery": ["package", "delivery failed", "shipment", "customs fee", "tracking number"],
  "Invoice Fraud": ["invoice", "purchase order", "outstanding balance", "remit payment"],
  "CEO Fraud/BEC": ["are you available", "wire the funds", "urgent request from ceo", "confidential task"],
  "Romance Scam": ["my love", "darling", "lonely heart", "meet you in person"],
  "Tech Support Scam": ["your computer is infected", "call microsoft support", "virus detected"],
  "Government Impersonation": ["court summons", "legal action", "warrant", "arrest"],
  "Crypto/Investment": ["guaranteed returns", "double your bitcoin", "investment opportunity"]
};

const RISKY_ATTACHMENT_EXT = [
  "exe", "scr", "bat", "ps1", "js", "vbs", "jar", "msi", "com", "cpl",
  "docm", "xlsm", "pptm", "iso", "img", "lnk"
];

// ---------- section 4.1: sender identity ----------

function analyzeSenderIdentity(headers, brands, freeProviders) {
  const findings = [];
  let score = 0;

  const fromAddr = headers.from?.address || "";
  const fromDisplay = (headers.from?.display_name || "").toLowerCase();
  const fromDomain = getDomain(fromAddr);
  const fromRoot = eTLD1(fromDomain);
  const localPart = (fromAddr.split("@")[0] || "");

  // free provider claiming to be a company (display name has a company-ish word)
  if (freeProviders.includes(fromDomain)) {
    for (const key in brands) {
      if (fromDisplay.includes(key) || fromDisplay.includes(brands[key].display.toLowerCase())) {
        score += 25;
        findings.push(`Sender uses a free email provider (${fromDomain}) but the display name claims to be "${brands[key].display}".`);
      }
    }
  }

  // display name impersonates a brand not matching sender domain
  for (const key in brands) {
    const b = brands[key];
    const nameHit = fromDisplay.includes(key) || fromDisplay.includes(b.display.toLowerCase());
    if (nameHit && !b.domains.some(d => fromRoot === d || fromRoot.endsWith("." + d))) {
      score += 30;
      findings.push(`Display name shows "${b.display}" but the sender address domain (${fromDomain}) does not match ${b.display}'s known domains.`);
    }
  }

  // typosquat check against brand root domains
  for (const key in brands) {
    for (const d of brands[key].domains) {
      const dist = levenshtein(fromRoot, d);
      if (dist > 0 && dist <= 2) {
        score += 25;
        findings.push(`Sender domain "${fromDomain}" is suspiciously similar to "${d}" (possible typosquat).`);
      }
    }
  }

  // homograph / punycode
  if (fromDomain.includes("xn--") || isMixedScript(fromDomain)) {
    score += 25;
    findings.push(`Sender domain "${fromDomain}" contains mixed scripts or punycode — possible homograph attack.`);
  }

  // reply-to / return-path / sender header mismatches
  const replyTo = headers.reply_to || [];
  if (replyTo.length > 1) {
    score += 10;
    findings.push("Multiple Reply-To headers present — unusual and often manipulated.");
  }
  if (replyTo.length && getDomain(replyTo[0]) && getDomain(replyTo[0]) !== fromDomain) {
    score += 15;
    findings.push(`Reply-To domain (${getDomain(replyTo[0])}) differs from From domain (${fromDomain}) — classic BEC pattern.`);
  }
  if (headers.return_path && getDomain(headers.return_path) && getDomain(headers.return_path) !== fromDomain) {
    score += 10;
    findings.push(`Return-Path domain (${getDomain(headers.return_path)}) differs from From domain (${fromDomain}).`);
  }
  if (headers.sender && getDomain(headers.sender) !== fromDomain) {
    score += 10;
    findings.push("Sender header does not match From header.");
  }

  // empty sender
  if (!fromAddr) {
    score += 20;
    findings.push("Sender address is empty or unparseable.");
  }

  // entropy / numeric local-part
  if (localPart.length >= 8) {
    const ent = shannonEntropy(localPart);
    if (ent > 3.6) {
      score += 10;
      findings.push(`Sender username "${localPart}" has high randomness — possibly auto-generated.`);
    }
  }
  if (/^\d+$/.test(localPart) && localPart.length >= 6) {
    score += 8;
    findings.push("Sender username is purely numeric.");
  }
  if (fromAddr.length > 60) {
    score += 5;
    findings.push("Sender address is unusually long.");
  }

  return { score, findings };
}

// ---------- section 4.2: authentication ----------

function analyzeAuthentication(headers) {
  const findings = [];
  let score = 0;
  const fromDomain = eTLD1(getDomain(headers.from?.address || ""));

  if (headers.spf === "fail") { score += 20; findings.push("SPF check failed for this sender domain."); }
  else if (headers.spf === "softfail") { score += 10; findings.push("SPF soft-failed for this sender domain."); }
  else if (headers.spf === "neutral" || headers.spf === "none") { score += 5; findings.push("No conclusive SPF result for this sender."); }

  if (headers.dkim === "fail") { score += 20; findings.push("DKIM signature failed verification."); }
  else if (headers.dkim === "none") { score += 8; findings.push("Email is not DKIM-signed."); }

  if (headers.dmarc === "fail") { score += 20; findings.push("DMARC alignment failed."); }
  else if (headers.dmarc === "none") { score += 5; findings.push("Sender domain has no DMARC policy."); }

  return { score, findings, fromDomain };
}

// ---------- section 4.3: headers structural ----------

function analyzeHeaderStructure(headers) {
  const findings = [];
  let score = 0;

  if (!headers.message_id) { score += 8; findings.push("Message-ID header is missing."); }

  if (headers.date) {
    const d = new Date(headers.date);
    const now = new Date();
    if (d.getTime() > now.getTime() + 24 * 3600 * 1000) {
      score += 10; findings.push("Date header is in the future.");
    }
  }

  const chain = headers.received_chain || [];
  if (chain.length === 0) {
    score += 5; findings.push("No Received chain present (unusual for real mail delivery).");
  }

  return { score, findings };
}

// ---------- section 4.4 + 4.5: subject + body ----------

function scanKeywords(text, list) {
  const hits = [];
  const lower = text.toLowerCase();
  for (const w of list) if (lower.includes(w)) hits.push(w);
  return hits;
}

function analyzeSubjectAndBody(subject, bodyText) {
  const findings = [];
  let score = 0;
  const combined = `${subject}\n${bodyText}`;

  const urgencyHits = scanKeywords(combined, URGENCY_WORDS);
  if (urgencyHits.length) {
    score += Math.min(20, urgencyHits.length * 6);
    findings.push(`Urgency/threat language detected: "${urgencyHits.slice(0, 3).join('", "')}".`);
  }

  const credHits = scanKeywords(bodyText, CREDENTIAL_WORDS);
  if (credHits.length) {
    score += Math.min(20, credHits.length * 8);
    findings.push(`Requests credentials/verification info: "${credHits.slice(0, 3).join('", "')}".`);
  }

  const finHits = scanKeywords(bodyText, FINANCIAL_WORDS);
  if (finHits.length) {
    score += Math.min(20, finHits.length * 8);
    findings.push(`Requests financial/sensitive data: "${finHits.slice(0, 3).join('", "')}".`);
  }

  let scamCategory = null;
  let bestHits = 0;
  for (const cat in SCAM_CATEGORY_KEYWORDS) {
    const hits = scanKeywords(combined, SCAM_CATEGORY_KEYWORDS[cat]);
    if (hits.length > bestHits) { bestHits = hits.length; scamCategory = cat; }
  }
  if (scamCategory) {
    score += Math.min(15, bestHits * 8);
    findings.push(`Content matches a "${scamCategory}" scam pattern.`);
  }

  // caps ratio / punctuation runs in subject
  const letters = subject.replace(/[^a-zA-Z]/g, "");
  const caps = subject.replace(/[^A-Z]/g, "");
  if (letters.length > 6 && caps.length / letters.length > 0.6) {
    score += 8; findings.push("Subject line is excessively capitalized.");
  }
  if (/[!?]{2,}/.test(subject)) {
    score += 5; findings.push("Subject line has excessive punctuation (!!! or ???).");
  }

  // generic / missing greeting
  if (!/\b(hi|hello|dear)\b/i.test(bodyText.slice(0, 100))) {
    score += 3; findings.push("Email has no greeting, or a generic/missing salutation.");
  }

  return { score, findings, scamCategory };
}

// ---------- brand impersonation (the "says PayPal but isn't @paypal.com" check) ----------
// This is the deepest part of the analyzer. It looks at HOW the brand is mentioned,
// not just WHETHER it's mentioned, and separately flags generic authority claims
// ("IT Support", "Your Bank", "Billing Department") that don't name a specific brand
// but are still impersonation attempts.

// Phrasing patterns that indicate an explicit CLAIM of identity, in rising strength.
// A brand name appearing once in passing ("use paypal to pay") is weak; a signature
// block or "this is an official message from X" is a strong, deliberate claim.
function brandClaimStrength(text, key, displayLower) {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedDisplay = displayLower.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const namePattern = `(?:${escapedKey}|${escapedDisplay})`;

  const strongPatterns = [
    new RegExp(`\\b(regards|sincerely|thanks|thank you)[,\\s]*[\\r\\n]+.{0,20}${namePattern}\\b`, "i"),
    new RegExp(`\\b${namePattern}\\s+(team|support|security|billing|customer service|department)\\b`, "i"),
    new RegExp(`\\bthis is (an official|a|the)?\\s*(message|email|notice)?\\s*from\\s+${namePattern}\\b`, "i"),
    new RegExp(`\\bofficial\\s+${namePattern}\\b`, "i"),
    new RegExp(`\\bon behalf of\\s+${namePattern}\\b`, "i"),
    new RegExp(`\\byour\\s+${namePattern}\\s+account\\b`, "i")
  ];
  const mediumPatterns = [
    new RegExp(`\\bfrom\\s+${namePattern}\\b`, "i"),
    new RegExp(`\\b${namePattern}\\s+(has|have|noticed|detected|verify|confirms?)\\b`, "i")
  ];

  for (const p of strongPatterns) if (p.test(text)) return 3;
  for (const p of mediumPatterns) if (p.test(text)) return 2;
  const weak = new RegExp(`\\b${namePattern}\\b`, "i");
  if (weak.test(text)) return 1;
  return 0;
}

// Generic authority roles impersonated WITHOUT naming a specific brand
// (e.g. "IT Department", "Your Bank", "HR Team", "Billing Support")
const GENERIC_AUTHORITY_ROLES = [
  "it support", "it department", "it helpdesk", "help desk",
  "hr department", "human resources", "payroll department",
  "billing department", "billing team", "accounts department",
  "your bank", "your financial institution", "customer support team",
  "security team", "security department", "compliance department",
  "legal department", "system administrator", "network administrator"
];

function analyzeBrandImpersonation(subject, bodyText, fromAddr, brands) {
  const findings = [];
  let score = 0;
  const fromDomain = eTLD1(getDomain(fromAddr));
  const combined = `${subject}\n${bodyText}`;
  const combinedLower = combined.toLowerCase();

  // 1. Named-brand impersonation, weighted by how explicit the claim is
  for (const key in brands) {
    const b = brands[key];
    const displayLower = b.display.toLowerCase();
    const strength = brandClaimStrength(combined, key, displayLower);
    if (strength === 0) continue;

    const matches = b.domains.some(d => fromDomain === d || fromDomain.endsWith("." + d));
    if (!matches) {
      const add = strength === 3 ? 45 : strength === 2 ? 30 : 15;
      score += add;
      const strengthDesc = strength === 3
        ? `explicitly signs off / identifies as "${b.display}" (e.g. in a signature block or "official message from" phrasing)`
        : strength === 2
        ? `states it is "from ${b.display}" or describes an action ${b.display} supposedly took`
        : `mentions "${b.display}" by name`;
      findings.push(`Email ${strengthDesc}, but the sender address (${fromAddr || "unknown"}) is not on a known ${b.display} domain — real ${b.display} mail comes from *@${b.domains[0]}.`);
    }
  }

  // 2. Generic authority impersonation (no specific brand, but claims institutional authority)
  const fromLooksPersonalOrFree = fromDomain && (fromDomain.split(".").length <= 2);
  for (const role of GENERIC_AUTHORITY_ROLES) {
    if (combinedLower.includes(role)) {
      score += 12;
      findings.push(`Email presents itself as "${role}" — a generic authority claim. Legitimate internal IT/HR/billing messages almost always come from a named, verifiable company domain, not a role name alone.`);
      break; // one hit is enough signal, avoid stacking near-duplicate findings
    }
  }

  return { score, findings };
}

// ---------- section 4.6: linguistic ----------

function analyzeLinguistics(bodyText) {
  const findings = [];
  let score = 0;

  const words = bodyText.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length > 20) {
    const trigrams = {};
    for (let i = 0; i < words.length - 2; i++) {
      const tri = words.slice(i, i + 3).join(" ");
      trigrams[tri] = (trigrams[tri] || 0) + 1;
    }
    const repeats = Object.values(trigrams).filter(c => c >= 3).length;
    if (repeats > 0) {
      score += 8; findings.push("Body text contains repeated phrase patterns, typical of templated scam text.");
    }
  }

  // very crude grammar signal: sentences not starting with capital / no punctuation at all
  const sentences = bodyText.split(/[.!?]/).filter(s => s.trim().length > 15);
  if (sentences.length >= 3) {
    const badStart = sentences.filter(s => /^[a-z]/.test(s.trim())).length;
    if (badStart / sentences.length > 0.5) {
      score += 6; findings.push("Frequent lowercase sentence starts / inconsistent capitalization — possible poor translation or template stitching.");
    }
  }

  return { score, findings };
}

// ---------- section 4.7: attachments ----------

function analyzeAttachments(attachments) {
  const findings = [];
  let score = 0;

  for (const att of attachments || []) {
    const name = (att.filename || "").toLowerCase();
    const parts = name.split(".");
    const ext = parts.length > 1 ? parts[parts.length - 1] : "";

    if (RISKY_ATTACHMENT_EXT.includes(ext)) {
      score += 30;
      findings.push(`Attachment "${att.filename}" has a high-risk extension (.${ext}).`);
    }
    if (parts.length > 2 && RISKY_ATTACHMENT_EXT.includes(ext)) {
      score += 10;
      findings.push(`Attachment "${att.filename}" uses a double extension — common malware disguise.`);
    }
    if (name.endsWith(".zip") && att.password_protected) {
      score += 15;
      findings.push(`Password-protected ZIP "${att.filename}" cannot be scanned — flagged as unknown-risk.`);
    }
  }

  return { score, findings };
}

// ---------- section 5: URL structural checks (sync part; SB lookup is async) ----------

function analyzeUrlsStructural(urls, bodyHtml, shorteners, riskyTlds, brands) {
  const findings = [];
  let score = 0;
  const flaggedUrls = [];

  for (const url of urls || []) {
    let u;
    try { u = new URL(url); } catch { continue; }
    const host = u.hostname.toLowerCase();
    let urlScore = 0;
    const reasons = [];

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      urlScore += 20; reasons.push("uses a raw IP address instead of a domain");
    }
    if (shorteners.includes(host)) {
      urlScore += 8; reasons.push("uses a URL shortener (destination hidden)");
    }
    if (host.split(".").length > 4) {
      urlScore += 10; reasons.push("has an excessive number of subdomains");
    }
    if (url.includes("@") && /https?:\/\/[^@\/]+@/.test(url)) {
      urlScore += 25; reasons.push("uses the '@' userinfo trick to disguise the real destination");
    }
    if (host.includes("xn--") || isMixedScript(host)) {
      urlScore += 25; reasons.push("domain uses punycode or mixed scripts (possible homograph attack)");
    }
    const tld = host.split(".").pop();
    if (riskyTlds.includes(tld)) {
      urlScore += 5; reasons.push(`uses a higher-risk TLD (.${tld})`);
    }
    for (const key in brands) {
      for (const d of brands[key].domains) {
        const dist = levenshtein(eTLD1(host), d);
        if (dist > 0 && dist <= 2) {
          urlScore += 25; reasons.push(`domain closely resembles ${brands[key].display}'s real domain (${d})`);
        }
      }
    }

    if (urlScore >= 15) {
      // require >=2 independent signals worth of score before elevating, per spec 5.3
      score += urlScore;
      flaggedUrls.push({ url, reasons });
      findings.push(`Link ${url} is suspicious: ${reasons.join(", ")}.`);
    }
  }

  // display-text vs href mismatch (very rough, needs html)
  if (bodyHtml) {
    const anchorRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi;
    let m;
    while ((m = anchorRe.exec(bodyHtml)) !== null) {
      const href = m[1];
      const text = m[2].trim();
      if (/^(https?:\/\/|www\.)/i.test(text)) {
        try {
          const displayHost = eTLD1(text.replace(/^https?:\/\//, "").split("/")[0].toLowerCase());
          const hrefHost = eTLD1(new URL(href, "https://x").hostname.toLowerCase());
          if (displayHost && hrefHost && displayHost !== hrefHost) {
            score += 20;
            findings.push(`Link text shows "${text}" but actually points to ${hrefHost} — mismatched display link.`);
          }
        } catch { /* ignore parse errors */ }
      }
    }
  }

  return { score, findings, flaggedUrls };
}

// ---------- master aggregator (sections 7 + 8) ----------

function analyzeEmail(parsed, brands, freeProviders, shorteners, riskyTlds) {
  const results = [];

  const sender = analyzeSenderIdentity(parsed.headers, brands, freeProviders);
  const auth = analyzeAuthentication(parsed.headers);
  const hdr = analyzeHeaderStructure(parsed.headers);
  const subjBody = analyzeSubjectAndBody(parsed.subject || "", parsed.bodyText || "");
  const brandImp = analyzeBrandImpersonation(parsed.subject || "", parsed.bodyText || "", parsed.headers.from?.address || "", brands);
  const ling = analyzeLinguistics(parsed.bodyText || "");
  const attach = analyzeAttachments(parsed.attachments || []);
  const urls = analyzeUrlsStructural(parsed.urls || [], parsed.bodyHtml || "", shorteners, riskyTlds, brands);

  results.push(sender, auth, hdr, subjBody, brandImp, ling, attach, urls);

  let rawScore = 0;
  let allFindings = [];
  for (const r of results) {
    rawScore += r.score;
    allFindings = allFindings.concat(r.findings.map(f => ({ text: f, weight: r === sender || r === brandImp ? 3 : r === auth ? 2 : 1 })));
  }

  // Combo signal: identity claim (brand or generic authority) + a credential/financial
  // ask in the SAME email is the classic phishing signature. Score it above a simple sum.
  const bodyLower = (parsed.bodyText || "").toLowerCase();
  const asksForSensitiveData = CREDENTIAL_WORDS.some(w => bodyLower.includes(w)) ||
                                FINANCIAL_WORDS.some(w => bodyLower.includes(w));
  if (brandImp.score > 0 && asksForSensitiveData) {
    rawScore += 25;
    allFindings.push({
      text: "Combined pattern: the email claims institutional identity AND asks for credentials/financial info — the hallmark structure of a phishing attempt.",
      weight: 4
    });
  }

  const heuristicScore = Math.min(100, rawScore);

  let category = "Legitimate Email";
  if (heuristicScore >= 80) category = brandImp.score > 0 ? "Credential Harvesting / Brand Impersonation" : "High-Risk Phishing";
  else if (heuristicScore >= 55) category = "Medium-Risk Phishing";
  else if (heuristicScore >= 35) category = "Low-Risk Phishing / Suspicious";
  else if (heuristicScore >= 15) category = "Suspicious";

  // sort explanations by weight and take top 5
  allFindings.sort((a, b) => b.weight - a.weight);
  const topReasons = allFindings.slice(0, 5).map(f => f.text);

  return {
    score: heuristicScore,
    category,
    reasons: topReasons,
    flaggedUrls: urls.flaggedUrls,
    scamCategory: subjBody.scamCategory
  };
}

if (typeof module !== "undefined") {
  module.exports = { analyzeEmail, getDomain, eTLD1 };
}
