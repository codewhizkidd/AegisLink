// brands.js
// Known brands commonly impersonated in phishing, mapped to their legitimate
// sending domains. If the email BODY or SUBJECT mentions a brand by name but
// the sender's domain isn't in this list for that brand -> impersonation flag.
//
// This list is intentionally small and editable. Add more brands as needed
// in options.html -> "Custom brands" (stored in chrome.storage.sync).

const BUILTIN_BRANDS = {
  "paypal":     { display: "PayPal",     domains: ["paypal.com"] },
  "microsoft":  { display: "Microsoft",  domains: ["microsoft.com", "outlook.com", "live.com", "office.com"] },
  "apple":      { display: "Apple",      domains: ["apple.com", "icloud.com"] },
  "google":     { display: "Google",     domains: ["google.com", "gmail.com", "googlemail.com"] },
  "amazon":     { display: "Amazon",     domains: ["amazon.com", "amazon.in", "amazon.co.uk"] },
  "netflix":    { display: "Netflix",    domains: ["netflix.com"] },
  "facebook":   { display: "Facebook",   domains: ["facebook.com", "fb.com"] },
  "instagram":  { display: "Instagram",  domains: ["instagram.com"] },
  "linkedin":   { display: "LinkedIn",   domains: ["linkedin.com"] },
  "chase":      { display: "Chase Bank", domains: ["chase.com"] },
  "wellsfargo": { display: "Wells Fargo",domains: ["wellsfargo.com"] },
  "bankofamerica": { display: "Bank of America", domains: ["bankofamerica.com"] },
  "hdfc":       { display: "HDFC Bank",  domains: ["hdfcbank.com"] },
  "icici":      { display: "ICICI Bank", domains: ["icicibank.com"] },
  "sbi":        { display: "State Bank of India", domains: ["sbi.co.in", "onlinesbi.sbi"] },
  "dhl":        { display: "DHL",        domains: ["dhl.com"] },
  "fedex":      { display: "FedEx",      domains: ["fedex.com"] },
  "ups":        { display: "UPS",        domains: ["ups.com"] },
  "irs":        { display: "IRS",        domains: ["irs.gov"] },
  "docusign":   { display: "DocuSign",   domains: ["docusign.com", "docusign.net"] },
  "adobe":      { display: "Adobe",      domains: ["adobe.com"] },
  "coinbase":   { display: "Coinbase",   domains: ["coinbase.com"] },
  "binance":    { display: "Binance",    domains: ["binance.com"] },
  "steam":      { display: "Steam",      domains: ["steampowered.com", "steamcommunity.com"] }
};

// Common free-mail providers -> "free provider claiming to be a company" rule
const FREE_PROVIDERS = [
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
  "proton.me", "protonmail.com", "mail.com", "gmx.com", "yandex.com", "zoho.com"
];

// Known URL shorteners -> unshorten before further analysis
const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly"
];

// Weighted risk TLDs (signal only, never sole trigger)
const RISKY_TLDS = ["tk", "ml", "gq", "cf", "ga", "xyz", "top", "work", "click", "loan"];

if (typeof module !== "undefined") {
  module.exports = { BUILTIN_BRANDS, FREE_PROVIDERS, URL_SHORTENERS, RISKY_TLDS };
}