// background.js (MV3 service worker)
importScripts("brands.js", "analyzer.js");

const GMAIL_API = "https://www.googleapis.com/gmail/v1/users/me";
const SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

// ---------- auth ----------

function getAuthToken(interactive) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(chrome.runtime.lastError || new Error("No token"));
      } else {
        resolve(token);
      }
    });
  });
}

async function gmailFetch(path, token) {
  const res = await fetch(`${GMAIL_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error(`Gmail API error ${res.status}: ${await res.text()}`);
  return res.json();
}

// ---------- base64url decode ----------

function b64urlDecode(data) {
  if (!data) return "";
  const b64 = data.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return "";
  }
}

// ---------- parse a Gmail API message into the shared schema ----------

function headerVal(headers, name) {
  const h = headers.find(x => x.name.toLowerCase() === name.toLowerCase());
  return h ? h.value : "";
}

function parseAuthResults(raw) {
  const out = { spf: "none", dkim: "none", dmarc: "none" };
  if (!raw) return out;
  const lower = raw.toLowerCase();
  const spfM = lower.match(/spf=(\w+)/);
  const dkimM = lower.match(/dkim=(\w+)/);
  const dmarcM = lower.match(/dmarc=(\w+)/);
  if (spfM) out.spf = spfM[1];
  if (dkimM) out.dkim = dkimM[1];
  if (dmarcM) out.dmarc = dmarcM[1];
  return out;
}

function parseFromHeader(raw) {
  if (!raw) return { display_name: "", address: "" };
  const m = raw.match(/^(.*?)<(.+)>$/);
  if (m) return { display_name: m[1].trim().replace(/^"|"$/g, ""), address: m[2].trim() };
  return { display_name: "", address: raw.trim() };
}

function walkParts(part, acc) {
  if (!part) return;
  const mime = part.mimeType || "";
  if (mime === "text/plain" && part.body?.data) {
    acc.text += b64urlDecode(part.body.data) + "\n";
  } else if (mime === "text/html" && part.body?.data) {
    acc.html += b64urlDecode(part.body.data) + "\n";
  } else if (part.filename) {
    acc.attachments.push({
      filename: part.filename,
      mimeType: mime,
      size: part.body?.size || 0,
      password_protected: false // Gmail API can't tell us this without downloading; treated conservatively elsewhere
    });
  }
  for (const p of part.parts || []) walkParts(p, acc);
}

function extractUrls(text, html) {
  const urls = new Set();
  const urlRe = /https?:\/\/[^\s"'<>)]+/gi;
  let m;
  while ((m = urlRe.exec(text || "")) !== null) urls.add(m[0]);
  while ((m = urlRe.exec(html || "")) !== null) urls.add(m[0]);
  return Array.from(urls);
}

function parseGmailMessage(msg) {
  const headers = msg.payload?.headers || [];
  const authRaw = headerVal(headers, "Authentication-Results");
  const auth = parseAuthResults(authRaw);
  const from = parseFromHeader(headerVal(headers, "From"));
  const replyToRaw = headerVal(headers, "Reply-To");

  const acc = { text: "", html: "", attachments: [] };
  walkParts(msg.payload, acc);
  if (!acc.text && !acc.html && msg.payload?.body?.data) {
    acc.text = b64urlDecode(msg.payload.body.data);
  }
  const bodyText = acc.text || msg.snippet || "";
  const urls = extractUrls(acc.text, acc.html);

  return {
    id: msg.id,
    threadId: msg.threadId,
    subject: headerVal(headers, "Subject"),
    snippet: msg.snippet,
    headers: {
      from,
      reply_to: replyToRaw ? [replyToRaw] : [],
      return_path: headerVal(headers, "Return-Path").replace(/[<>]/g, ""),
      sender: headerVal(headers, "Sender"),
      message_id: headerVal(headers, "Message-ID"),
      date: headerVal(headers, "Date"),
      received_chain: headers.filter(h => h.name.toLowerCase() === "received"),
      spf: auth.spf,
      dkim: auth.dkim,
      dmarc: auth.dmarc,
      authentication_results_raw: authRaw
    },
    bodyText,
    bodyHtml: acc.html,
    urls,
    attachments: acc.attachments
  };
}

// ---------- Safe Browsing ----------

async function checkSafeBrowsing(urls, apiKey) {
  if (!apiKey || !urls.length) return {};
  const body = {
    client: { clientId: "phishguard-extension", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: urls.slice(0, 500).map(url => ({ url }))
    }
  };
  try {
    const res = await fetch(`${SAFE_BROWSING_API}?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) return {};
    const data = await res.json();
    const hits = {};
    for (const match of data.matches || []) {
      hits[match.threat.url] = match.threatType;
    }
    return hits;
  } catch {
    return {};
  }
}

// ---------- orchestration ----------

async function scanInbox(maxResults) {
  const token = await getAuthToken(true);
  const { apiKey, customBrands } = await chrome.storage.sync.get(["apiKey", "customBrands"]);
  const brands = Object.assign({}, BUILTIN_BRANDS, customBrands || {});

  const list = await gmailFetch(`/messages?maxResults=${maxResults}&labelIds=INBOX`, token);
  const ids = (list.messages || []).map(m => m.id);

  const results = [];
  for (const id of ids) {
    const msg = await gmailFetch(`/messages/${id}?format=full`, token);
    const parsed = parseGmailMessage(msg);
    const verdict = analyzeEmail(parsed, brands, FREE_PROVIDERS, URL_SHORTENERS, RISKY_TLDS);

    // async Safe Browsing check merged in
    const sbHits = await checkSafeBrowsing(parsed.urls, apiKey);
    let sbScoreAdd = 0;
    const sbReasons = [];
    for (const url in sbHits) {
      sbScoreAdd = 100; // hard override per spec section 7
      sbReasons.push(`Link ${url} is on Google Safe Browsing's known-threat list (${sbHits[url]}).`);
    }
    const finalScore = sbScoreAdd ? 100 : verdict.score;
    const finalReasons = sbReasons.concat(verdict.reasons).slice(0, 5);
    const finalCategory = sbScoreAdd ? "High-Risk Phishing / Malware Delivery" : verdict.category;

    results.push({
      id: parsed.id,
      subject: parsed.subject,
      from: parsed.headers.from,
      score: finalScore,
      category: finalCategory,
      reasons: finalReasons
    });
  }

  results.sort((a, b) => b.score - a.score);
  return results;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_INBOX") {
    scanInbox(msg.maxResults || 15)
      .then(results => sendResponse({ ok: true, results }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true; // keep channel open for async response
  }
});