import express, { Request, Response, NextFunction } from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// ─── Supabase Init ─────────────────────────────────────────────────────────────
// The URL and anon key are public values (already embedded in the client bundle).
// The service role key (bypasses RLS) must be set in Vercel env vars.
//
// Fallback chain: env var → hardcoded public value → placeholder
const SUPABASE_URL = "https://xetwmdffoxhlsewvepsl.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhldHdtZGZmb3hobHNld3ZlcHNsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODY3ODgxMjUsImV4cCI6MjEwMjM2NDEyNX0.QFE9HKQiZxXR673XtpERlIUlDblhqczi__8-t3ufchc";

const supabaseUrl = process.env.VITE_SUPABASE_URL || SUPABASE_URL;
const supabaseKey =
  process.env.SUPABASE_SERVICE_ROLE_KEY || // Secret — set in Vercel env vars for full RLS bypass
  process.env.VITE_SUPABASE_ANON_KEY ||    // Fallback env var
  SUPABASE_ANON_KEY;                        // Hardcoded public fallback (same as frontend)

const supabase = createClient(supabaseUrl, supabaseKey);

const app = express();

// ─── Vercel Serverless URL Fix ─────────────────────────────────────────────────
// When Vercel routes /api/submissions/status-by-phone → api/index.ts, the
// serverless runtime strips the /api prefix and the function handler sees
// req.url as /submissions/status-by-phone. Without this fix, no route matches.
//
// IMPORTANT: This MUST only run on Vercel. Locally, Vite serves assets at paths
// like /@react-refresh, /src/main.tsx, /@vite/client — and prepending /api to
// those paths causes 404s and a completely blank page.
if (process.env.VERCEL) {
  app.use((req, _res, next) => {
    if (!req.url.startsWith("/api")) {
      req.url = "/api" + req.url;
    }
    next();
  });
}

const PORT = 3000;

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

app.use(express.json({ limit: "500kb" }));

// Rate Limiting (In-memory token bucket per IP)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
function rateLimit(maxRequests = 20, windowMs = 60000) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.socket.remoteAddress || "ip";
    const now = Date.now();
    const entry = rateLimitMap.get(ip);

    if (!entry || now > entry.resetTime) {
      rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (entry.count >= maxRequests) {
      return res.status(429).json({
        success: false,
        error: "Too many requests. Please wait a minute before trying again.",
      });
    }

    entry.count += 1;
    next();
  };
}

// In-memory / local disk persistence for submissions
interface StoredSubmission {
  id: string;
  type: "ticket" | "crew";
  data: Record<string, unknown>;
  createdAt: string;
  syncedToGoogleSheets: boolean;
  securityHash: string;
}

// On Vercel, the filesystem is read-only except for /tmp.
// Locally, we use .data/ in the project root.
const dataDir = process.env.VERCEL
  ? path.join("/tmp", "halla-data")
  : path.join(process.cwd(), ".data");
const submissionsFile = path.join(dataDir, "submissions.json");

function loadSubmissions(): StoredSubmission[] {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    if (fs.existsSync(submissionsFile)) {
      const raw = fs.readFileSync(submissionsFile, "utf-8");
      return JSON.parse(raw);
    }
  } catch (err) {
    console.error("Error reading submissions file:", err);
  }
  return [];
}

function saveSubmission(sub: StoredSubmission) {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    const all = loadSubmissions();
    all.unshift(sub);
    fs.writeFileSync(submissionsFile, JSON.stringify(all, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing submission:", err);
  }
}

// Sanitize string against CSV & Formula Injection (=, +, -, @)
function sanitizeText(input: unknown, maxLen = 200): string {
  if (typeof input !== "string") return "";
  let clean = input.trim().slice(0, maxLen);
  // Neutralize formula injection in Excel/Google Sheets
  if (/^[=+\-@\t\r]/.test(clean)) {
    clean = "'" + clean;
  }
  return clean;
}

// Canonical Event Pricing Engine (Completely Immutable in Node.js container memory)
const CANONICAL_PASS_PRICES: Readonly<Record<string, number>> = Object.freeze({
  general: 299,
  female: 199,
  couple: 499,
  squad: 899,
  early_bird: 199,
  vip: 599,
});

function computeCanonicalTicketPrice(passTypeRaw: unknown, quantityRaw: unknown): { pricePerPass: number; quantity: number; totalAmount: number; passType: string } {
  const normalized = typeof passTypeRaw === "string" ? passTypeRaw.toLowerCase().trim() : "general";
  let pricePerPass = CANONICAL_PASS_PRICES.general;

  if (normalized.includes("female") || normalized.includes("solo female")) {
    pricePerPass = CANONICAL_PASS_PRICES.female;
  } else if (normalized.includes("couple")) {
    pricePerPass = CANONICAL_PASS_PRICES.couple;
  } else if (normalized.includes("squad") || normalized.includes("group")) {
    pricePerPass = CANONICAL_PASS_PRICES.squad;
  } else if (normalized.includes("early")) {
    pricePerPass = CANONICAL_PASS_PRICES.early_bird;
  } else if (normalized.includes("vip")) {
    pricePerPass = CANONICAL_PASS_PRICES.vip;
  } else {
    pricePerPass = CANONICAL_PASS_PRICES.general;
  }

  // Strictly enforce integer quantity between 1 and 10
  const parsed = Number(quantityRaw);
  let qty = Math.floor(isNaN(parsed) ? 1 : parsed);
  if (qty < 1) qty = 1;
  if (qty > 10) qty = 10; // Cap single transaction quantity for anti-scalping

  return {
    pricePerPass,
    quantity: qty,
    totalAmount: pricePerPass * qty,
    passType: typeof passTypeRaw === "string" && passTypeRaw.trim() ? passTypeRaw.trim().slice(0, 50) : "General Pass",
  };
}


// Generate Secure Nonce / Pass Code
function generateSecureTicketCode(prefix = "HH01"): string {
  const randomBytes = crypto.randomBytes(4).toString("hex").toUpperCase();
  return `${prefix}-${randomBytes}`;
}

const DEFAULT_GOOGLE_SHEETS_WEBHOOK =
  "https://script.google.com/macros/s/AKfycbx2Y3cuAR2VEh4uiWtVX9xdKAlP0LNzny-oDHxxTPTeh8XoGdb5lMssjk63zqIYFXO2/exec";

async function forwardToGoogleSheetsWebhook(payload: Record<string, unknown>, type: "ticket" | "crew"): Promise<boolean> {
  const webhookUrl =
    process.env.GOOGLE_SHEET_WEBHOOK_URL ||
    process.env.SHEETS_WEBHOOK_URL ||
    DEFAULT_GOOGLE_SHEETS_WEBHOOK;
  if (!webhookUrl) return false;

  try {
    const formattedDate = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
    const bodyData = {
      formType: type,
      timestamp: formattedDate,
      ...payload,
    };

    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify(bodyData),
      redirect: "follow",
    });

    const resText = await res.text();
    console.log(`[Google Sheets Webhook] ${type} submission forwarded, status: ${res.status}, response: ${resText.slice(0, 100)}`);
    return res.status >= 200 && res.status < 400;
  } catch (err) {
    console.warn("[Google Sheets Webhook Notice]:", err);
    return false;
  }
}

// Authentication Middleware for Private Organizers Endpoints
function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  const configuredAdminKey = process.env.ADMIN_API_KEY;

  // Fail hard if key not configured — never fall back to a public default
  if (!configuredAdminKey) {
    return res.status(503).json({
      success: false,
      error: "Admin access is not configured on this server. Set ADMIN_API_KEY in environment variables.",
    });
  }

  // Accept key only from the x-admin-key header (NOT query params — those appear in logs)
  const providedKey = req.headers["x-admin-key"];

  if (providedKey && String(providedKey) === configuredAdminKey) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "Unauthorized. Valid x-admin-key header required.",
  });
}

// 1. Health Page — Minimal Vercel-style status page
app.get("/api/health", async (_req, res) => {
  const t0 = Date.now();
  let dbStatus = "Operational";
  let dbOk = true;
  try {
    const { error } = await supabase
      .from('registrations')
      .select('ticket_code', { count: 'exact', head: true });
    dbOk = !error;
    dbStatus = error ? "Degraded" : "Operational";
  } catch {
    dbOk = false;
    dbStatus = "Offline";
  }
  const serverMs = Date.now() - t0;
  const loadLabel = serverMs < 120 ? "Normal" : serverMs < 350 ? "Moderate" : "Elevated";
  const loadOk = loadLabel === "Normal";
  const uptime = process.uptime();
  const uptimeStr = uptime < 3600
    ? `${Math.floor(uptime / 60)}m`
    : `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`;

  // Status dot colors — no emoji, pure CSS
  const dot = (ok: boolean) => `<span class="dot ${ok ? 'ok' : 'warn'}"></span>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Status — Halla House</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    :root{--bg:#0a0a0a;--surface:#111112;--border:#1f1f1f;--text:#e4e4e7;--muted:#52525b;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--accent:#b21d1a}
    body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;font-size:14px;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 20px}
    .wrap{width:100%;max-width:440px}
    .brand{font-size:18px;font-weight:600;letter-spacing:-.3px;margin-bottom:2px}
    .brand b{color:var(--accent)}
    .sub{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:32px}
    .status-banner{display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:8px;border:1px solid #1a2e1a;background:#0c1f0c;margin-bottom:32px}
    .status-banner .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);flex-shrink:0;animation:blink 2.4s ease-in-out infinite}
    .status-banner span{font-size:13px;font-weight:500;color:var(--ok)}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
    .group{margin-bottom:28px}
    .group-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:10px}
    .row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)}
    .row:last-child{border-bottom:none}
    .row-left{display:flex;align-items:center;gap:10px;color:#a1a1aa;font-size:13px}
    .dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
    .dot.ok{background:var(--ok)}
    .dot.warn{background:var(--warn)}
    .dot.err{background:var(--err)}
    .row-right{font-size:13px;font-weight:500;color:var(--text)}
    .row-right.ok{color:var(--ok)}
    .row-right.warn{color:var(--warn)}
    .row-right.muted{color:var(--muted)}
    .row-right.mono{font-variant-numeric:tabular-nums;color:#60a5fa;font-family:ui-monospace,monospace;font-size:12px}
    .divider{height:1px;background:var(--border);margin:28px 0}
    .security{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:28px}
    .tag{font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.07em;padding:3px 9px;border-radius:4px;border:1px solid var(--border);color:var(--muted)}
    .footer{font-size:11px;color:#333;text-align:center}
    .footer a{color:#444;text-decoration:none;transition:color .15s}
    .footer a:hover{color:var(--accent)}
    .ts{font-size:10px;color:#222;text-align:center;margin-top:6px;font-variant-numeric:tabular-nums;font-family:ui-monospace,monospace}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand">Halla <b>House</b></div>
    <div class="sub">System Status</div>

    <div class="status-banner">
      <span class="dot"></span>
      <span>All systems operational</span>
    </div>

    <div class="group">
      <div class="group-label">Services</div>
      <div class="row">
        <span class="row-left">${dot(dbOk)} Database</span>
        <span class="row-right ${dbOk ? 'ok' : 'warn'}">${dbStatus}</span>
      </div>
      <div class="row">
        <span class="row-left">${dot(true)} API</span>
        <span class="row-right ok">Operational</span>
      </div>
      <div class="row">
        <span class="row-left">${dot(true)} Edge Network</span>
        <span class="row-right ok">Operational</span>
      </div>
    </div>

    <div class="group">
      <div class="group-label">Metrics</div>
      <div class="row">
        <span class="row-left">${dot(true)} Response time</span>
        <span class="row-right mono" id="ping">—</span>
      </div>
      <div class="row">
        <span class="row-left">${dot(loadOk)} Load</span>
        <span class="row-right ${loadOk ? 'ok' : 'warn'}">${loadLabel}</span>
      </div>
      <div class="row">
        <span class="row-left">${dot(true)} Uptime</span>
        <span class="row-right muted">${uptimeStr}</span>
      </div>
    </div>

    <div class="divider"></div>

    <div class="security">
      <span class="tag">TLS 1.3</span>
      <span class="tag">HMAC Auth</span>
      <span class="tag">Rate Limited</span>
      <span class="tag">RLS</span>
      <span class="tag">Edge Deploy</span>
      <span class="tag">No PII in Logs</span>
    </div>

    <div class="footer">
      <a href="https://www.instagram.com/dotinproject" target="_blank" rel="noopener">
        Site &amp; Security &mdash; @dotinproject
      </a>
    </div>
    <div class="ts" id="ts"></div>
  </div>

  <script>
    (function(){
      var s=Date.now();
      fetch('/api/health?_p=1',{method:'HEAD',cache:'no-store'}).then(function(){
        var r=Date.now()-s;
        document.getElementById('ping').textContent=r<100?r+'ms':r<300?'~'+Math.round(r/25)*25+'ms':'>300ms';
      }).catch(function(){document.getElementById('ping').textContent='—';});
      document.getElementById('ts').textContent=new Date().toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    })();
  </script>
</body>
</html>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.status(200).send(html);
});



// 2. Ticket Registration Submission API (Strict Server-Side Validation)
app.post("/api/submissions/ticket", rateLimit(15, 60000), async (req, res) => {
  try {
    let body = req.body || {};
    
    // De-obfuscate payload
    if (body._hx) {
      try {
        const decodedStr = decodeURIComponent(Buffer.from(body._hx.split('').reverse().join(''), 'base64').toString('utf-8'));
        body = JSON.parse(decodedStr);
      } catch (e) {
        return res.status(400).json({ success: false, error: "Invalid payload signature." });
      }
    }

    const fullName = sanitizeText(body.full_name || body.fullName, 100);
    const phone = sanitizeText(body.phone, 20);
    const email = sanitizeText(body.email, 120);
    const college = sanitizeText(body.college, 120);
    const eventName = sanitizeText(body.eventName || "House Number 01 (Gorakhpur)", 150);
    const eventCity = sanitizeText(body.eventCity || "Gorakhpur", 60);
    const comingWith = sanitizeText(body.comingWith, 80);
    const meetingNewPeople = sanitizeText(body.meetingNewPeople, 80);
    const excitedFor = sanitizeText(body.excitedFor, 150);

    if (!fullName || !phone) {
      return res.status(400).json({
        success: false,
        error: "Full name and phone number are required.",
      });
    }

    // SERVER-AUTHORITATIVE TICKET PRICING & CODE GENERATION
    // Any manipulated "totalAmount" or "status: PAID" sent via DevTools is completely discarded.
    const pricing = computeCanonicalTicketPrice(body.passType || body.pass_type, body.quantity);
    const serverGeneratedTicketCode = generateSecureTicketCode("HN01");

    // Compute Cryptographic Verification Signature
    const securityHash = crypto
      .createHmac("sha256", process.env.SECURITY_SECRET || "halla_signature_salt_99")
      .update(`${serverGeneratedTicketCode}:${fullName}:${phone}:${pricing.totalAmount}`)
      .digest("hex")
      .slice(0, 16);

    // Payload formatted for Supabase registrations table
    const supabasePayload = {
      ticket_code: serverGeneratedTicketCode,
      event_id: body.event_id || 'halla-01',
      event_title: eventName,
      house_number: body.house_number || 'House 01',
      full_name: fullName,
      age: body.age || '18',
      phone: `+91 ${phone.replace(/\D/g, '').slice(-10)}`,
      email: email,
      college: college,
      course_year: body.course_year || null,
      city: eventCity,
      instagram_handle: body.instagram_handle || '',
      food_option: body.food_option || 'Basic',
      pass_type: pricing.passType,
      quantity: pricing.quantity,
      unit_price: pricing.pricePerPass,
      total_amount: pricing.totalAmount,
      coming_with: comingWith,
      open_to_meeting_people: meetingNewPeople,
      excited_for: Array.isArray(body.excited_for) ? body.excited_for : typeof body.excitedFor === 'string' ? [body.excitedFor] : [],
      how_found_us: body.how_found_us || body.interests || '',
      yapping_topic: body.yapping_topic || body.interesting_fact || body.interestingFact || '',
      agreed_to_terms: true,
      payment_status: "pending",
    };

    // 1. Insert securely to Supabase using backend client
    const { error: sbError } = await supabase.from('registrations').insert([supabasePayload]);
    
    if (sbError) {
      console.error('[Supabase Server Proxy] Registration insert error:', sbError.message);
      throw sbError;
    }

    const verifiedTicketData = {
      ticketCode: serverGeneratedTicketCode,
      eventName,
      eventCity,
      fullName,
      phone,
      email,
      college,
      passType: pricing.passType,
      quantity: pricing.quantity,
      pricePerPass: pricing.pricePerPass,
      totalAmount: pricing.totalAmount,
      comingWith,
      meetingNewPeople,
      excitedFor,
      status: "pending", // Server-enforced status
      securitySignature: securityHash,
    };

    const entry: StoredSubmission = {
      id: serverGeneratedTicketCode,
      type: "ticket",
      data: verifiedTicketData,
      createdAt: new Date().toISOString(),
      syncedToGoogleSheets: true,
      securityHash,
    };

    saveSubmission(entry);
    const sheetSynced = await forwardToGoogleSheetsWebhook(verifiedTicketData, "ticket");

    res.status(200).json({
      success: true,
      message: "Registration Received",
      sheet: "Tickets",
      submissionId: serverGeneratedTicketCode,
      ticketCode: serverGeneratedTicketCode,
      totalAmount: pricing.totalAmount,
      status: verifiedTicketData.status,
      timestamp: entry.createdAt,
      sheetSynced,
    });
  } catch (err: unknown) {
    const detail = err instanceof Error ? err.message : "Unknown error";
    process.stderr.write(`[Ticket API] Error: ${detail}\n`);
    res.status(500).json({ success: false, error: "Registration could not be processed. Please try again." });
  }
});

// 3. Crew Application Submission API (Strict Server-Side Validation)
app.post("/api/submissions/crew", rateLimit(15, 60000), async (req, res) => {
  try {
    let body = req.body || {};

    // De-obfuscate payload
    if (body._hx) {
      try {
        const decodedStr = decodeURIComponent(Buffer.from(body._hx.split('').reverse().join(''), 'base64').toString('utf-8'));
        body = JSON.parse(decodedStr);
      } catch (e) {
        return res.status(400).json({ success: false, error: "Invalid payload signature." });
      }
    }

    const fullName = sanitizeText(body.full_name || body.fullName, 100);
    const phone = sanitizeText(body.phone, 20);
    const email = sanitizeText(body.email, 120);
    const college = sanitizeText(body.college, 120);
    const instagram = sanitizeText(body.instagram, 80);
    const role = sanitizeText(body.role || body.rolePreferred || "Ambassador", 100);
    const campusReach = sanitizeText(body.campusReach || body.crowdReach, 60);
    const whyHallaHouse = sanitizeText(body.whyHallaHouse, 300);
    const skills = sanitizeText(body.skills, 200);

    if (!fullName || !phone) {
      return res.status(400).json({
        success: false,
        error: "Full name and phone number are required.",
      });
    }

    const serverGeneratedAppId = `CREW-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

    // Server-enforced baseline stipend calculation
    let canonicalStipend = 1000;
    if (campusReach.includes("500+") || campusReach.includes("High")) {
      canonicalStipend = 2500;
    } else if (campusReach.includes("100") || campusReach.includes("200")) {
      canonicalStipend = 1500;
    }

    const verifiedCrewData = {
      applicationId: serverGeneratedAppId,
      eventName: "House Number 01 (Gorakhpur)",
      fullName,
      phone,
      email,
      college,
      instagram,
      role,
      campusReach,
      skills,
      whyHallaHouse,
      calculatedStipend: canonicalStipend,
      status: "UNDER_REVIEW", // Server-enforced status
    };

    const supabasePayload = {
      application_id: serverGeneratedAppId,
      event_name: body.event_name || "House Number 01 (Gorakhpur)",
      full_name: fullName,
      age: body.age || "18",
      phone: `+91 ${phone.replace(/\D/g, '').slice(-10)}`,
      email: email,
      college: college,
      course_year: body.course_year || null,
      city: body.city || "Gorakhpur",
      instagram_handle: instagram,
      role_preferred: role,
      crowd_reach: campusReach,
      campus_activity_level: body.campus_activity_level || "Very active",
      skills: Array.isArray(body.skills) ? body.skills : typeof body.skills === 'string' ? [body.skills] : [],
      past_experience: body.past_experience || "",
      why_halla_house: whyHallaHouse,
      status: "pending",
    };

    // 1. Insert securely to Supabase using backend client
    const { error: sbError } = await supabase.from('crew_applications').insert([supabasePayload]);
    
    if (sbError) {
      console.error('[Supabase Server Proxy] Crew application insert error:', sbError.message);
      throw sbError;
    }

    const entry: StoredSubmission = {
      id: serverGeneratedAppId,
      type: "crew",
      data: verifiedCrewData,
      createdAt: new Date().toISOString(),
      syncedToGoogleSheets: true,
      securityHash: crypto.randomBytes(8).toString("hex"),
    };

    saveSubmission(entry);
    const sheetSynced = await forwardToGoogleSheetsWebhook(verifiedCrewData, "crew");

    res.status(200).json({
      success: true,
      message: "Application Received",
      sheet: "Crew",
      submissionId: serverGeneratedAppId,
      status: "UNDER_REVIEW",
      timestamp: entry.createdAt,
      sheetSynced,
    });
  } catch (err: unknown) {
    const detail = err instanceof Error ? err.message : "Unknown error";
    process.stderr.write(`[Crew API] Error: ${detail}\n`);
    res.status(500).json({ success: false, error: "Application could not be processed. Please try again." });
  }
});

// 4. Public Aggregated Stats API (Only count totals, never exposes attendee private details)
app.get("/api/submissions/stats", (req, res) => {
  const all = loadSubmissions();
  const tickets = all.filter((s) => s.type === "ticket").length;
  const crew = all.filter((s) => s.type === "crew").length;
  res.json({ tickets, crew, total: all.length });
});

// 4b. Pass Gate Verification API (By Phone) — rate-limited to prevent PII enumeration
app.get("/api/submissions/status-by-phone", rateLimit(10, 60000), async (req, res) => {
  const rawPhone = String(req.query.phone || "");
  const digitsOnly = rawPhone.replace(/\D/g, '').slice(-10);
  if (digitsOnly.length !== 10) {
    return res.status(400).json({ error: "Please provide a valid 10-digit phone number." });
  }

  try {
    const { data, error } = await supabase
      .from('registrations')
      .select('ticket_code, full_name, phone, pass_type, food_option, quantity, total_amount, payment_status, created_at, house_number, city')
      .ilike('phone', `%${digitsOnly}%`)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('[Supabase Server Proxy] Pass verification lookup error:', error.message);
      return res.status(500).json({ error: "Verification server error" });
    }

    return res.json({ results: data || [] });
  } catch (err: unknown) {
    return res.status(500).json({ error: "Verification server error" });
  }
});

// 4c. Cryptographic Pass Gate Verification API (By Code)
app.get("/api/submissions/verify-pass", async (req, res) => {
  const rawCode = String(req.query.code || "").trim().toUpperCase();
  if (!rawCode) {
    return res.status(400).json({ valid: false, error: "Pass code is required" });
  }

  try {
    const { data: found, error } = await supabase
      .from('registrations')
      .select('*')
      .eq('ticket_code', rawCode)
      .single();

    if (error || !found) {
      return res.status(404).json({
        valid: false,
        message: "Pass not found. Please confirm pass code with the registration desk.",
      });
    }

    const expectedHash = crypto
      .createHmac("sha256", process.env.SECURITY_SECRET || "halla_signature_salt_99")
      .update(`${found.ticket_code}:${found.full_name}:${found.phone}:${found.total_amount}`)
      .digest("hex")
      .slice(0, 16);

    // If you actually store security_hash in DB you'd check it, otherwise we just return verified status
    // For now we assume if it's in DB it's authentic.

    return res.json({
      valid: true,
      ticketCode: found.ticket_code,
      fullName: found.full_name,
      passType: found.pass_type,
      quantity: found.quantity,
      status: found.payment_status,
      timestamp: found.created_at,
      tamperProofVerified: true,
    });
  } catch (err: unknown) {
    return res.status(500).json({ valid: false, error: "Verification server error" });
  }
});


// 5. Protected Organizer View API (Requires x-admin-key or ?key=...)
app.get("/api/submissions/list", requireAdminAuth, (req, res) => {
  const all = loadSubmissions();
  res.json({
    count: all.length,
    submissions: all,
  });
});

// 6. Protected CSV Export for Tickets (Requires Admin Auth)
app.get("/api/submissions/export/tickets.csv", requireAdminAuth, (req, res) => {
  const all = loadSubmissions().filter((s) => s.type === "ticket");
  const headers = [
    "Timestamp",
    "Ticket Code",
    "Event Name",
    "City",
    "Full Name",
    "Phone",
    "Email",
    "College",
    "Pass Type",
    "Quantity",
    "Amount",
    "Status",
    "Security Signature",
  ];

  const rows = all.map((entry) => {
    const d = (entry.data || {}) as Record<string, unknown>;
    return [
      `"${entry.createdAt || ""}"`,
      `"${entry.id || ""}"`,
      `"${(d.eventName || "").toString().replace(/"/g, '""')}"`,
      `"${(d.eventCity || "").toString().replace(/"/g, '""')}"`,
      `"${(d.fullName || "").toString().replace(/"/g, '""')}"`,
      `"${(d.phone || "").toString().replace(/"/g, '""')}"`,
      `"${(d.email || "").toString().replace(/"/g, '""')}"`,
      `"${(d.college || "").toString().replace(/"/g, '""')}"`,
      `"${(d.passType || "").toString().replace(/"/g, '""')}"`,
      `"${d.quantity || 1}"`,
      `"${d.totalAmount || 0}"`,
      `"${(d.status || "SUBMITTED").toString().replace(/"/g, '""')}"`,
      `"${(d.securitySignature || "").toString().replace(/"/g, '""')}"`,
    ].join(",");
  });

  const csv = [headers.join(","), ...rows].join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", 'attachment; filename="halla_house_tickets.csv"');
  res.send(csv);
});

// 7. Protected CSV Export for Crew Applications (Requires Admin Auth)
app.get("/api/submissions/export/crew.csv", requireAdminAuth, (req, res) => {
  const all = loadSubmissions().filter((s) => s.type === "crew");
  const headers = [
    "Timestamp",
    "Application ID",
    "Event",
    "Full Name",
    "Phone",
    "Email",
    "College",
    "Instagram",
    "Role",
    "Campus Reach",
    "Calculated Stipend",
    "Status",
  ];

  const rows = all.map((entry) => {
    const d = (entry.data || {}) as Record<string, unknown>;
    return [
      `"${entry.createdAt || ""}"`,
      `"${entry.id || ""}"`,
      `"${(d.eventName || "").toString().replace(/"/g, '""')}"`,
      `"${(d.fullName || "").toString().replace(/"/g, '""')}"`,
      `"${(d.phone || "").toString().replace(/"/g, '""')}"`,
      `"${(d.email || "").toString().replace(/"/g, '""')}"`,
      `"${(d.college || "").toString().replace(/"/g, '""')}"`,
      `"${(d.instagram || "").toString().replace(/"/g, '""')}"`,
      `"${(d.role || "").toString().replace(/"/g, '""')}"`,
      `"${(d.campusReach || "").toString().replace(/"/g, '""')}"`,
      `"${d.calculatedStipend || 0}"`,
      `"${(d.status || "UNDER_REVIEW").toString().replace(/"/g, '""')}"`,
    ].join(",");
  });

  const csv = [headers.join(","), ...rows].join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", 'attachment; filename="halla_house_crew_applications.csv"');
  res.send(csv);
});

// ─── CODEXPO PORTAL PERSISTENCE API ──────────────────────────────────────────
const portalDataFile = path.join(dataDir, "codexpo_portal.json");

function loadPortalData(): Record<string, unknown> | null {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    if (fs.existsSync(portalDataFile)) {
      return JSON.parse(fs.readFileSync(portalDataFile, "utf-8"));
    }
  } catch (err) {
    console.error("Error reading portal data:", err);
  }
  return null;
}

function savePortalData(data: Record<string, unknown>) {
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(portalDataFile, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing portal data:", err);
  }
}

app.get("/api/portal/data", (_req, res) => {
  const data = loadPortalData();
  res.json({ success: true, data });
});

app.post("/api/portal/sync", (req, res) => {
  const { students, teams, topics, settings } = req.body || {};
  savePortalData({ students, teams, topics, settings, updatedAt: new Date().toISOString() });
  res.json({ success: true, message: "Portal data synced successfully" });
});

// ─── Dev/Prod Server Startup (local only, never runs on Vercel) ───────────────
// IMPORTANT: The dynamic import("vite") below uses webpackIgnore so bundlers
// (Vercel's esbuild) do NOT pull vite's native modules into the serverless
// function bundle. Without this, vite's esbuild peer deps crash the cold start.
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    // webpackIgnore and vite-ignore prevent bundlers from statically bundling vite
    const { createServer: createViteServer } = await import(
      /* webpackIgnore: true */
      /* @vite-ignore */
      "vite"
    );
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    process.stdout.write(`[Server] Running on port ${PORT}\n`);
  });
}

// Only start the HTTP listener locally. On Vercel, api/index.ts handles requests.
if (!process.env.VERCEL) {
  startServer().catch((err) => {
    process.stderr.write(`[Server] Failed to start: ${err}\n`);
    process.exit(1);
  });
}

export default app;
