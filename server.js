// dist/server.js - Roma Cafe Loyalty System (Production Server)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Security and Parsers
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Customer self-registration portal (/zbon)
app.get('/zbon', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/zbon.html'));
});

// Admin & Cashier portal (/admin)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});

// Default root redirects to admin dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});

// QR verification route
app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/verify.html'));
});

// Favicon handler to prevent 404 errors and hanging browser tabs
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Core Configuration & Credentials
const ISSUER_ID = process.env.GOOGLE_ISSUER_ID || "3388000000023239265";
const DRINKS_CLASS_ID = process.env.GOOGLE_CLASS_ID || `${ISSUER_ID}.ROMA`;
const BAKERY_CLASS_ID = `${ISSUER_ID}.ROMA_BAKERY`;
const SCOPE = "https://www.googleapis.com/auth/wallet_object.issuer";

// Admin Security PIN (Configurable via ADMIN_PIN in .env, default: 1234)
const ADMIN_PIN = process.env.ADMIN_PIN || "1234";

// Security Middleware: Protects sensitive Admin endpoints against unauthorized tampering
function requireAdminAuth(req, res, next) {
  if (!ADMIN_PIN || ADMIN_PIN === "OFF") return next();

  const authHeader = req.headers['authorization'];
  const pinHeader = req.headers['x-admin-pin'];

  if (pinHeader && pinHeader.toString().trim() === ADMIN_PIN.toString().trim()) {
    return next();
  }
  if (authHeader && authHeader.startsWith('Bearer roma_admin_')) {
    return next();
  }
  if (req.query && req.query.admin_pin && req.query.admin_pin.toString() === ADMIN_PIN.toString().trim()) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "غير مصرح. يرجى إدخال رمز المرور (PIN) للأدمن والكاشير.",
    require_login: true
  });
}

// Initialize Supabase Client with Built-in Fallback
const DEFAULT_SUPABASE_URL = "https://iulapfbjwckfcdhghszf.supabase.co";
const DEFAULT_SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Iml1bGFwZmJqd2NrZmNkaGdoc3pmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQxNTkzMDMsImV4cCI6MjEwOTczNTMwM30.lx5awUV1CXH61ViE8AqVG0Xcs-qkEllBBnwaDfgtMTg";

const rawUrl = process.env.SUPABASE_URL || DEFAULT_SUPABASE_URL;
const rawKey = process.env.SUPABASE_ANON_KEY || DEFAULT_SUPABASE_KEY;

const SUPABASE_URL = rawUrl.trim().replace(/^["']|["']$/g, '');
const SUPABASE_ANON_KEY = (rawKey === 'placeholder' || !rawKey.trim()) ? DEFAULT_SUPABASE_KEY : rawKey.trim().replace(/^["']|["']$/g, '');
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

console.log(`🔗 Supabase Client Connected to: ${SUPABASE_URL}`);

// Dynamic Program Settings Store
const SETTINGS_FILE = path.join(__dirname, 'data/settings.json');
function loadSettings() {
  const defaults = {
    drinksMaxStamps: 6,
    bakeryMaxStamps: 5,
    cafeLatitude: 32.2211,
    cafeLongitude: 35.2544,
    cafeAddress: "Roma Cafe, Main Street",
    geofenceActive: true
  };
  try {
    if (!fs.existsSync(path.dirname(SETTINGS_FILE))) {
      fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
    }
    if (fs.existsSync(SETTINGS_FILE)) {
      return { ...defaults, ...JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) };
    }
  } catch (e) {
    console.error("Error reading settings file:", e);
  }
  return defaults;
}

function saveSettings(settings) {
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
  } catch (e) {
    console.error("Error saving settings file:", e);
  }
}

// Read Service Account credentials safely (file or ENV variable)
function getServiceAccount() {
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    try {
      const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON.trim();
      const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (parsed.private_key) {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      return parsed;
    } catch (e) {
      console.error("Error parsing GOOGLE_SERVICE_ACCOUNT_JSON from env:", e);
    }
  }

  const saPaths = [
    path.join(__dirname, 'service_account.json'),
    path.join(__dirname, '../service_account.json'),
    path.join(__dirname, 'gen-lang-client-0170929101-ae1e1ddb6f9d.json'),
    path.join(__dirname, '../gen-lang-client-0170929101-ae1e1ddb6f9d.json')
  ];

  for (const p of saPaths) {
    if (fs.existsSync(p)) {
      try {
        return JSON.parse(fs.readFileSync(p, 'utf8'));
      } catch (e) {}
    }
  }

  throw new Error("ملف service_account.json غير موجود. يرجى وضعه في مجلد المشروع أو تعيين متغير البيئة GOOGLE_SERVICE_ACCOUNT_JSON.");
}

function createJwt(header, payload, privateKey) {
  const encHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(encHeader + '.' + encPayload);
  const signature = sign.sign(privateKey, 'base64url');
  return encHeader + '.' + encPayload + '.' + signature;
}

let cachedOAuthToken = null;
let cachedTokenExpiry = 0;

// Get Google OAuth token (Cached with TTL for instant 0ms responses)
async function getGoogleOAuthToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedOAuthToken && cachedTokenExpiry > now + 60) {
    return cachedOAuthToken;
  }

  const sa = getServiceAccount();
  const jwt = createJwt(
    { alg: 'RS256', typ: 'JWT' },
    {
      iss: sa.client_email,
      scope: SCOPE,
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now
    },
    sa.private_key
  );

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    })
  });

  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error(`فشل استخراج OAuth Token: ${JSON.stringify(data)}`);
  }

  cachedOAuthToken = data.access_token;
  cachedTokenExpiry = now + (data.expires_in || 3600);
  return cachedOAuthToken;
}

/**
 * Builds Visual Text Gauge for Stamps (e.g. ☕ ☕ ⚪ ⚪ ⚪ ⚪  33%)
 */
function buildVisualStampGauge(current, max, iconFilled, iconEmpty = '⚪') {
  const clamped = Math.min(max, Math.max(0, current));
  const filled = iconFilled.repeat(clamped);
  const empty = iconEmpty.repeat(Math.max(0, max - clamped));
  const percent = Math.round((clamped / max) * 100);
  return `${filled} ${empty}  (${clamped} / ${max}) [${percent}%]`;
}

/**
 * Builds Loyalty Object structure for Drinks or Bakery
 */
function buildLoyaltyObject(params) {
  const settings = loadSettings();
  const customerId = params.customerId;
  const programType = params.programType || 'DRINKS';
  
  const isBakery = (programType === 'BAKERY');
  const maxStamps = isBakery ? settings.bakeryMaxStamps : settings.drinksMaxStamps;
  const stampsCount = Math.min(maxStamps, Math.max(0, Number(params.stampsCount) || 0));
  
  const classId = isBakery ? BAKERY_CLASS_ID : DRINKS_CLASS_ID;
  const loyaltyObjectId = `${ISSUER_ID}.CUSTOMER_${programType}_${customerId}`;
  const verifyUrl = `https://roma-cafe.com/verify?cid=${customerId}&type=${programType}`;

  const icon = isBakery ? '🥐' : '☕';
  const label = isBakery ? 'أختام المخبوزات والحلويات' : 'أختام القهوة والمشروبات';
  const visualGauge = buildVisualStampGauge(stampsCount, maxStamps, icon);
  const percent = Math.round((stampsCount / maxStamps) * 100);

  const loyaltyObject = {
    id: loyaltyObjectId,
    classId: classId,
    state: "ACTIVE",
    accountId: customerId,
    accountName: params.fullName,
    groupingInfo: {
      groupingId: `ROMA_VIP_${customerId}`,
      sortIndex: isBakery ? 2 : 1
    },
    loyaltyPoints: {
      label: label,
      balance: {
        string: visualGauge
      }
    },
    barcode: {
      type: "QR_CODE",
      value: verifyUrl,
      alternateText: `${customerId} (${programType})`
    },
    textModulesData: [
      {
        header: "مستوى تقدم المكافأة 🎯",
        body: stampsCount >= maxStamps 
          ? `🎉 مبروك! لقد جمعت ${maxStamps} أختام، ${isBakery ? 'المخبوز أو الحلى المجاني' : 'المشروب المجاني'} جاهز للاستلام الآن!`
          : `تبقّى لك ${maxStamps - stampsCount} أختام للحصول على مكافأتك القادمة مجاناً (${percent}% مكتمل)!`
      },
      {
        header: "نوع بطاقة الولاء",
        body: isBakery ? "🥐 برنامج مخبوزات وحلويات Roma Cafe" : "☕ برنامج قهوة ومشروبات Roma Cafe"
      }
    ]
  };

  return {
    loyaltyObject,
    loyaltyObjectId,
    programType,
    maxStamps,
    stampsCount,
    visualGauge
  };
}

/**
 * Generate Google Wallet Save URL for a single pass
 */
function generatePassJwt(params) {
  const sa = getServiceAccount();
  const built = buildLoyaltyObject(params);

  const claims = {
    iss: sa.client_email,
    aud: "google",
    typ: "savetowallet",
    iat: Math.floor(Date.now() / 1000),
    origins: [],
    payload: {
      loyaltyObjects: [built.loyaltyObject]
    }
  };

  const token = createJwt({ alg: 'RS256', typ: 'JWT' }, claims, sa.private_key);
  const saveUrl = `https://pay.google.com/gp/v/save/${token}`;

  return {
    saveUrl,
    jwtToken: token,
    loyaltyObjectId: built.loyaltyObjectId,
    programType: built.programType,
    maxStamps: built.maxStamps,
    stampsCount: built.stampsCount,
    visualGauge: built.visualGauge,
    loyaltyObject: built.loyaltyObject
  };
}

/**
 * Generate Combined Save URL to install BOTH Drinks & Bakery passes together in 1 click
 */
function generateDualPassJwt(drinksParams, bakeryParams) {
  const sa = getServiceAccount();
  const dObj = buildLoyaltyObject(drinksParams).loyaltyObject;
  const bObj = buildLoyaltyObject(bakeryParams).loyaltyObject;

  const claims = {
    iss: sa.client_email,
    aud: "google",
    typ: "savetowallet",
    iat: Math.floor(Date.now() / 1000),
    origins: [],
    payload: {
      loyaltyObjects: [dObj, bObj]
    }
  };

  const token = createJwt({ alg: 'RS256', typ: 'JWT' }, claims, sa.private_key);
  return `https://pay.google.com/gp/v/save/${token}`;
}

// Fast 1-click redirect route for mobile camera QR scans to save both cards in Google Wallet
app.get('/wallet/save/:customerId', async (req, res) => {
  try {
    const { customerId } = req.params;
    const { data: cust } = await supabase.from('customers').select('*').eq('customer_id', customerId).maybeSingle();
    if (!cust) return res.status(404).send("لم يتم العثور على بطاقة الزبون في النظام");

    let meta = {};
    try { if (cust.notes && cust.notes.startsWith('{')) meta = JSON.parse(cust.notes); } catch (e) {}
    const dStamps = cust.drinks_stamps ?? meta.drinks_stamps ?? cust.stamps_count ?? 0;
    const bStamps = cust.bakery_stamps ?? meta.bakery_stamps ?? 0;

    const bothSaveUrl = generateDualPassJwt(
      { customerId: cust.customer_id, fullName: cust.full_name, stampsCount: dStamps, programType: 'DRINKS' },
      { customerId: cust.customer_id, fullName: cust.full_name, stampsCount: bStamps, programType: 'BAKERY' }
    );

    res.redirect(bothSaveUrl);
  } catch (err) {
    res.status(500).send("خطأ أثناء تحويل البطاقة: " + err.message);
  }
});

// Patch Google Wallet Object with Visual Stamp Gauge and Text & Notify
async function patchGoogleWalletPass(customerId, programType, stampsCount, maxStamps, rewardRedeemed = false, customerName = 'زبون مقهى Roma') {
  const loyaltyObjectId = `${ISSUER_ID}.CUSTOMER_${programType}_${customerId}`;
  const clampedStamps = Math.min(maxStamps, Math.max(0, stampsCount));
  const isBakery = (programType === 'BAKERY');
  const icon = isBakery ? '🥐' : '☕';
  const label = isBakery ? 'أختام المخبوزات والحلويات' : 'أختام القهوة والمشروبات';
  const visualGauge = buildVisualStampGauge(clampedStamps, maxStamps, icon);
  const percent = Math.round((clampedStamps / maxStamps) * 100);

  try {
    const accessToken = await getGoogleOAuthToken();
    const endpoint = `https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/${encodeURIComponent(loyaltyObjectId)}`;

    const patchBody = {
      loyaltyPoints: {
        label: label,
        balance: {
          string: visualGauge
        }
      },
      textModulesData: [
        {
          header: "مستوى تقدم المكافأة 🎯",
          body: clampedStamps >= maxStamps
            ? `🎉 مبروك! لقد جمعت ${maxStamps} أختام، ${isBakery ? 'المخبوز المجاني' : 'المشروب المجاني'} جاهز للاستلام الآن!`
            : `رصيدك الحالي: ${clampedStamps} من ${maxStamps} أختام (${percent}%). تبقّى ${maxStamps - clampedStamps} للحصول على المكافأة المجانية!`
        }
      ]
    };

    if (clampedStamps >= maxStamps && !rewardRedeemed) {
      patchBody.messages = [
        {
          id: `reward_ready_${Date.now()}`,
          header: `🎉 مبروك! ${isBakery ? 'المخبوز' : 'المشروب'} المجاني جاهز ☕🥐`,
          body: `لقد أتممت ${maxStamps} أختام بنجاح في مقهى Roma Cafe! أظهر كارتك للكاشير لاستلام مكافأتك.`,
          messageType: "TEXT_AND_NOTIFY",
          displayInterval: { start: { date: new Date().toISOString() } }
        }
      ];
    } else if (rewardRedeemed) {
      patchBody.messages = [
        {
          id: `reward_claimed_${Date.now()}`,
          header: "صحتين وهنا! تم استلام المكافأة المجانية ✨",
          body: "شكراً لزيارتك مقهى Roma Cafe. لقد بدأ عداد الأختام الجديد لجولتك القادمة!",
          messageType: "TEXT_AND_NOTIFY",
          displayInterval: { start: { date: new Date().toISOString() } }
        }
      ];
    } else {
      patchBody.messages = [
        {
          id: `stamp_add_${Date.now()}`,
          header: `Roma Cafe: ختم جديد ${icon}`,
          body: `رصيدك الجديد: ${clampedStamps} من ${maxStamps} أختام ${icon} (${percent}% مكتمل)!`,
          messageType: "TEXT_AND_NOTIFY",
          displayInterval: { start: { date: new Date().toISOString() } }
        }
      ];
    }

    let res = await fetch(endpoint, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(patchBody)
    });

    let resData = await res.json();

    // Auto-create in Google Wallet if pass was not yet pushed
    if (res.status === 404) {
      console.log(`[Google Wallet Auto-Create] Object ${loyaltyObjectId} not found, creating via POST...`);
      const createEndpoint = 'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject';
      const classId = isBakery ? BAKERY_CLASS_ID : DRINKS_CLASS_ID;
      const verifyUrl = `https://roma-cafe.com/verify?cid=${customerId}&type=${programType}`;

      const createBody = {
        id: loyaltyObjectId,
        classId: classId,
        state: "ACTIVE",
        accountId: customerId,
        accountName: customerName,
        loyaltyPoints: patchBody.loyaltyPoints,
        barcode: {
          type: "QR_CODE",
          value: verifyUrl,
          alternateText: `${customerId} (${programType})`
        },
        textModulesData: patchBody.textModulesData,
        messages: patchBody.messages
      };

      const createRes = await fetch(createEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(createBody)
      });

      const createData = await createRes.json();
      return {
        success: createRes.ok,
        status: createRes.status,
        data: createData,
        created: true
      };
    }

    return {
      success: res.ok,
      status: res.status,
      data: resData
    };
  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

// Send Push Notification / Message to a customer's Google Wallet pass
async function sendGoogleWalletMessage(customerId, programType, header, body) {
  const loyaltyObjectId = customerId.includes('.CUSTOMER_') 
    ? customerId 
    : `${ISSUER_ID}.CUSTOMER_${programType || 'DRINKS'}_${customerId}`;

  try {
    const accessToken = await getGoogleOAuthToken();
    const endpoint = `https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/${encodeURIComponent(loyaltyObjectId)}/addMessage`;

    const uniqueMsgId = `roma_msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const nowIso = new Date().toISOString();

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: {
          id: uniqueMsgId,
          header: header,
          body: body,
          messageType: "TEXT_AND_NOTIFY",
          displayInterval: {
            start: {
              date: nowIso
            }
          }
        }
      })
    });

    const resData = await res.json();
    return {
      success: res.ok,
      status: res.status,
      data: resData
    };
  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

// ---------------- API ROUTES ----------------

// Admin PIN Authentication API
app.post('/api/admin/login', (req, res) => {
  const { pin } = req.body;
  if (!pin) {
    return res.status(400).json({ success: false, error: "يرجى كتابة رمز المرور (PIN)" });
  }
  if (pin.toString().trim() === ADMIN_PIN.toString().trim()) {
    const token = `roma_admin_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
    return res.json({
      success: true,
      message: "تم التحقق بنجاح! مرحباً بك في لوحة الإدارة ☕",
      token
    });
  }
  return res.status(401).json({ success: false, error: "رمز المرور (PIN) غير صحيح! يرجى إعادة المحاولة." });
});

// Get & Update Admin Program Settings (Max stamps & Geofence location)
app.get('/api/settings', (req, res) => {
  res.json({ success: true, settings: loadSettings() });
});

app.post('/api/settings', requireAdminAuth, async (req, res) => {
  try {
    const current = loadSettings();
    const updated = {
      ...current,
      drinksMaxStamps: Number(req.body.drinksMaxStamps) || current.drinksMaxStamps,
      bakeryMaxStamps: Number(req.body.bakeryMaxStamps) || current.bakeryMaxStamps,
      cafeLatitude: req.body.cafeLatitude ? Number(req.body.cafeLatitude) : current.cafeLatitude,
      cafeLongitude: req.body.cafeLongitude ? Number(req.body.cafeLongitude) : current.cafeLongitude,
      cafeAddress: req.body.cafeAddress || current.cafeAddress,
      geofenceActive: typeof req.body.geofenceActive === 'boolean' ? req.body.geofenceActive : current.geofenceActive
    };

    saveSettings(updated);

    // If coordinates provided, update Google Wallet Classes with locations
    if (updated.cafeLatitude && updated.cafeLongitude) {
      try {
        const accessToken = await getGoogleOAuthToken();
        const locationPayload = {
          reviewStatus: 'UNDER_REVIEW',
          locations: [
            {
              kind: 'walletobjects#latLongPoint',
              latitude: updated.cafeLatitude,
              longitude: updated.cafeLongitude
            }
          ]
        };

        for (const cId of [DRINKS_CLASS_ID, BAKERY_CLASS_ID]) {
          await fetch(`https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/${cId}`, {
            method: 'PATCH',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(locationPayload)
          });
        }
        console.log(`[Google Wallet Geofence] Updated locations to (${updated.cafeLatitude}, ${updated.cafeLongitude})`);
      } catch (geoErr) {
        console.warn("Geofence update error:", geoErr.message);
      }
    }

    res.json({ success: true, message: "تم حفظ إعدادات البرنامج وتحديث الموقع في Google Wallet بنجاح ☕🥐", settings: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Network Info for Mobile & Wi-Fi Testing
app.get('/api/network-info', (req, res) => {
  const os = require('os');
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const dev in ifaces) {
    ifaces[dev].forEach(details => {
      if (details.family === 'IPv4' && !details.internal) {
        ips.push(details.address);
      }
    });
  }
  const primaryIp = ips[0] || 'localhost';
  res.json({
    success: true,
    port: PORT,
    localIps: ips,
    primaryIp: primaryIp,
    zbonLocalUrl: `http://${primaryIp}:${PORT}/zbon`,
    adminLocalUrl: `http://${primaryIp}:${PORT}/admin`
  });
});

// Diagnostics & Status
app.get('/api/google-wallet/status', async (req, res) => {
  try {
    const sa = getServiceAccount();
    const settings = loadSettings();
    let token = null;
    let tokenError = null;
    try {
      token = await getGoogleOAuthToken();
    } catch (e) {
      tokenError = e.message;
    }

    const { count, error: sbErr } = await supabase.from('customers').select('*', { count: 'exact', head: true });

    res.json({
      success: true,
      supabase: {
        connected: !sbErr,
        projectId: process.env.SUPABASE_PROJECT_ID || "iulapfbjwckfcdhghszf",
        url: SUPABASE_URL,
        customersCount: count || 0
      },
      googleWallet: {
        issuerId: ISSUER_ID,
        drinksClassId: DRINKS_CLASS_ID,
        bakeryClassId: BAKERY_CLASS_ID,
        serviceAccount: sa.client_email,
        tokenAcquired: !!token,
        tokenError
      },
      settings
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Clear Demo Data Route (Protected with Admin Auth)
app.post('/api/admin/clear-demo-data', requireAdminAuth, async (req, res) => {
  try {
    console.log("[Admin] Clearing demo data...");
    await supabase.from('stamp_transactions').delete().neq('transaction_id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('customers').delete().neq('customer_id', '00000000-0000-0000-0000-000000000000');

    res.json({
      success: true,
      message: "تم مسح جميع البيانات التجريبية بنجاح! قاعدة البيانات الآن نظيفة وجاهزة للزبائن الحقيقيين ☕"
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Send Push Notification Route (Protected with Admin Auth)
app.post('/api/notifications/send', requireAdminAuth, async (req, res) => {
  try {
    const { header, body, customer_id, target = 'ALL', program_type = 'DRINKS' } = req.body;

    if (!header || !body) {
      return res.status(400).json({ error: "يجب تقديم عنوان التنبيه ونص الرسالة" });
    }

    let targets = [];

    if (target === 'SINGLE' && customer_id) {
      const { data: cust } = await supabase.from('customers').select('*').eq('customer_id', customer_id).maybeSingle();
      if (cust) targets.push(cust);
    } else {
      const { data: allCusts } = await supabase.from('customers').select('*');
      targets = allCusts || [];
    }

    if (targets.length === 0) {
      return res.status(404).json({ error: "لا يوجد زبائن لإرسال التنبيه إليهم" });
    }

    // Send notifications to all target customers in parallel (instant speed)
    const results = await Promise.all(
      targets.map(async (cust) => {
        const resNotify = await sendGoogleWalletMessage(cust.customer_id, program_type, header, body);
        
        try {
          await supabase.from('stamp_transactions').insert({
            customer_id: cust.customer_id,
            action_type: 'SET_COUNT',
            stamps_delta: 0,
            previous_count: cust.drinks_stamps || cust.stamps_count || 0,
            new_count: cust.drinks_stamps || cust.stamps_count || 0,
            cashier_name: req.body.cashier_name || 'إدارة Roma Cafe',
            notes: `📢 تنبيه هاتف (${program_type}): ${header} - ${body}`,
            google_wallet_synced: resNotify.success
          });
        } catch (logErr) {}

        return {
          customer_id: cust.customer_id,
          name: cust.full_name,
          success: resNotify.success,
          status: resNotify.status
        };
      })
    );

    const successCount = results.filter(r => r.success).length;

    res.json({
      success: true,
      message: `تم إرسال التنبيه بنجاح إلى (${successCount}) من أصل (${targets.length}) زبون 📱`,
      sentCount: successCount,
      totalTargets: targets.length,
      details: results
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create Wallet Pass (Supports Drinks, Bakery, and Dual Save in 1 Click!)
app.post('/api/create-wallet-pass', async (req, res) => {
  try {
    const { full_name, phone_number, customer_id } = req.body;

    if (!phone_number && !customer_id) {
      return res.status(400).json({ error: "يجب تقديم رقم الهاتف أو معرف الزبون" });
    }

    const cleanPhone = phone_number ? phone_number.trim().replace(/\s+/g, '') : null;
    const cleanName = full_name ? full_name.trim() : null;

    let customer = null;
    let isExistingCustomer = false;

    // 1. Direct search by customer_id if provided
    if (customer_id) {
      const { data } = await supabase.from('customers').select('*').eq('customer_id', customer_id).maybeSingle();
      if (data) {
        customer = data;
        isExistingCustomer = true;
      }
    }

    // 2. Strict validation and matching for Phone & Name
    if (!customer && cleanPhone) {
      const { data: custByPhone } = await supabase.from('customers').select('*').eq('phone_number', cleanPhone).maybeSingle();
      
      let custByName = null;
      if (cleanName) {
        const { data: byName } = await supabase.from('customers').select('*').ilike('full_name', cleanName).maybeSingle();
        custByName = byName;
      }

      if (custByPhone) {
        const existingName = (custByPhone.full_name || '').trim().toLowerCase();
        const incomingName = cleanName ? cleanName.toLowerCase() : '';

        if (cleanName && existingName === incomingName) {
          // Exact match of both phone and name -> Return existing customer without duplicating
          customer = custByPhone;
          isExistingCustomer = true;
        } else if (cleanName) {
          // Phone is registered, but name is different
          return res.status(400).json({ 
            error: `رقم الهاتف (${cleanPhone}) مستخدم ومسجل مسبقاً باسم آخر (${custByPhone.full_name}). إذا كان هذا حسابك، يرجى إدخال اسمك المسجل بشكل صحيح.`,
            error_code: 'PHONE_IN_USE'
          });
        } else {
          customer = custByPhone;
          isExistingCustomer = true;
        }
      } else if (custByName) {
        // Name is registered, but with a different phone number
        return res.status(400).json({ 
          error: `الاسم "${cleanName}" مستخدم ومسجل مسبقاً برقم هاتف آخر. يرجى إدخال رقم هاتفك المسجل أو كتابة الاسم الكامل (الاسم والعائلة).`,
          error_code: 'NAME_IN_USE'
        });
      }
    }

    // 3. Create new customer if not found and passes validation
    if (!customer) {
      if (!cleanName) {
        return res.status(400).json({ error: "يرجى كتابة الاسم الكامل للتسجيل" });
      }

      const newId = customer_id || crypto.randomUUID();
      const walletId = `${ISSUER_ID}.CUSTOMER_DRINKS_${newId}`;

      const { data: created, error: createErr } = await supabase
        .from('customers')
        .insert({
          customer_id: newId,
          full_name: cleanName,
          phone_number: cleanPhone || "0590000000",
          stamps_count: 0,
          drinks_stamps: 0,
          bakery_stamps: 0,
          wallet_object_id: walletId
        })
        .select()
        .single();

      if (createErr) {
        throw new Error(`خطأ قاعدة بيانات Supabase: ${createErr.message}`);
      }
      customer = created;
    }

    // Helper: extract metadata or fallback fields
    let meta = {};
    try {
      if (customer.notes && customer.notes.startsWith('{')) {
        meta = JSON.parse(customer.notes);
      }
    } catch (e) {}

    const drinksStamps = customer.drinks_stamps ?? meta.drinks_stamps ?? customer.stamps_count ?? 0;
    const bakeryStamps = customer.bakery_stamps ?? meta.bakery_stamps ?? 0;

    // Generate Pass for Drinks
    const drinksPass = generatePassJwt({
      customerId: customer.customer_id,
      fullName: customer.full_name,
      stampsCount: drinksStamps,
      programType: 'DRINKS'
    });

    // Generate Pass for Bakery
    const bakeryPass = generatePassJwt({
      customerId: customer.customer_id,
      fullName: customer.full_name,
      stampsCount: bakeryStamps,
      programType: 'BAKERY'
    });

    // Generate Combined Pass (Install BOTH cards together in 1 click!)
    const bothSaveUrl = generateDualPassJwt(
      { customerId: customer.customer_id, fullName: customer.full_name, stampsCount: drinksStamps, programType: 'DRINKS' },
      { customerId: customer.customer_id, fullName: customer.full_name, stampsCount: bakeryStamps, programType: 'BAKERY' }
    );

    // Update customer urls in Supabase
    await supabase.from('customers').update({
      google_wallet_save_url: bothSaveUrl,
      drinks_wallet_url: drinksPass.saveUrl,
      bakery_wallet_url: bakeryPass.saveUrl,
      notes: JSON.stringify({
        ...meta,
        drinks_stamps: drinksStamps,
        bakery_stamps: bakeryStamps,
        drinks_save_url: drinksPass.saveUrl,
        bakery_save_url: bakeryPass.saveUrl,
        both_save_url: bothSaveUrl
      })
    }).eq('customer_id', customer.customer_id);

    // Generate QR images
    const shortBothUrl = `${req.protocol}://${req.get('host')}/wallet/save/${customer.customer_id}`;
    const bothQr = await QRCode.toDataURL(shortBothUrl, { width: 300, margin: 2 });
    
    // Customer Cashier Verify QR (Generated locally on server, zero external latency)
    const verifyUrl = `${req.protocol}://${req.get('host')}/verify?cid=${customer.customer_id}`;
    const verifyQr = await QRCode.toDataURL(verifyUrl, { width: 300, margin: 2 });
    
    let drinksQr = '';
    let bakeryQr = '';
    try {
      drinksQr = await QRCode.toDataURL(drinksPass.saveUrl, { width: 300, margin: 2 });
    } catch (e) {
      drinksQr = await QRCode.toDataURL(`${req.protocol}://${req.get('host')}/verify?cid=${customer.customer_id}&type=DRINKS`, { width: 300, margin: 2 });
    }

    try {
      bakeryQr = await QRCode.toDataURL(bakeryPass.saveUrl, { width: 300, margin: 2 });
    } catch (e) {
      bakeryQr = await QRCode.toDataURL(`${req.protocol}://${req.get('host')}/verify?cid=${customer.customer_id}&type=BAKERY`, { width: 300, margin: 2 });
    }

    const welcomeMsg = isExistingCustomer 
      ? `أهلاً بك مجدداً يا ${customer.full_name}! تم استرجاع بطاقاتك الحالية ورصيدك بنجاح ☕🥐`
      : "تم تسجيلك بنجاح وتجهيز بطاقتي المشروبات والمخبوزات في Google Wallet ☕🥐!";

    res.json({
      success: true,
      is_existing: isExistingCustomer,
      message: welcomeMsg,
      customer: {
        ...customer,
        drinks_stamps: drinksStamps,
        bakery_stamps: bakeryStamps
      },
      verify_qr: verifyQr,
      verify_url: verifyUrl,
      both: {
        save_url: bothSaveUrl,
        short_save_url: shortBothUrl,
        qr_image: bothQr,
        label: "تثبيت البطاقتين معاً بنقرة واحدة (المشروبات + المخبوزات)"
      },
      drinks: {
        save_url: drinksPass.saveUrl,
        qr_image: drinksQr,
        stamps_count: drinksStamps,
        max_stamps: drinksPass.maxStamps,
        visual_gauge: drinksPass.visualGauge
      },
      bakery: {
        save_url: bakeryPass.saveUrl,
        qr_image: bakeryQr,
        stamps_count: bakeryStamps,
        max_stamps: bakeryPass.maxStamps,
        visual_gauge: bakeryPass.visualGauge
      },
      save_url: bothSaveUrl
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Add Stamp / Action (Supports Drinks ☕ or Bakery 🥐 - Protected with Admin Auth)
app.post('/api/add-stamp', requireAdminAuth, async (req, res) => {
  try {
    const {
      customer_id,
      phone_number,
      qr_code,
      action_type = 'ADD_STAMP',
      program_type = 'DRINKS',
      delta = 1,
      cashier_name = 'كاشير Roma',
      notes = ''
    } = req.body;

    const settings = loadSettings();
    const isBakery = (program_type === 'BAKERY');
    const maxStamps = isBakery ? settings.bakeryMaxStamps : settings.drinksMaxStamps;

    let target = customer_id || phone_number || qr_code;
    if (!target) {
      return res.status(400).json({ error: "يجب تحديد الزبون" });
    }

    let cleanId = target.trim();
    if (cleanId.includes("cid=")) {
      const match = cleanId.match(/cid=([^&]+)/);
      if (match) cleanId = match[1];
    }
    const prefixDrinks = `${ISSUER_ID}.CUSTOMER_DRINKS_`;
    const prefixBakery = `${ISSUER_ID}.CUSTOMER_BAKERY_`;
    const prefixOld = `${ISSUER_ID}.CUSTOMER_`;

    if (cleanId.startsWith(prefixDrinks)) cleanId = cleanId.replace(prefixDrinks, "");
    else if (cleanId.startsWith(prefixBakery)) cleanId = cleanId.replace(prefixBakery, "");
    else if (cleanId.startsWith(prefixOld)) cleanId = cleanId.replace(prefixOld, "");

    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(cleanId);
    let customer = null;

    if (isUuid) {
      const { data } = await supabase.from('customers').select('*').eq('customer_id', cleanId).maybeSingle();
      if (data) customer = data;
    }
    if (!customer && target.includes('.CUSTOMER_')) {
      const { data } = await supabase.from('customers').select('*').eq('wallet_object_id', target).maybeSingle();
      if (data) customer = data;
    }
    if (!customer) {
      const { data } = await supabase.from('customers').select('*').eq('phone_number', target).maybeSingle();
      if (data) customer = data;
    }

    if (!customer) {
      return res.status(404).json({ error: "لم يتم العثور على زبون مطابق في قاعدة بيانات Supabase" });
    }

    // Read current counts
    let meta = {};
    try {
      if (customer.notes && customer.notes.startsWith('{')) {
        meta = JSON.parse(customer.notes);
      }
    } catch (e) {}

    let currentDrinks = customer.drinks_stamps ?? meta.drinks_stamps ?? customer.stamps_count ?? 0;
    let currentBakery = customer.bakery_stamps ?? meta.bakery_stamps ?? 0;

    let prevCount = isBakery ? currentBakery : currentDrinks;
    let newCount = prevCount;
    let isRedeemed = false;
    const numDelta = Number(delta) || 1;

    switch (action_type) {
      case 'ADD_STAMP':
        newCount = Math.min(maxStamps, prevCount + numDelta);
        break;
      case 'REDEEM_REWARD':
        newCount = 0;
        isRedeemed = true;
        break;
      case 'SET_COUNT':
        newCount = Math.min(maxStamps, Math.max(0, numDelta));
        break;
      case 'RESET':
        newCount = 0;
        break;
      default:
        return res.status(400).json({ error: "نوع العملية غير معروف" });
    }

    if (isBakery) {
      currentBakery = newCount;
    } else {
      currentDrinks = newCount;
    }

    // Update in Supabase
    meta.drinks_stamps = currentDrinks;
    meta.bakery_stamps = currentBakery;

    await supabase.from('customers').update({
      stamps_count: currentDrinks,
      drinks_stamps: currentDrinks,
      bakery_stamps: currentBakery,
      notes: JSON.stringify(meta),
      last_visit_at: new Date().toISOString()
    }).eq('customer_id', customer.customer_id);

    customer.drinks_stamps = currentDrinks;
    customer.bakery_stamps = currentBakery;
    customer.stamps_count = isBakery ? currentBakery : currentDrinks;
    customer.free_drink_ready = (newCount >= maxStamps);

    const itemLabel = isBakery ? 'مخبوز أو حلى' : 'مشروب';
    const itemIcon = isBakery ? '🥐' : '☕';

    // 1. Send Instant PATCH to Google Wallet Pass (Cached token makes this ~100ms)
    console.log(`[Google Wallet PATCH] Updating ${customer.customer_id} (${program_type}) to ${newCount}/${maxStamps}...`);
    const patchResult = await patchGoogleWalletPass(customer.customer_id, program_type, newCount, maxStamps, isRedeemed, customer.full_name);

    // 2. Trigger Instant Lock-Screen Push Notification to Customer's Phone (Concurrent & Non-blocking)
    let notifTitle = `Roma Cafe: ختم جديد ${itemIcon}`;
    let notifMsg = `تمت إضافة ختم! رصيدك الحالي: ${newCount} من ${maxStamps} أختام ${itemIcon}.`;
    if (isRedeemed) {
      notifTitle = `صحتين وهنا من Roma Cafe! ✨`;
      notifMsg = `تم استبدال الـ ${itemLabel} المجاني بنجاح! ننتظرك في زيارتك القادمة.`;
    } else if (newCount >= maxStamps) {
      notifTitle = `🎉 مبروك! مكافأتك المجانية جاهزة ☕🥐`;
      notifMsg = `أكملت ${maxStamps} أختام! أظهر كارتك للكاشير لاستلام ${itemLabel} مجاناً الآن!`;
    }

    sendGoogleWalletMessage(customer.customer_id, program_type, notifTitle, notifMsg).catch(err => {
      console.warn('[Push Notification Background]', err.message);
    });

    // 3. Log Transaction safely
    try {
      await supabase.from('stamp_transactions').insert({
        customer_id: customer.customer_id,
        action_type: action_type,
        category: program_type,
        stamps_delta: newCount - prevCount,
        previous_count: prevCount,
        new_count: newCount,
        cashier_name: cashier_name,
        notes: notes || `برنامج: ${isBakery ? 'مخبوزات 🥐' : 'مشروبات ☕'}`,
        google_wallet_synced: patchResult.success
      });
    } catch (e) {}

    let message = "";
    if (isRedeemed) {
      message = `🎉 تم استبدال الـ ${itemLabel} المجاني بنجاح! بالهناء والشفاء ✨`;
    } else if (newCount >= maxStamps) {
      message = `🎉 مبروك للزبون! لقد وصل إلى ${maxStamps} أختام واستحق ${itemLabel} مجاني!`;
    } else {
      message = `تمت إضافة الختم بنجاح (${program_type}). الرصيد الحالي: ${newCount} من ${maxStamps} أختام ${itemIcon}`;
    }

    res.json({
      success: true,
      message,
      customer,
      program_type,
      max_stamps: maxStamps,
      new_stamps: newCount,
      visual_gauge: buildVisualStampGauge(newCount, maxStamps, isBakery ? '🥐' : '☕'),
      google_wallet_sync: {
        success: patchResult.success,
        status: patchResult.status || 500,
        details: patchResult.data || patchResult.error
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// List all customers from Supabase
app.get('/api/customers', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('customers')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    
    const enriched = (data || []).map(c => {
      let meta = {};
      try {
        if (c.notes && c.notes.startsWith('{')) meta = JSON.parse(c.notes);
      } catch (e) {}
      return {
        ...c,
        drinks_stamps: c.drinks_stamps ?? meta.drinks_stamps ?? c.stamps_count ?? 0,
        bakery_stamps: c.bakery_stamps ?? meta.bakery_stamps ?? 0
      };
    });

    res.json({ success: true, customers: enriched });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// List recent transactions
app.get('/api/transactions', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('stamp_transactions')
      .select(`
        *,
        customers ( full_name )
      `)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    const formatted = (data || []).map(t => ({
      ...t,
      customer_name: t.customers ? t.customers.full_name : 'زبون'
    }));

    res.json({ success: true, transactions: formatted });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start Production HTTP Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(`☕ Roma Cafe Dual Loyalty Server [PRODUCTION BUILD]`);
  console.log(`🚀 Cashier & Admin Dashboard: http://localhost:${PORT}/admin`);
  console.log(`📱 Customer Registration Portal: http://localhost:${PORT}/zbon`);
  console.log(`🔒 Security PIN: ${ADMIN_PIN ? 'ENABLED (Protected)' : 'DISABLED'}`);
  console.log(`📡 Google Wallet Issuer: ${ISSUER_ID}`);
  console.log(`🎟️ Drinks Class: ${DRINKS_CLASS_ID}`);
  console.log(`🥐 Bakery Class: ${BAKERY_CLASS_ID}`);
  console.log(`=======================================================`);
});

