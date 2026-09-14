require("dotenv").config();
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { google } = require("googleapis");

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_CHANNELS = 7;

// YouTube scopes: upload + read channel information.
const SCOPES = [
  "https://www.googleapis.com/auth/youtube.upload",
  "https://www.googleapis.com/auth/youtube.readonly"
];

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_PASSWORD) {
  console.warn("WARNING: ADMIN_PASSWORD is not set. Admin login will be unavailable.");
}

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 20 * 1024 * 1024 * 1024 }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const baseUrl = (process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const redirectUri = `${baseUrl}/oauth2callback`;

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const dbFile = path.join(dataDir, "channels.json");

function readDB() {
  try { return JSON.parse(fs.readFileSync(dbFile, "utf8")); }
  catch { return { channels: [] }; }
}
function writeDB(db) {
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
}

function publicChannel(c) {
  return {
    slot: c.slot,
    connected: !!c.tokens,
    title: c.title || `Channel ${c.slot}`,
    thumbnail: c.thumbnail || "",
    enabled: !!c.enabled,
    channelId: c.channelId || ""
  };
}

function makeOAuth() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    redirectUri
  );
}

async function getChannelInfo(oauth) {
  const youtube = google.youtube({ version: "v3", auth: oauth });
  const r = await youtube.channels.list({
    part: ["snippet", "statistics"],
    mine: true
  });
  const c = r.data.items?.[0];
  if (!c) return null;

  return {
    channelId: c.id,
    title: c.snippet?.title || "YouTube Channel",
    thumbnail: c.snippet?.thumbnails?.high?.url ||
               c.snippet?.thumbnails?.default?.url || "",
    subscribers: c.statistics?.subscriberCount || "0",
    videos: c.statistics?.videoCount || "0",
    views: c.statistics?.viewCount || "0"
  };
}

// =====================================================
// SIMPLE SECURE ADMIN SESSION
// =====================================================

const sessions = new Map();
const SESSION_TTL = 24 * 60 * 60 * 1000;

function createSession() {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, Date.now() + SESSION_TTL);
  return token;
}

function isValidSession(token) {
  if (!token) return false;
  const expires = sessions.get(token);
  if (!expires) return false;
  if (Date.now() > expires) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-session"];
  if (!isValidSession(token)) {
    return res.status(401).json({ error: "Admin login required." });
  }
  next();
}

// Login endpoint
app.post("/api/login", (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ error: "ADMIN_PASSWORD is not configured on the server." });
  }

  const password = String(req.body.password || "");

  if (!crypto.timingSafeEqual(
    Buffer.from(password),
    Buffer.from(ADMIN_PASSWORD)
  )) {
    return res.status(401).json({ error: "Incorrect password." });
  }

  const token = createSession();

  res.json({
    success: true,
    token
  });
});

app.post("/api/logout", (req, res) => {
  const token = req.headers["x-admin-session"];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

app.get("/api/auth-status", (req, res) => {
  res.json({ loggedIn: isValidSession(req.headers["x-admin-session"]) });
});

// =====================================================
// PUBLIC HOME = LOGIN SCREEN
// =====================================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// =====================================================
// PROTECTED OAUTH CONNECTION
// =====================================================

app.get("/auth/:slot", (req, res) => {
  if (!isValidSession(req.headers["x-admin-session"])) {
    return res.redirect("/");
  }

  const slot = Number(req.params.slot);
  if (!Number.isInteger(slot) || slot < 1 || slot > MAX_CHANNELS)
    return res.status(400).send("Invalid channel slot.");

  const state = Buffer.from(JSON.stringify({
    slot,
    nonce: crypto.randomBytes(16).toString("hex")
  })).toString("base64url");

  // Put session token into state so callback can restore login.
  const sessionToken = req.headers["x-admin-session"];
  const stateWithSession = Buffer.from(JSON.stringify({
    slot,
    nonce: crypto.randomBytes(16).toString("hex"),
    sessionToken
  })).toString("base64url");

  const oauth = makeOAuth();
  const authUrl = oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: true,
    scope: SCOPES,
    state: stateWithSession
  });

  res.redirect(authUrl);
});

app.get("/oauth2callback", async (req, res) => {
  try {
    if (req.query.error) return res.redirect("/?error=oauth_cancelled");
    if (!req.query.code || !req.query.state) return res.status(400).send("Authorization data missing.");

    const state = JSON.parse(
      Buffer.from(req.query.state, "base64url").toString("utf8")
    );

    const slot = Number(state.slot);
    const sessionToken = state.sessionToken;

    if (!Number.isInteger(slot) || slot < 1 || slot > MAX_CHANNELS)
      return res.status(400).send("Invalid channel slot.");

    if (!isValidSession(sessionToken))
      return res.status(401).send("Admin session expired. Please log in again.");

    const oauth = makeOAuth();
    const { tokens } = await oauth.getToken(req.query.code);
    oauth.setCredentials(tokens);

    const info = await getChannelInfo(oauth);
    if (!info) return res.status(400).send("No YouTube channel was found for this Google account.");

    const db = readDB();
    db.channels = db.channels || [];

    const old = db.channels.find(c => c.slot === slot);
    const record = {
      slot,
      tokens: { ...(old?.tokens || {}), ...tokens },
      enabled: old?.enabled ?? true,
      ...info
    };

    db.channels = db.channels.filter(c => c.slot !== slot);
    db.channels.push(record);
    db.channels.sort((a, b) => a.slot - b.slot);
    writeDB(db);

    res.redirect("/?connected=1");
  } catch (err) {
    console.error("OAuth callback error:", err.response?.data || err);
    res.status(500).send("YouTube authorization failed. Check Render logs.");
  }
});

// =====================================================
// PROTECTED CHANNEL API
// =====================================================

app.get("/api/channels", requireAdmin, async (req, res) => {
  const db = readDB();
  db.channels = db.channels || [];
  const channels = [];

  for (let slot = 1; slot <= MAX_CHANNELS; slot++) {
    const c = db.channels.find(x => x.slot === slot);

    if (!c) {
      channels.push({
        slot,
        connected: false,
        title: `Channel ${slot}`,
        enabled: false
      });
      continue;
    }

    try {
      const oauth = makeOAuth();
      oauth.setCredentials(c.tokens);
      const fresh = await getChannelInfo(oauth);

      if (fresh) {
        Object.assign(c, fresh);
        channels.push(publicChannel(c));
      } else {
        channels.push({ ...publicChannel(c), connected: false });
      }
    } catch {
      channels.push({ ...publicChannel(c), connected: false });
    }
  }

  writeDB(db);
  res.json({ channels });
});

app.post("/api/channels/:slot/toggle", requireAdmin, (req, res) => {
  const slot = Number(req.params.slot);
  if (!Number.isInteger(slot) || slot < 1 || slot > MAX_CHANNELS)
    return res.status(400).json({ error: "Invalid slot." });

  const db = readDB();
  const c = (db.channels || []).find(x => x.slot === slot);

  if (!c || !c.tokens)
    return res.status(404).json({ error: "Channel is not connected." });

  c.enabled = !!req.body.enabled;
  writeDB(db);
  res.json({ success: true, enabled: c.enabled });
});

// =====================================================
// PROTECTED MULTI-CHANNEL UPLOAD
// =====================================================

app.post(
  "/api/upload",
  requireAdmin,
  upload.fields([
    { name: "video", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 }
  ]),
  async (req, res) => {
    const videoFile = req.files?.video?.[0];
    const thumbnailFile = req.files?.thumbnail?.[0];

    try {
      if (!videoFile) return res.status(400).json({ error: "Video is required." });

      const db = readDB();
      const targets = (db.channels || []).filter(c => c.tokens && c.enabled);

      if (!targets.length)
        return res.status(400).json({ error: "Enable at least one connected YouTube channel." });

      const title = (req.body.title || "Untitled Video").trim();
      const description = req.body.description || "";
      const privacy = ["public", "unlisted", "private"].includes(req.body.privacy)
        ? req.body.privacy : "private";
      const tags = (req.body.tags || "").split(",").map(x => x.trim()).filter(Boolean);

      const results = [];

      for (const c of targets) {
        try {
          const oauth = makeOAuth();
          oauth.setCredentials(c.tokens);

          oauth.on("tokens", newTokens => {
            c.tokens = { ...(c.tokens || {}), ...newTokens };
            writeDB(db);
          });

          const youtube = google.youtube({ version: "v3", auth: oauth });

          const r = await youtube.videos.insert({
            part: ["snippet", "status"],
            requestBody: {
              snippet: { title, description, tags },
              status: { privacyStatus: privacy }
            },
            media: {
              mimeType: videoFile.mimetype || "video/*",
              body: fs.createReadStream(videoFile.path)
            },
            resumable: true
          });

          const videoId = r.data.id;
          let thumbnailUploaded = false;

          if (thumbnailFile && videoId) {
            try {
              await youtube.thumbnails.set({
                videoId,
                media: {
                  mimeType: thumbnailFile.mimetype,
                  body: fs.createReadStream(thumbnailFile.path)
                }
              });
              thumbnailUploaded = true;
            } catch (err) {
              console.error(`Thumbnail error slot ${c.slot}:`, err.response?.data || err);
            }
          }

          results.push({
            slot: c.slot,
            title: c.title,
            success: true,
            thumbnailUploaded,
            videoId,
            url: `https://www.youtube.com/watch?v=${videoId}`
          });
        } catch (err) {
          console.error(`Upload error slot ${c.slot}:`, err.response?.data || err);
          results.push({
            slot: c.slot,
            title: c.title,
            success: false,
            error: err.response?.data?.error?.message || err.message || "Upload failed."
          });
        }
      }

      res.json({
        success: results.some(x => x.success),
        results
      });
    } catch (err) {
      console.error("Multi upload error:", err);
      res.status(500).json({ error: err.message || "Upload failed." });
    } finally {
      for (const f of [videoFile, thumbnailFile]) {
        if (f?.path) { try { fs.unlinkSync(f.path); } catch {} }
      }
    }
  }
);

app.get("/health", (req, res) => res.json({ status: "ok", service: "YT Admin 7 Channel Secure" }));

app.listen(PORT, () => {
  console.log("YT Admin 7 Channel Secure running on port", PORT);
  console.log("OAuth redirect:", redirectUri);
});
