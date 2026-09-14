const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");
const { google } = require("googleapis");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 20 * 1024 * 1024 * 1024 } // 20 GB
});

const REDIRECT_URI = `http://localhost:${PORT}/oauth2callback`;
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  REDIRECT_URI
);

const TOKEN_FILE = path.join(__dirname, "tokens.json");
if (fs.existsSync(TOKEN_FILE)) {
  oauth2Client.setCredentials(JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")));
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/auth", (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/youtube.upload"]
  });
  res.redirect(url);
});

app.get("/oauth2callback", async (req, res) => {
  try {
    const { tokens } = await oauth2Client.getToken(req.query.code);
    oauth2Client.setCredentials(tokens);
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
    res.redirect("/?connected=1");
  } catch (err) {
    console.error(err);
    res.status(500).send("YouTube authorization failed. Check the terminal.");
  }
});

app.get("/api/status", async (req, res) => {
  try {
    if (!fs.existsSync(TOKEN_FILE)) return res.json({ connected: false });
    oauth2Client.setCredentials(JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")));
    const youtube = google.youtube({ version: "v3", auth: oauth2Client });
    const result = await youtube.channels.list({
      part: ["snippet"],
      mine: true
    });
    const channel = result.data.items?.[0];
    res.json({
      connected: !!channel,
      channel: channel ? {
        title: channel.snippet.title,
        id: channel.id
      } : null
    });
  } catch (err) {
    res.json({ connected: false, error: "Authorization expired or invalid." });
  }
});

app.post("/api/upload", upload.fields([
  { name: "video", maxCount: 1 },
  { name: "thumbnail", maxCount: 1 }
]), async (req, res) => {
  try {
    if (!fs.existsSync(TOKEN_FILE)) {
      return res.status(401).json({ error: "Connect YouTube first." });
    }

    oauth2Client.setCredentials(JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")));
    const youtube = google.youtube({ version: "v3", auth: oauth2Client });

    const videoFile = req.files?.video?.[0];
    if (!videoFile) return res.status(400).json({ error: "Video is required." });

    const privacy = ["public", "unlisted", "private"].includes(req.body.privacy)
      ? req.body.privacy : "private";

    const tags = (req.body.tags || "")
      .split(",").map(s => s.trim()).filter(Boolean);

    const result = await youtube.videos.insert({
      part: ["snippet", "status"],
      requestBody: {
        snippet: {
          title: req.body.title || "Untitled",
          description: req.body.description || "",
          tags
        },
        status: {
          privacyStatus: privacy
        }
      },
      media: {
        body: fs.createReadStream(videoFile.path)
      }
    });

    const videoId = result.data.id;

    const thumb = req.files?.thumbnail?.[0];
    if (thumb && videoId) {
      await youtube.thumbnails.set({
        videoId,
        media: {
          mimeType: thumb.mimetype,
          body: fs.createReadStream(thumb.path)
        }
      });
    }

    for (const f of [videoFile, thumb].filter(Boolean)) {
      try { fs.unlinkSync(f.path); } catch {}
    }

    res.json({
      success: true,
      videoId,
      url: `https://www.youtube.com/watch?v=${videoId}`
    });
  } catch (err) {
    console.error(err?.response?.data || err);
    res.status(500).json({
      error: err?.response?.data?.error?.message || "Upload failed. Check the terminal."
    });
  }
});

app.listen(PORT, () => {
  console.log(`YT Admin running at http://localhost:${PORT}`);
});