require("dotenv").config();

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { google } = require("googleapis");

const app = express();

const PORT = process.env.PORT || 3000;

// ===============================
// BASIC SETUP
// ===============================

const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===============================
// FILE UPLOAD SETUP
// ===============================

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 20 * 1024 * 1024 * 1024
  }
});

// ===============================
// RENDER URL + OAUTH
// ===============================

const baseUrl = (
  process.env.RENDER_EXTERNAL_URL ||
  `http://localhost:${PORT}`
).replace(/\/$/, "");

const redirectUri = `${baseUrl}/oauth2callback`;

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  redirectUri
);

// ===============================
// TOKEN STORAGE
// ===============================

const tokenFile = path.join(__dirname, "tokens.json");

function saveTokens(tokens) {
  fs.writeFileSync(
    tokenFile,
    JSON.stringify(tokens, null, 2)
  );
}

function loadTokens() {
  if (!fs.existsSync(tokenFile)) {
    return null;
  }

  try {
    return JSON.parse(
      fs.readFileSync(tokenFile, "utf8")
    );
  } catch (error) {
    console.error("Token read error:", error);
    return null;
  }
}

// ===============================
// HOME PAGE
// ===============================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// ===============================
// YOUTUBE LOGIN
// ===============================

app.get("/auth", (req, res) => {
  try {
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "https://www.googleapis.com/auth/youtube.upload",
      access_type: "offline",
      prompt: "consent"
    });

    const authUrl =
      `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

    console.log("OAuth redirect URI:", redirectUri);

    res.redirect(authUrl);

  } catch (error) {
    console.error("Auth URL error:", error);
    res.status(500).send("Unable to start Google authentication.");
  }
});

// ===============================
// OAUTH CALLBACK
// ===============================

app.get("/oauth2callback", async (req, res) => {

  try {

    const code = req.query.code;

    if (!code) {
      return res
        .status(400)
        .send("Authorization code missing.");
    }

    console.log("OAuth callback received.");

    const { tokens } =
      await oauth2Client.getToken(code);

    oauth2Client.setCredentials(tokens);

    saveTokens(tokens);

    console.log("YouTube authorization successful.");

    res.redirect("/?connected=1");

  } catch (error) {

    console.error(
      "OAuth callback error:",
      error.response?.data || error
    );

    res
      .status(500)
      .send(
        "YouTube authorization failed. Check Render logs."
      );
  }
});

// ===============================
// CONNECTION STATUS
// ===============================

app.get("/api/status", async (req, res) => {

  try {

    const tokens = loadTokens();

    if (!tokens) {
      return res.json({
        connected: false
      });
    }

    oauth2Client.setCredentials(tokens);

    const youtube = google.youtube({
      version: "v3",
      auth: oauth2Client
    });

    const response =
      await youtube.channels.list({
        part: ["snippet"],
        mine: true
      });

    const channel =
      response.data.items?.[0];

    if (!channel) {
      return res.json({
        connected: false
      });
    }

    res.json({
      connected: true,
      channel: {
        id: channel.id,
        title: channel.snippet.title
      }
    });

  } catch (error) {

    console.error(
      "Status error:",
      error.response?.data || error
    );

    res.json({
      connected: false
    });
  }
});

// ===============================
// YOUTUBE VIDEO UPLOAD
// ===============================

app.post(
  "/api/upload",

  upload.fields([
    {
      name: "video",
      maxCount: 1
    },
    {
      name: "thumbnail",
      maxCount: 1
    }
  ]),

  async (req, res) => {

    const videoFile =
      req.files?.video?.[0];

    const thumbnailFile =
      req.files?.thumbnail?.[0];

    try {

      // -------------------------------
      // CHECK LOGIN
      // -------------------------------

      const tokens = loadTokens();

      if (!tokens) {

        return res.status(401).json({
          error: "Connect YouTube first."
        });

      }

      oauth2Client.setCredentials(tokens);

      // -------------------------------
      // YOUTUBE CLIENT
      // -------------------------------

      const youtube = google.youtube({
        version: "v3",
        auth: oauth2Client
      });

      // -------------------------------
      // VIDEO CHECK
      // -------------------------------

      if (!videoFile) {

        return res.status(400).json({
          error: "Video is required."
        });

      }

      // -------------------------------
      // FORM DATA
      // -------------------------------

      const title =
        req.body.title ||
        "Untitled Video";

      const description =
        req.body.description ||
        "";

      const privacy =
        ["public", "unlisted", "private"]
          .includes(req.body.privacy)
          ? req.body.privacy
          : "private";

      const tags =
        (req.body.tags || "")
          .split(",")
          .map(tag => tag.trim())
          .filter(Boolean);

      // -------------------------------
      // UPLOAD VIDEO
      // -------------------------------

      console.log(
        "Uploading video:",
        title
      );

      const videoResponse =
        await youtube.videos.insert({

          part: [
            "snippet",
            "status"
          ],

          requestBody: {

            snippet: {

              title: title,

              description: description,

              tags: tags

            },

            status: {

              privacyStatus: privacy

            }

          },

          media: {

            body: fs.createReadStream(
              videoFile.path
            )

          }

        });

      const videoId =
        videoResponse.data.id;

      console.log(
        "Video uploaded:",
        videoId
      );

      // -------------------------------
      // THUMBNAIL
      // -------------------------------

      if (
        thumbnailFile &&
        videoId
      ) {

        console.log(
          "Uploading thumbnail..."
        );

        try {

          await youtube.thumbnails.set({

            videoId: videoId,

            media: {

              mimeType:
                thumbnailFile.mimetype,

              body:
                fs.createReadStream(
                  thumbnailFile.path
                )

            }

          });

          console.log(
            "Thumbnail uploaded."
          );

        } catch (thumbnailError) {

          console.error(
            "Thumbnail upload error:",
            thumbnailError.response?.data ||
            thumbnailError
          );

          // Video is already uploaded,
          // so don't fail the whole request.
        }
      }

      // -------------------------------
      // SUCCESS
      // -------------------------------

      res.json({

        success: true,

        videoId: videoId,

        url:
          `https://www.youtube.com/watch?v=${videoId}`

      });

    } catch (error) {

      console.error(
        "YouTube upload error:",
        error.response?.data ||
        error
      );

      const message =
        error.response?.data?.error?.message ||
        error.message ||
        "YouTube upload failed.";

      res.status(500).json({

        error: message

      });

    } finally {

      // -------------------------------
      // DELETE TEMP FILES
      // -------------------------------

      for (
        const file of [
          videoFile,
          thumbnailFile
        ]
      ) {

        if (file?.path) {

          try {

            fs.unlinkSync(file.path);

          } catch (error) {

            console.error(
              "Temporary file delete error:",
              error.message
            );

          }

        }

      }

    }

  }
);

// ===============================
// HEALTH CHECK
// ===============================

app.get("/health", (req, res) => {

  res.json({
    status: "ok",
    service: "YT Admin",
    oauthRedirectUri: redirectUri
  });

});

// ===============================
// START SERVER
// ===============================

app.listen(PORT, () => {

  console.log(
    "================================="
  );

  console.log(
    "YT Admin server is running"
  );

  console.log(
    "Port:",
    PORT
  );

  console.log(
    "OAuth Redirect URI:",
    redirectUri
  );

  console.log(
    "================================="
  );

});
