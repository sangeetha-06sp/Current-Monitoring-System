
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const MAX_FILE_BYTES = 120 * 1024;
const MAX_RECORDS = 5000;

// Capture the original JSON bytes so retries can be identified
// even when the server receives the same file again.
app.use(
  express.json({
    limit: "120kb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    }
  })
);

// Enable dashboard access. Restrict origins when your dashboard URL
// is known; the device API is protected separately with an API key.
app.use(cors());

// One MongoDB document per uploaded JSON file.
// A 100 KB file is safely below MongoDB's 16 MB document limit.
const uploadedFileSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true
    },
    fileName: {
      type: String,
      required: true
    },
    sha256: {
      type: String,
      required: true
    },
    recordCount: {
      type: Number,
      required: true
    },
    readings: {
      type: [mongoose.Schema.Types.Mixed],
      required: true
    },
    receivedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    versionKey: false
  }
);

// Prevent the same device/file combination being stored twice.
uploadedFileSchema.index(
  { deviceId: 1, fileName: 1 },
  { unique: true }
);

const UploadedFile = mongoose.model(
  "UploadedFile",
  uploadedFileSchema
);

// API-key protection for device and data endpoints.
function requireApiKey(req, res, next) {
  const expected = process.env.DEVICE_API_KEY;
  const supplied = req.get("X-API-Key") || "";

  if (!expected) {
    return res.status(503).json({
      success: false,
      message: "Server API key is not configured."
    });
  }

  const expectedBuffer = Buffer.from(expected);
  const suppliedBuffer = Buffer.from(supplied);

  const valid =
    expectedBuffer.length === suppliedBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);

  if (!valid) {
    return res.status(401).json({
      success: false,
      message: "Invalid API key."
    });
  }

  next();
}

// Health check. Does not expose credentials.
app.get("/", (req, res) => {
  res.json({
    service: "Current Monitoring API",
    status: "running"
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected"
  });
});

// Upload one completed JSON file.
// Headers:
// X-API-Key: your device secret
// X-Device-ID: esp8266-01
// X-File-Name: data1.json
//
// Body: the JSON array contained in the local file.
app.post(
  "/api/readings/files",
  requireApiKey,
  async (req, res) => {
    try {
      const deviceId = req.get("X-Device-ID") || "";
      const fileName = req.get("X-File-Name") || "";
      const readings = req.body;

      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(deviceId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid device ID."
        });
      }

      if (!/^data[0-9]+\.json$/.test(fileName)) {
        return res.status(400).json({
          success: false,
          message: "Invalid file name."
        });
      }

      if (
        !req.rawBody ||
        req.rawBody.length === 0 ||
        req.rawBody.length > MAX_FILE_BYTES
      ) {
        return res.status(413).json({
          success: false,
          message: "File is empty or exceeds the size limit."
        });
      }

      if (!Array.isArray(readings) || readings.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Expected a non-empty JSON array."
        });
      }

      if (readings.length > MAX_RECORDS) {
        return res.status(400).json({
          success: false,
          message: "Too many records in this file."
        });
      }

      // Validate every reading before saving anything.
      for (const item of readings) {
        if (
          !item ||
          typeof item !== "object" ||
          Array.isArray(item) ||
          !Number.isFinite(item.time_ms) ||
          !Number.isFinite(item.current_A) ||
          (
            item.current_mA !== undefined &&
            !Number.isFinite(item.current_mA)
          )
        ) {
          return res.status(400).json({
            success: false,
            message:
              "Each record must contain numeric time_ms and current_A fields."
          });
        }
      }

      const sha256 = crypto
        .createHash("sha256")
        .update(req.rawBody)
        .digest("hex");

      // Idempotency: a retry of an already saved file is safe.
      const existing = await UploadedFile.findOne({
        deviceId,
        fileName
      }).lean();

      if (existing) {
        if (existing.sha256 !== sha256) {
          return res.status(409).json({
            success: false,
            message:
              "This filename already exists with different content. Keep the local file and investigate."
          });
        }

        return res.status(200).json({
          success: true,
          duplicate: true,
          fileName,
          recordCount: existing.recordCount,
          message: "This file was already stored successfully."
        });
      }

      await UploadedFile.create({
        deviceId,
        fileName,
        sha256,
        recordCount: readings.length,
        readings
      });

      // Only this success acknowledgement permits local deletion.
      return res.status(201).json({
        success: true,
        duplicate: false,
        fileName,
        recordCount: readings.length,
        message: "File stored successfully."
      });
    } catch (error) {
      // Another retry may have inserted the same file concurrently.
      if (error.code === 11000) {
        try {
          const deviceId = req.get("X-Device-ID") || "";
          const fileName = req.get("X-File-Name") || "";
          const sha256 = crypto
            .createHash("sha256")
            .update(req.rawBody || Buffer.alloc(0))
            .digest("hex");

          const existing = await UploadedFile.findOne({
            deviceId,
            fileName
          }).lean();

          if (existing && existing.sha256 === sha256) {
            return res.status(200).json({
              success: true,
              duplicate: true,
              fileName,
              recordCount: existing.recordCount,
              message: "File was already stored successfully."
            });
          }
        } catch (_) {
          // Fall through to the error response.
        }
      }

      console.error("Upload error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Upload failed. Keep the local file and retry."
      });
    }
  }
);

// Retrieve uploaded-file summaries for a dashboard.
// The same API key is required.
app.get(
  "/api/readings/files",
  requireApiKey,
  async (req, res) => {
    try {
      const deviceId = req.query.deviceId || "esp8266-01";

      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(deviceId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid device ID."
        });
      }

      const files = await UploadedFile.find(
        { deviceId },
        {
          _id: 0,
          deviceId: 1,
          fileName: 1,
          recordCount: 1,
          receivedAt: 1,
          sha256: 1
        }
      )
        .sort({ receivedAt: -1 })
        .limit(100)
        .lean();

      return res.json({
        success: true,
        deviceId,
        count: files.length,
        files
      });
    } catch (error) {
      console.error("Read error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Could not retrieve file records."
      });
    }
  }
);

// Return JSON for unknown routes and invalid requests.
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Endpoint not found."
  });
});

async function startServer() {
  if (!process.env.MONGODB_URI || !process.env.DEVICE_API_KEY) {
    throw new Error(
      "Set MONGODB_URI and DEVICE_API_KEY in your environment."
    );
  }

  await mongoose.connect(process.env.MONGODB_URI);

  // Ensure the unique index exists before accepting uploads.
  await UploadedFile.init();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Current Monitoring API listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Could not start server:", error.message);
  process.exit(1);
});
