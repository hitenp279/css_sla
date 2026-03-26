const express    = require("express");
const cors       = require("cors");
const bodyParser = require("body-parser");
const certRoutes = require("./routes/certRoutes");

const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(bodyParser.json({ limit: "100kb" }));

app.get("/", (req, res) => {
  res.json({ status: "running", service: "CertAuth API", version: "2.0" });
});

app.use("/api", certRoutes);

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 CertAuth API running on http://localhost:${PORT}`)
);