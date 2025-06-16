const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "login page")));

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || "your-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 30 }
}));

// MongoDB connection
mongoose.connect(process.env.LOGIN_MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("Connected to Login MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

// User Schema
const loginUserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  adminType: { type: String, enum: ["camp", "enroll"], required: true }
});

const LoginUser = mongoose.model("LoginUser", loginUserSchema);

// Routes

// Login
app.post("/api/login", async (req, res) => {
  const { username, password, adminType } = req.body;
  if (!username || !password || !adminType)
    return res.status(400).json({ message: "Missing fields" });

  try {
    const user = await LoginUser.findOne({ username, adminType });
    if (!user) return res.status(401).json({ message: "Invalid user or access" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Wrong password" });

    res.status(200).json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Add user
app.post("/api/add-user", async (req, res) => {
  let { username, password, adminType } = req.body;
  if (!username || !password || !adminType)
    return res.status(400).json({ message: "Missing fields" });

  if (!Array.isArray(adminType)) adminType = [adminType];

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    for (const type of adminType) {
      const exists = await LoginUser.findOne({ username, adminType: type });
      if (exists)
        return res.status(409).json({ message: `User exists for ${type}` });

      await new LoginUser({ username, password: hashedPassword, adminType: type }).save();
    }

    res.status(201).json({ message: "User(s) added" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get users
app.get("/api/users", async (req, res) => {
  try {
    const users = await LoginUser.find({}, "username adminType -_id");
    const grouped = users.reduce((acc, user) => {
      if (!acc[user.username]) acc[user.username] = { username: user.username, adminType: [] };
      acc[user.username].adminType.push(user.adminType);
      return acc;
    }, {});
    res.json(Object.values(grouped));
  } catch (err) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

// Delete user
app.delete("/api/users/:username/:adminType", async (req, res) => {
  const { username, adminType } = req.params;
  try {
    const result = await LoginUser.deleteOne({ username, adminType });
    if (result.deletedCount === 0)
      return res.status(404).json({ message: "User not found" });
    res.status(200).json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ message: "Delete error" });
  }
});

// Edit user (inline update username, password, access)
app.put("/api/users/:username/:adminType", async (req, res) => {
  const { username, adminType } = req.params;
  const { newUsername, newPassword, newAdminType } = req.body;

  try {
    const user = await LoginUser.findOne({ username, adminType });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (newUsername) user.username = newUsername;
    if (newPassword) user.password = await bcrypt.hash(newPassword, 10);
    if (newAdminType) user.adminType = newAdminType;

    await user.save();
    res.status(200).json({ message: "User updated" });
  } catch (err) {
    res.status(500).json({ message: "Update error" });
  }
});

// Home route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login page", "login.html"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
