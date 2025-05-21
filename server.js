const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "login page"))); // Serve frontend
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Default route to load registration page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login page", "login.html"));
});

// MongoDB connection (Login DB)
mongoose.connect(process.env.LOGIN_MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("Connected to Login MongoDB"))
  .catch(err => console.error("Login MongoDB connection error:", err));

// User schema for login system
const loginUserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  adminType: { type: String, enum: ["camp", "enroll"], required: true },
});

const LoginUser = mongoose.model("LoginUser", loginUserSchema);

// Login route
app.post("/api/login", async (req, res) => {
  const { username, password, adminType } = req.body;

  if (!username || !password || !adminType) {
    return res.status(400).json({ message: "Missing credentials or admin type" });
  }

  try {
    const user = await LoginUser.findOne({ username, adminType });
    if (!user) {
      return res.status(401).json({ message: "Invalid username or admin type" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    res.status(200).json({ message: "Login successful" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Add user route - supports multiple admin types
app.post("/api/add-user", async (req, res) => {
  let { username, password, adminType } = req.body;

  if (!username || !password || !adminType) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // Normalize adminType to array if it's not already
  if (!Array.isArray(adminType)) {
    adminType = [adminType];
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    for (const type of adminType) {
      const existing = await LoginUser.findOne({ username, adminType: type });
      if (existing) {
        return res.status(409).json({ message: `User already exists for admin type: ${type}` });
      }
      const newUser = new LoginUser({ username, password: hashedPassword, adminType: type });
      await newUser.save();
    }

    res.status(201).json({ message: "User(s) added successfully" });
  } catch (err) {
    console.error("Add user error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all users grouped by username with array of admin types
app.get("/api/users", async (req, res) => {
  try {
    const users = await LoginUser.find({}, "username adminType -_id");

    // Group users by username
    const grouped = users.reduce((acc, user) => {
      if (!acc[user.username]) acc[user.username] = { username: user.username, adminType: [] };
      acc[user.username].adminType.push(user.adminType);
      return acc;
    }, {});

    res.json(Object.values(grouped));
  } catch (err) {
    console.error("Fetch users error:", err);
    res.status(500).json({ message: "Error fetching users" });
  }
});

// Delete a user by username and adminType
app.delete("/api/users/:username/:adminType", async (req, res) => {
  const { username, adminType } = req.params;
  try {
    const result = await LoginUser.deleteOne({ username, adminType });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ message: "Error deleting user" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Login server is running on http://localhost:${PORT}`);
});
