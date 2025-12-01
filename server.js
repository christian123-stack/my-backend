// server.js (ES Modules)
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import helmet from "helmet";

import User from "./models/User.js";
import Kos from "./models/Kos.js";
import commentRoute from "./routes/commentRoute.js";

dotenv.config();

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const FRONTEND_URL = process.env.FRONTEND_URL;

const app = express();

// ------------------------------------ SECURITY ------------------------------------
app.use(helmet());

// ------------------------------------ CORS ------------------------------------
app.use(
  cors({
    origin: FRONTEND_URL, // contoh: "https://christian123-stack.github.io/my-frontend/"
    methods: ["GET", "POST", "DELETE", "PUT"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "20mb" }));

// ------------------------------------ ROOT ROUTE ------------------------------------
app.get("/", (req, res) => {
  res.send("Backend API is running 🚀");
});

// ------------------------------------ REGISTER ------------------------------------
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email sudah terdaftar!" });

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hashed });
    await user.save();

    res.json({ message: "Registrasi berhasil!" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ message: "Error server" });
  }
});

// ------------------------------------ LOGIN ------------------------------------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user)
      return res.status(400).json({ message: "Email tidak ditemukan" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Password salah" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login berhasil",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Error server" });
  }
});

// ------------------------------------ UPLOAD KOS ------------------------------------
app.post("/api/kos", async (req, res) => {
  try {
    const { name, price, description, address, image, userId } = req.body;

    const newKos = new Kos({
      name,
      price,
      description,
      address,
      image,
      createdBy: userId,
      comments: [],
    });

    await newKos.save();

    res.json({ message: "Kos berhasil disimpan!", kos: newKos });
  } catch (err) {
    console.error("UPLOAD KOS ERROR:", err);
    res.status(500).json({ message: "Gagal upload kos" });
  }
});

// ------------------------------------ GET ALL KOS ------------------------------------
app.get("/api/kos", async (req, res) => {
  try {
    const data = await Kos.find().populate("createdBy", "name email");
    res.json(data);
  } catch (err) {
    console.error("GET ALL KOS ERROR:", err);
    res.status(500).json({ message: "Gagal mengambil data kos" });
  }
});

// ------------------------------------ COMMENTS ------------------------------------
app.use("/api/comments", commentRoute);

// ------------------------------------ DELETE KOS ------------------------------------
app.delete("/api/kos/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.query;

    const kos = await Kos.findById(id);
    if (!kos)
      return res.status(404).json({ message: "Kos tidak ditemukan" });

    const isOwner = kos.createdBy.toString() === userId;

    if (!isOwner)
      return res.status(403).json({ message: "Tidak punya akses!" });

    await Kos.findByIdAndDelete(id);

    res.json({ message: "Kos berhasil dihapus!" });
  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: "Gagal menghapus kos" });
  }
});

// ------------------------------------ MONGO CONNECTION ------------------------------------
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB CONNECT ERROR:", err));

// ------------------------------------ START SERVER ------------------------------------
app.listen(PORT, () => console.log("Server berjalan di port", PORT));
