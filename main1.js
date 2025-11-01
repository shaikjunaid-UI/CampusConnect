require("dotenv").config();
const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const http = require("http");
const { Server } = require("socket.io");
const nodemailer = require("nodemailer");
const Detail = require("./modules/data");
const Event = require("./modules/event");
const Message = require("./modules/message");

const app = express();
const upload = multer({ dest: "uploads/" });
const port = process.env.PORT || 8080;
const mongoUrl = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/campusconnect";

mongoose.connect(mongoUrl).then(() => console.log("MongoDB Connected")).catch(err => console.log(err));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(session({ secret: process.env.SESSION_SECRET || "campusconnectsecret", resave: false, saveUninitialized: true }));

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.get("/welcome", (req, res) => res.render("Landingpage"));
app.get("/signup", (req, res) => res.render("signuppage", { err: false }));

app.post("/signup", async (req, res) => {
  try {
    const body = req.body.detail || req.body;
    const name = body.name?.trim();
    const email = body.email?.toLowerCase().trim();
    const password = body.password;
    const college = body.college?.trim();
    const year = body.year?.trim();
    if (!name || !email || !password || !college || !year) return res.render("signuppage", { err: "All fields are required" });
    const existing = await Detail.findOne({ mail: email });
    if (existing) return res.render("signuppage", { err: "Email already exists" });
    const user = new Detail({ name, mail: email, password, college, year });
    await user.save();
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.render("signuppage", { err: "Something went wrong" });
  }
});

app.get("/login", (req, res) => res.render("Loginpage"));

app.post("/login", async (req, res) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const password = req.body.password;
    const user = await Detail.findOne({ mail: email });
    if (!user || user.password !== password) return res.render("Loginpage", { err: "Invalid email or password" });
    req.session.userId = user._id;
    res.redirect("/MainDashboard");
  } catch (err) {
    console.error(err);
    res.render("Loginpage", { err: "Something went wrong" });
  }
});

app.get("/forgotpassword", (req, res) => res.render("Forgotpassword", { stage: "email", err: false }));

app.post("/forgotpassword", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    if (!email) return res.render("Forgotpassword", { stage: "email", err: true });
    const user = await Detail.findOne({ mail: email });
    if (!user) return res.render("Forgotpassword", { stage: "email", err: true });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5 * 60 * 1000;
    user.otp = otp;
    user.otpExpiry = expiry;
    await user.save();
    await transporter.sendMail({
      to: email,
      subject: "Campus Connect OTP",
      html: `Your OTP for password reset is: <b>${otp}</b>. Valid for 5 minutes.`,
    });
    res.render("Forgotpassword", { stage: "otp", email, err: false });
  } catch (err) {
    console.error(err);
    res.render("Forgotpassword", { stage: "email", err: true });
  }
});

app.post("/verifyotp", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const otp = req.body.otp;
    if (!email || !otp) return res.render("Forgotpassword", { stage: "otp", email, err: true });
    const user = await Detail.findOne({ mail: email, otp, otpExpiry: { $gt: Date.now() } });
    if (!user) return res.render("Forgotpassword", { stage: "otp", email, err: true });
    res.render("Forgotpassword", { stage: "reset", email, err: false });
  } catch (err) {
    console.error(err);
    res.render("Forgotpassword", { stage: "otp", email: req.body.email, err: true });
  }
});

app.post("/resetpassword", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const newPassword = req.body.newPassword;
    if (!email || !newPassword) return res.send("Missing fields");
    const user = await Detail.findOne({ mail: email });
    if (!user) return res.send("Email not found");
    user.password = newPassword;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();
    res.send("Password updated successfully. You can now login.");
  } catch (err) {
    console.error(err);
    res.send("Error updating password");
  }
});

app.get("/MainDashboard", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  const detail = await Detail.findById(req.session.userId);
  if (!detail) return res.redirect("/login");
  res.render("MainDashboard", { detail });
});

app.get("/profile/:id", async (req, res) => {
  const detail = await Detail.findById(req.params.id);
  if (!detail) return res.redirect("/MainDashboard");
  res.render("profile", { detail });
});

app.get("/search", async (req, res) => {
  const name = req.query.name || "";
  const results = await Detail.find({ name: { $regex: name, $options: "i" } });
  res.render("searchresults", { results });
});

app.get("/publicprofile/:id", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  const profile = await Detail.findById(req.params.id);
  const currentUser = await Detail.findById(req.session.userId);
  if (!profile) return res.redirect("/MainDashboard");
  const isConnected = (currentUser.following || []).includes(profile._id.toString());
  res.render("publicprofile", { profile, currentUserId: currentUser._id.toString(), isConnected });
});

app.post("/connect/:id", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  const profileId = req.params.id;
  const currentUserId = req.session.userId;
  await Detail.findByIdAndUpdate(currentUserId, { $addToSet: { following: profileId } });
  await Detail.findByIdAndUpdate(profileId, { $addToSet: { followers: currentUserId } });
  res.redirect(`/publicprofile/${profileId}`);
});

app.get("/editprofile/:id", async (req, res) => {
  const id = req.params.id;
  if (!req.session.userId) return res.redirect("/login");
  const detail = await Detail.findById(id);
  if (!detail) return res.redirect("/MainDashboard");
  res.render("edit_profile", { detail });
});

app.post("/editprofile/:id", async (req, res) => {
  await Detail.findByIdAndUpdate(req.params.id, req.body.detail || req.body, { new: true });
  res.redirect("/MainDashboard");
});

app.get("/events", (req, res) => res.render("events"));
app.get("/createevent", (req, res) => res.render("createevent"));
app.post("/createevent", async (req, res) => {
  const event = new Event(req.body.event || req.body);
  await event.save();
  res.redirect("/events");
});

app.get("/chat", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  const currentUser = await Detail.findById(req.session.userId);
  const contacts = await Detail.find({ _id: { $ne: currentUser._id } });
  res.render("chat_home", { currentUser, contacts });
});

app.get("/chat/:id", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  const receiverId = req.params.id;
  const currentUser = await Detail.findById(req.session.userId);
  const receiver = await Detail.findById(receiverId);
  const contacts = await Detail.find({ _id: { $ne: currentUser._id } });
  const messages = await Message.find({
    $or: [
      { sender: currentUser._id.toString(), receiver: receiverId },
      { sender: receiverId, receiver: currentUser._id.toString() }
    ]
  }).sort({ timestamp: 1 });
  res.render("chat", { currentUser, receiver, contacts, messages });
});

const server = http.createServer(app);
const io = new Server(server);
const connectedUsers = new Map();

io.on("connection", (socket) => {
  socket.on("join", (userId) => { if (userId) connectedUsers.set(userId, socket.id); });
  socket.on("private message", async ({ senderId, receiverId, message }) => {
    const newMsg = new Message({ sender: senderId, receiver: receiverId, message });
    await newMsg.save();
    const sender = await Detail.findById(senderId);
    const receiverSocket = connectedUsers.get(receiverId);
    const data = { from: sender.name, message, fromId: senderId };
    if (receiverSocket) io.to(receiverSocket).emit("private message", data);
    io.to(socket.id).emit("private message", data);
  });
  socket.on("disconnect", () => {
    for (const [id, sid] of connectedUsers.entries()) {
      if (sid === socket.id) connectedUsers.delete(id);
    }
  });
});

server.listen(port, () => console.log(`Server running on port ${port}`));
