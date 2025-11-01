const express = require("express");
const app = express();
const path = require("path");
const mysql = require("mysql2");
const http = require("http");
const { Server } = require("socket.io");
const nodemailer = require("nodemailer");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const fs = require("fs");
require("dotenv").config();

const upload = multer({ dest: "uploads/" });
const port = 3000;
const server = http.createServer(app);
const io = new Server(server);

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "mayhem",
  password: "akhil2006",
});

io.on("connection", (socket) => {
  socket.on("sendMessage", (data) => {
    const { sender, receiver, message } = data;
    const checkQuery = "SELECT * FROM detail WHERE name = ?";
    connection.query(checkQuery, [receiver], (err, result) => {
      if (err) {
        socket.emit("errorMessage", "Database error while checking receiver.");
        return;
      }
      if (result.length === 0) {
        socket.emit("errorMessage", "Receiver not found in database!");
        return;
      }
      const q = "INSERT INTO message (sender, receiver, message) VALUES (?, ?, ?)";
      connection.query(q, [sender, receiver, message], (err2) => {
        if (err2) {
          socket.emit("errorMessage", "Failed to save message.");
          return;
        }
        io.emit("newMessage", { sender, receiver, message, timestamp: new Date() });
      });
    });
  });
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

app.get("/welcome", (req, res) => res.render("Landingpage"));

app.get("/signup", (req, res) => res.render("signuppage", { err: false }));

app.post("/signup", (req, res) => {
  const { name, mail, college, year, password } = req.body;
  const email = mail?.trim().toLowerCase();
  const q = "INSERT INTO detail(name, email, college, year, password) VALUES(?,?,?,?,?)";
  connection.query(q, [name, email, college, year, password], (err) => {
    if (err) return res.render("signuppage", { err: true });
    res.redirect("/login");
  });
});

app.get("/login", (req, res) => res.render("Loginpage", { err: false }));

app.post("/login", (req, res) => {
  const { email: rawEmail, password } = req.body;
  const email = rawEmail?.trim().toLowerCase();
  const q = "SELECT * FROM detail WHERE email = ?";
  connection.query(q, [email], (err, result) => {
    if (err || !result || result.length === 0) return res.render("Loginpage", { err: true });
    const user = result[0];
    if (user.password === password) {
      res.redirect(`/maindashboard?email=${encodeURIComponent(user.email)}`);
    } else {
      res.render("Loginpage", { err: true });
    }
  });
});

app.get("/maindashboard", (req, res) => {
  const email = req.query.email?.trim().toLowerCase();
  if (!email) return res.status(400).send("Email not provided");
  const q = "SELECT * FROM detail WHERE email = ?";
  connection.query(q, [email], (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(404).send("Profile not found");
    const profile = result[0];
    res.render("maindashboard", {
      name: profile.name,
      college: profile.college,
      email: profile.email,
    });
  });
});

app.get("/profile", (req, res) => {
  const email = req.query.email?.trim().toLowerCase();
  if (!email) return res.status(400).send("Email not provided");
  const q = "SELECT * FROM detail WHERE email = ?";0
  connection.query(q, [email], (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(404).send("Profile not found");
    const profile = result[0];
    res.render("profile", {
      name: profile.name,
      about: profile.about,
      gpa: profile.gpa,
      key: profile.courses,
      projects: profile.projects,
      skills: profile.skills,
      mail: profile.email,
      linkedin: profile.linkedin,
      github: profile.github,
    });
  });
});

app.get("/editprofile", (req, res) => {
  const email = req.query.email?.trim().toLowerCase();
  if (!email) return res.status(400).send("Email not provided");
  const q = "SELECT * FROM detail WHERE email = ?";
  connection.query(q, [email], (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(404).send("Profile not found");
    const profile = result[0];
    res.render("edit_profile", { profile });
  });
});

app.post("/editprofile", (req, res) => {
  const { name, about, gpa, key, projects, skills, linkedin, github } = req.body;
  const email = req.query.email?.trim().toLowerCase();
  if (!email) return res.status(400).send("Email not provided");
  const q = `
    UPDATE detail
    SET name = ?, about = ?, gpa = ?, courses = ?, projects = ?, skills = ?, linkedin = ?, github = ?
    WHERE email = ?
  `;
  connection.query(q, [name, about, gpa, key, projects, skills, linkedin, github, email], () => {
    res.redirect(`/maindashboard?email=${encodeURIComponent(email)}`);
  });
});

app.get("/createevent", (req, res) => res.render("createevent"));

app.post("/createevent", upload.single("image"), (req, res) => {
  try {
    const { name, date, time, location, description } = req.body;
    if (!req.file) return res.status(400).send("Image required");
    const image = fs.readFileSync(req.file.path);
    const q = "INSERT INTO events (name, date, time, location, description, image) VALUES (?, ?, ?, ?, ?, ?)";
    connection.query(q, [name, date, time, location, description, image], (err) => {
      fs.unlink(req.file.path, () => {});
      if (err) return res.status(500).send("Error saving event");
      res.redirect("/event");
    });
  } catch {
    res.status(500).send("Server error");
  }
});

app.get("/event-image/:id", (req, res) => {
  const q = "SELECT image FROM events WHERE id = ?";
  connection.query(q, [req.params.id], (err, results) => {
    if (err || !results || results.length === 0) return res.status(404).send("Image not found");
    res.contentType("image/jpeg");
    res.send(results[0].image);
  });
});

app.get("/event", (req, res) => {
  const today = new Date();
  const yyyy = today.getFullYear();
  const mm = String(today.getMonth() + 1).padStart(2, "0");
  const dd = String(today.getDate()).padStart(2, "0");
  const todayStr = `${yyyy}-${mm}-${dd}`;
  const q = "SELECT id, name, date, time, location, description FROM events WHERE date <= ?";
  connection.query(q, [todayStr], (err, results) => {
    if (err) return res.status(500).send(err);
    const cards = results.map((row) => ({ ...row, image: `/event-image/${row.id}` }));
    res.render("events", { cards });
  });
});

app.get("/forgotpassword", (req, res) => res.render("Forgotpassword", { stage: "email", err: false }));

app.post("/forgotpassword", (req, res) => {
  const rawEmail = req.body.email;
  const email = rawEmail?.trim().toLowerCase();
  if (!email) return res.render("Forgotpassword", { stage: "email", err: true });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiry = Date.now() + 5 * 60 * 1000;
  const q = "UPDATE detail SET otp = ?, otpExpiry = ? WHERE email = ?";
  connection.query(q, [otp, expiry, email], (err, result) => {
    if (err || !result || result.affectedRows === 0)
      return res.render("Forgotpassword", { stage: "email", err: true });
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    transporter.sendMail(
      {
        to: email,
        subject: "Campus Connect OTP",
        html: `Your OTP for password reset is: <b>${otp}</b>. Valid for 5 minutes.`,
      },
      (mailErr) => {
        if (mailErr) return res.render("Forgotpassword", { stage: "email", err: true });
        res.render("Forgotpassword", { stage: "otp", email, err: false });
      }
    );
  });
});

app.post("/verifyotp", (req, res) => {
  const { email: rawEmail, otp } = req.body;
  const email = rawEmail?.trim().toLowerCase();
  if (!email || !otp) return res.render("Forgotpassword", { stage: "otp", email, err: true });
  const q = "SELECT * FROM detail WHERE email = ? AND otp = ? AND otpExpiry > ?";
  connection.query(q, [email, otp, Date.now()], (err, result) => {
    if (err || !result || result.length === 0)
      return res.render("Forgotpassword", { stage: "otp", email, err: true });
    res.render("Forgotpassword", { stage: "reset", email, err: false });
  });
});

app.post("/resetpassword", (req, res) => {
  const { email: rawEmail, newPassword } = req.body;
  const email = rawEmail?.trim().toLowerCase();
  if (!email || !newPassword) return res.send("Missing fields");
  const q = "UPDATE detail SET password = ?, otp = NULL, otpExpiry = NULL WHERE email = ?";
  connection.query(q, [newPassword, email], (err) => {
    if (err) return res.send("Error updating password");
    res.send("Password updated successfully. You can now login.");
  });
});

app.get("/search", (req, res) => {
  const query = req.query.query?.trim();
  const email = req.query.email?.trim().toLowerCase();
  if (!query) return res.redirect(`/maindashboard?email=${encodeURIComponent(email)}`);
  const q = "SELECT * FROM detail WHERE name LIKE ?";
  connection.query(q, [`%${query}%`], (err, results) => {
    if (err) return res.status(500).send("Database error");
    res.render("searchresults", { results, email });
  });
});

app.get("/getcookies",(req,res) => {
  res.cookie("greet" , "namaste");
  res.cookie("Made in" , "India");
  res.send("Sent Some Cookies");
});

app.get("/",(req,res) => {
  console.dir(req.cookies);
  res.send("Hi,I am root");
});

app.get("/users",(req,res) => {
  let {name = "anonymous"} = req.cookies;
  res.send(`Hi , ${name}`);
})
server.listen(port, () => console.log(`Server running at http://localhost:${port}`));