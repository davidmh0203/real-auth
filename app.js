
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./mysql");
const path = require("path");

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: "secret-key",
  resave: false,
  saveUninitialized: false
}));
app.use(express.static(path.join(__dirname, "pyramid_JS")));

function authCheck(req, res, next) {
  if (!req.session.userId) return res.redirect("/login.html");
  next();
}

app.get("/", authCheck, (req, res) => {
  res.sendFile(path.join(__dirname, "pyramid_JS", "index.html"));
});

app.post("/users", async (req, res) => {
  const { id, pw } = req.body;
  if (!id || !pw) return res.status(400).json({ msg: "id, pw required" });

  try {
    const hashedPw = await bcrypt.hash(pw, 10);
    db.query("INSERT INTO user (id, pw) VALUES (?, ?)", [id, hashedPw], (err) => {
      if (err && err.code === "ER_DUP_ENTRY")
        return res.status(409).json({ msg: "id exists" });
      if (err) return res.status(500).json({ msg: "db error" });
      res.json({ msg: "saved" });
    });
  } catch (err) {
    res.status(500).json({ msg: "hash error" });
  }
});

app.post("/login", (req, res) => {
  const { id, pw } = req.body;
  if (!id || !pw) return res.status(400).json({ msg: "id, pw required" });

  db.query("SELECT * FROM user WHERE id = ?", [id], async (err, rows) => {
    if (err) return res.status(500).json({ msg: "db error" });
    if (rows.length === 0) return res.status(400).json({ msg: "id not found" });

    const user = rows[0];
    const match = await bcrypt.compare(pw, user.pw);
    if (!match) return res.status(401).json({ msg: "wrong password" });

    req.session.userId = user.id;
    req.session.userNo = user.user_no;
    res.redirect("/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

app.get("/db", (_, res) => {
  db.query("SELECT * FROM user", (err, rows) => {
    if (err) return res.status(500).json({ msg: "db error" });
    res.json(rows);
  });
});

app.listen(port, () => console.log(`http://localhost:${port}`));
