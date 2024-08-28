require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

let refreshTokens = [];

// refresh token
app.post("/token", (req, res) => {
  const refreshtoken = req.body.token;
  if (refreshtoken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshtoken)) return res.sendStatus(403);

  jwt.verify(refreshtoken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

// Delete request
app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  if (refreshTokens.includes(req.body.token)) {
    return res.send("token not deleted");
  }
  res.status(204).send("Refresh token deleted, item secured");
});

// login request
app.post("/login", (req, res) => {
  const name = req.body.name;
  const user = { name: name };

  const accessToken = generateToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

// lets create the token using its own function
function generateToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "30s" });
}

// middleware to authenticate using our accesstoken
function authenticate(req, res, next) {
  const accesstoken = req.headers["authorization"];
  const token = accesstoken && accesstoken.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
app.listen(4000, (err) => {
  if (err) return err;
  console.log("listening on port 4000...");
});
