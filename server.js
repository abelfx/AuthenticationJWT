require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
const blogs = [
  {
    name: "john",
    blog: "this is it",
  },
  {
    name: "mary",
    blog: "this is not it",
  },
];

app.get("/blog", authenticate, (req, res) => {
  const blog = blogs.find((blog) => blog.name === req.user.name);
  if (blog == null) return res.sendStatus(401);
  res.send(blog);
});

app.post("/login", (req, res) => {
  const name = req.body.name;
  const user = { name: name };

  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  res.json({ accessToken: accessToken });
});

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
app.listen(3000, (err) => {
  if (err) return err;
  console.log("listening on port 3000...");
});
