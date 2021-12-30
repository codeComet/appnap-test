const express = require("express");
const router = express.Router();
const { ensureAuthenticated } = require("../config/checkAuth");

//------------ Welcome Route ------------//
router.get("/", (req, res) => {
  res.render("welcome");
});

//------------ Dashboard Route ------------//
router.get("/dashboard", ensureAuthenticated, (req, res) =>
  res.render("dash", {
    username: req.user.username,
  })
);

module.exports = router;
