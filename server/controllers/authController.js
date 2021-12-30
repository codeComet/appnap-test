const passport = require("passport");
const bcryptjs = require("bcryptjs");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require("jsonwebtoken");
const JWT_KEY = "jwtactive987";
const JWT_RESET_KEY = "jwtreset987";

//------------ User Model ------------//
const User = require("../models/User");

//------------ Register Handle ------------//
exports.registerHandle = (req, res) => {
  const { fullname, username, email, password, password2, dob } = req.body;
  let errors = [];

  //------------ Checking required fields ------------//
  if (!fullname || !username || !email || !password || !password2 || !dob) {
    errors.push({ msg: "Please enter all fields" });
  }

  //------------ Checking password mismatch ------------//
  if (password != password2) {
    errors.push({ msg: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", {
      errors,
      username,
      fullname,
      email,
      password,
      password2,
      dob,
    });
  } else {
    //------------ Validation passed ------------//
    User.findOne({ username }).then((user) => {
      if (user) {
        //------------ User already exists ------------//
        errors.push({ msg: "User name is already registered" });
        res.render("register", {
          errors,
          username,
          fullname,
          email,
          password,
          password2,
          dob,
        });
      } else {
        const oauth2Client = new OAuth2(
          "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com", // ClientID
          "OKXIYR14wBB_zumf30EC__iJ", // Client Secret
          "https://developers.google.com/oauthplayground" // Redirect URL
        );

        oauth2Client.setCredentials({
          refresh_token:
            "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
        });
        const accessToken = oauth2Client.getAccessToken();

        const token = jwt.sign(
          { username, fullname, dob, email, password },
          JWT_KEY,
          { expiresIn: "30m" }
        );
        const CLIENT_URL = "http://" + req.headers.host;

        const output = `
                <h2>Please click on below link to activate your account</h2>
                <a href=${CLIENT_URL}/auth/activate/${token}>Verify</a>
                <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
                `;

        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            type: "OAuth2",
            user: "nodejsa@gmail.com",
            clientId:
              "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com",
            clientSecret: "OKXIYR14wBB_zumf30EC__iJ",
            refreshToken:
              "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
            accessToken: accessToken,
          },
        });

        // send mail with defined transport object
        const mailOptions = {
          from: '"Auth Admin" <nodejsa@gmail.com>', // sender address
          to: email, // list of receivers
          subject: "Account Verification", // Subject line
          generateTextFromHTML: true,
          html: output, // html body
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.log(error);
            req.flash(
              "error_msg",
              "Something went wrong on our end. Please register again."
            );
            res.redirect("/auth/login");
          } else {
            console.log("Mail sent : %s", info.response);
            req.flash(
              "success_msg",
              "Activation link sent to email ID. Please activate to log in."
            );
            res.redirect("/auth/login");
          }
        });
      }
    });
  }
};

//------------ Activate Account Handle ------------//
exports.activateHandle = (req, res) => {
  const token = req.params.token;
  let errors = [];
  if (token) {
    jwt.verify(token, JWT_KEY, (err, decodedToken) => {
      if (err) {
        req.flash(
          "error_msg",
          "Incorrect or expired link! Please register again."
        );
        res.redirect("/auth/register");
      } else {
        const { username, fullname, email, password, dob } = decodedToken;
        User.findOne({ username: username }).then((user) => {
          if (user) {
            //------------ User already exists ------------//
            req.flash(
              "error_msg",
              "User ID already registered! Please log in."
            );
            res.redirect("/auth/login");
          } else {
            const newUser = new User({
              username,
              fullname,
              email,
              password,
              dob,
            });

            bcryptjs.genSalt(10, (err, salt) => {
              bcryptjs.hash(newUser.password, salt, (err, hash) => {
                if (err) throw err;
                newUser.password = hash;
                newUser
                  .save()
                  .then((user) => {
                    req.flash(
                      "success_msg",
                      "Account activated. You can now log in."
                    );
                    res.redirect("/auth/login");
                  })
                  .catch((err) => console.log(err));
              });
            });
          }
        });
      }
    });
  } else {
    console.log("Account activation error!");
  }
};

//------------ Forgot Password Handle ------------//
exports.forgotPassword = (req, res) => {
  const { username } = req.body;

  let errors = [];

  //------------ Checking required fields ------------//
  if (!username) {
    errors.push({ msg: "Please enter your username" });
  }

  if (errors.length > 0) {
    res.render("forgot", {
      errors,
      username,
    });
  } else {
    User.findOne({ username: username }).then((user) => {
      if (!user) {
        //------------ User already exists ------------//
        errors.push({ msg: "User with username does not exist!" });
        res.render("forgot", {
          errors,
          username,
        });
      } else {
        console.log("user", user);
        const oauth2Client = new OAuth2(
          "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com", // ClientID
          "OKXIYR14wBB_zumf30EC__iJ", // Client Secret
          "https://developers.google.com/oauthplayground" // Redirect URL
        );

        oauth2Client.setCredentials({
          refresh_token:
            "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
        });
        const accessToken = oauth2Client.getAccessToken();

        const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, {
          expiresIn: "30m",
        });
        const CLIENT_URL = "http://" + req.headers.host;
        const output = `
                <h2>Please click on below link to reset your account password</h2>
                <a href=${CLIENT_URL}/auth/forgot/${token}>Click here</a>
                <p><b>NOTE: </b> The activation link expires in 30 minutes.</p>
                `;

        User.updateOne({ resetLink: token }, (err, success) => {
          if (err) {
            errors.push({ msg: "Error resetting password!" });
            res.render("forgot", {
              errors,
              email,
            });
          } else {
            const transporter = nodemailer.createTransport({
              service: "gmail",
              auth: {
                type: "OAuth2",
                user: "nodejsa@gmail.com",
                clientId:
                  "173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com",
                clientSecret: "OKXIYR14wBB_zumf30EC__iJ",
                refreshToken:
                  "1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w",
                accessToken: accessToken,
              },
            });

            // send mail with defined transport object
            const mailOptions = {
              from: '"Auth Admin" <nodejsa@gmail.com>', // sender address
              to: user.email, // list of receivers
              subject: "Account Password Reset", // Subject line
              html: output, // html body
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.log(error);
                req.flash(
                  "error_msg",
                  "Something went wrong on our end. Please try again later."
                );
                res.redirect("/auth/forgot");
              } else {
                console.log("Mail sent : %s", info.response);
                req.flash(
                  "success_msg",
                  "Password reset link sent to email corresponing with this username. Please check your email."
                );
                res.redirect("/auth/login");
              }
            });
          }
        });
      }
    });
  }
};

//------------ Redirect to Reset Handle ------------//
exports.gotoReset = (req, res) => {
  const { token } = req.params;

  if (token) {
    jwt.verify(token, JWT_RESET_KEY, (err, decodedToken) => {
      if (err) {
        req.flash("error_msg", "Incorrect or expired link! Please try again.");
        res.redirect("/auth/login");
      } else {
        const { _id } = decodedToken;
        User.findById(_id, (err, user) => {
          if (err) {
            req.flash(
              "error_msg",
              "User with email ID does not exist! Please try again."
            );
            res.redirect("/auth/login");
          } else {
            res.redirect(`/auth/reset/${_id}`);
          }
        });
      }
    });
  } else {
    console.log("Password reset error!");
  }
};

exports.resetPassword = (req, res) => {
  var { password, password2 } = req.body;
  const id = req.params.id;
  let errors = [];

  //------------ Checking required fields ------------//
  if (!password || !password2) {
    req.flash("error_msg", "Please enter all fields.");
    res.redirect(`/auth/reset/${id}`);
  }

  //------------ Checking password mismatch ------------//
  else if (password != password2) {
    req.flash("error_msg", "Passwords do not match.");
    res.redirect(`/auth/reset/${id}`);
  } else {
    bcryptjs.genSalt(10, (err, salt) => {
      bcryptjs.hash(password, salt, (err, hash) => {
        if (err) throw err;
        password = hash;

        User.findByIdAndUpdate(
          { _id: id },
          { password },
          function (err, result) {
            if (err) {
              req.flash("error_msg", "Error resetting password!");
              res.redirect(`/auth/reset/${id}`);
            } else {
              req.flash("success_msg", "Password reset successfully!");
              res.redirect("/auth/login");
            }
          }
        );
      });
    });
  }
};

//------------ Login Handle ------------//
exports.loginHandle = (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/auth/login",
    failureFlash: true,
  })(req, res, next);
};

//------------ Logout Handle ------------//
exports.logoutHandle = (req, res) => {
  req.logout();
  req.flash("success_msg", "You are logged out");
  res.redirect("/auth/login");
};
