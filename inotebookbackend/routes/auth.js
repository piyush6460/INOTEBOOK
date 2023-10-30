const express = require("express");
const User = require("../models/User");
const router = express.Router();
const { body, validationResult } = require("express-validator");
const fetchuser = require("../middleware/fetchuser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "viratkohliisking";

//ROUTE 1: Create a User using : POST "/api/auth/createuser". No Login Required.

router.post(
  "/createuser",
  [
    body("name", "Enter A Valid Name.").isLength({ min: 2 }),
    body("email", "Enter A Valid Email.").isEmail(),
    body("password", "Password Must Contain Atleast 5 Characters.").isLength({
      min: 5,
    }),
  ],
  async (req, res) => {
    let success = false;
    //If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success, errors: errors.array() });
    }

    try {
      // Check weather the User with this email exists already
      let user = await User.findOne({ email: req.body.email });
      if (user) {
        return res.status(400).json({
          success,
          error: "User With This Email Address Already Exists!",
        });
      }
      const salt = await bcrypt.genSalt(10);
      const secPass = await bcrypt.hash(req.body.password, salt);

      //create a new user
      user = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: secPass,
      });
      const data = {
        user: user.id,
      };
      const authToken = jwt.sign(data, JWT_SECRET);
      success = true;
      res.json({ success, authToken });
    } catch (error) {
      console.error(error.message);
      res.status(500).send(success, "Ineternal Server Error");
    }
  }
);

//ROUTE 2: Authenticate User using : POST "/api/auth/login". No login Required.
router.post(
  "/login",
  [
    body("email", "Enter A Valid Email.").isEmail(),
    body("password", "Password cannot be blank.").exists(),
  ],
  async (req, res) => {
    let success = false;
    //If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success, errors: errors.array() });
    }
    const { email, password } = req.body;
    try {
      let user = await User.findOne({ email });
      if (!user) {
        return res
          .status(400)
          .json({ success, error: "Please Try Correct Login Credentials" });
      }
      const passwordCompare = await bcrypt.compare(password, user.password);
      if (!passwordCompare) {
        return res
          .status(400)
          .json({ success, error: "Please Try Correct Login Credentials" });
      }
      const data = {
        user: user.id,
      };
      const authToken = jwt.sign(data, JWT_SECRET);
      success = true;
      res.json({ success, authToken });
    } catch (error) {
      // console.error(error.message);
      res
        .status(500)
        .send({ success, error: "Please Try Correct Login Credentials" });
    }
  }
);

//ROUTE 3: Get Loggedin User details using : POST "/api/auth/getuser". Login Required.
router.post("/getuser", fetchuser, async (req, res) => {
  try {
    const userId = req.user;
    const user = await User.findById(userId).select("-password");

    res.json(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Ineternal Server Error");
  }
});

module.exports = router;
