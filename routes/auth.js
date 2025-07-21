const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/User");

const authenticate = require("../middlewares/authenticate");

const router = express.Router();

// Регистрация пользователя
router.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(409).json({ msg: "User already exist" });
    }

    user = new User({
      email,
      password,
    });

    await user.save();

    const payload = {
      id: user._id,
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET, // Замените на ваш секретный ключ
      { expiresIn: "24h" }
    );
    user.token = token;
    await user.save();

    res.status(201).json({
      token,
      user: {
        email
      }
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Авторизация пользователя
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    const payload = {
      id: user._id,
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET, // Замените на ваш секретный ключ
      { expiresIn: "24h" }
    );
    user.token = token;
    await user.save();

    res.json({
      token,
      user: {
        email
      }
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// получение текущего пользователя
router.get("/current", authenticate, async (req, res) => {
  const { email } = req.user;
  res.json({
    email,
  });
});

router.post("/logout", authenticate, async(req, res)=> {
  await User.findByIdAndUpdate(req.user._id, {token: ""});
  res.json({
    msg: "Logout success"
  })
})

router.delete("/user", async(req, res)=> {
  try {
    const {email} = req.body;
    await User.findOneAndDelete({email});
    res.status(204).send();
  }
  catch(error) {
    res.status(404).json({
      msg: `${req.body.email} not found`
    })
  }
})

module.exports = router;
