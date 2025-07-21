const jwt = require("jsonwebtoken");
const User = require("../models/User");
require("dotenv/config");

const {JWT_SECRET} = process.env;

const authenticate = async (req, res, next) => {
  const authorization = req.get("authorization");
  if (!authorization) {
    return res.status(401).json({
      msg: "Authorization header missing"
    })
  }

  const [bearer, token] = authorization.split(" ");

  if (bearer !== "Bearer") {
    return res.status(401).json({
      msg: "Bearer missing"
    })
  };

  try {
    if (typeof JWT_SECRET !== "string") {
      return res.status(500).json({
        msg: "JWT_SECRET not found"
      })
    }
    const { id } = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(id);
    if (!user || !user.token || user.token !== token) {
      return res.status(500).json({
        msg: "User not found"
      })
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof Error) {
      return res.status(401).json({
        msg: error.message
      })
      throw HttpExeption(401, error.message);
    }
  }
};

module.exports = authenticate;
