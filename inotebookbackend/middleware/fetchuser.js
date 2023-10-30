const jwt = require("jsonwebtoken");
const JWT_SECRET = "viratkohliisking";

const fetchuser = (req, res, next) => {
  //Get the user from jwt token and add id to the req object
  const token = req.header("authToken");
  if (!token) {
    return res
      .status(401)
      .send({ error: "Please Authenticate Using Valid Token" });
  }
  const data = jwt.verify(token, JWT_SECRET);
  req.user = data.user;
  next();
};

module.exports = fetchuser;
