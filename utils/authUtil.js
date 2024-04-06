const validator = require("validator");

const userDataValidation = ({ name, email, username, password }) => {
  return new Promise((resolve, reject) => {
    if (!name || !username || !email || !password)
      reject("Missing credentials");

    if (typeof name !== "string") reject("Name is not a string");
    if (typeof username !== "string") reject("username is not a string");
    if (typeof email !== "string") reject("email is not a string");
    if (typeof password !== "string") reject("password is not a string");

    if (username.length <= 2 || username.length > 20)
      reject("username length should be 3-20");

    if (password.length <= 2 || password.length > 20)
      reject("password length should be 3-20");

    // if (!validator.isAlphanumeric(password))
    //   reject("Password should contains a-z, A-Z and 0-9");
    if (!validator.isEmail(email)) reject("Email format is incorrect");

    resolve();
  });
};

module.exports = { userDataValidation };
