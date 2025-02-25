const bcrypt = require("bcrypt");
const User = require("../Models/User.js");
const student = require("../Models/student.js");
const {
  SendVerificationCode,
  resetPasswordLink,
} = require("../Middlewares/Email.js");
const crypto = require("crypto");
const multer = require("multer");
const dotenv = require("dotenv").config();
const loginData = require("../Models/loginAuth.js");
const {
  generateAccessToken,
  verifyAccessToken,
  customEncrypt,
  usingTokenWithCookie,
  VerifyTokenWithCookie,
} = require("../Middlewares/Token.js");

//user registration :
const userRegister = async (req, res) => {
  try {
    const {
      firstname,
      middlename,
      lastname,
      role,
      email,
      password,
      mobile,
      city,
      state,
      district,
      pincode,
      registerotp,
      expiryTime,
      loginotp,
      resetPasswordToken,
      image,
    } = req.body;

    //check weather the user exist or not in the database :
    const isMailexist = await User.findOne({ email });
    if (isMailexist) {
      return res.json({
        message: "Email is already taken",
      });
    }

    //hashing the incommimg password :
    // const hashedPassword = await hashingTool(password);
    const hashedPassword = await bcrypt.hash(password, 10);

    //create a new user with hashed password :
    const user = await User.create({
      firstname,
      middlename,
      lastname,
      role,
      email,
      password: hashedPassword,
      mobile,
      city,
      state,
      district,
      pincode,
      registerotp,
      expiryTime,
      loginotp,
      resetPasswordToken,
      image,
    });
    await user.save();
    const otpVal = Math.floor(100000 + Math.random() * 900000).toString();
    await SendVerificationCode(user.email, otpVal);
    user.expiryTime = Date.now() + 10 * 60 * 1000;
    const hashedotp = (await bcrypt.hash(otpVal, 10)).toString();
    user.registerotp = hashedotp;
    await user.save();
    res.json({ message: "otp sent to the registered email" });
  } catch (error) {
    res.json({ error: `registration error ${error}` });
  }
};

// user registration verification using OTP :
const isvalidate = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    //caluclate the expiry time :
    if (Date.now() > user.expiryTime) {
      res.json({ message: "OTP time expired please try again" });
    }
    //find the duplicate emails in Db :
    if (!user) {
      return res.json({ message: "No user found please register" });
    }
    //check for the Duplicates :
    if (user.length > 1) {
      return console.log(`Duplicates found on the ${email}`);
    }
    //compare the passwords :
    const valid = await bcrypt.compare(otp, user.registerotp);
    if (!valid) {
      res.json({ message: "OTP does not match" });
    }
    user.status = "active";
    user.save();
    return res.json({ success: "user verified Successfully!!" });
  } catch (error) {
    res.json({ error: `validation error : ${error}` });
  }
};

// method-1 : User login authentication :
const userLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!email) {
      res.json({ error: "please enter the email ID" });
    }
    if (!password) {
      res.json({ error: "please enter the Password" });
    }
    if (!user) {
      return res.json({ message: "user not found please register" });
    }
    if (user.length > 1) {
      return res.json({ message: "Duplicates found on the user" });
    }
    const isPasswordMatch = bcrypt.compare(user.password, password);
    if (!isPasswordMatch) {
      return res.json({
        message: "password does not match",
      });
    }
    //create a token :
    const token = generateAccessToken(user);
    //update the token in the database :
    await loginData.create({
      userId: user._id,
      token: token,
      expiriryDate: Date.now(),
    });
    await loginData.save();
    const verified = verifyAccessToken(token);
    if (!verified) {
      res.json({ error: "internal server error" });
    }
    customEncrypt(token);
    const Regotp = Math.floor(100000 + Math.random() * 900000).toString();
    await SendVerificationCode(user.email, Regotp);
    user.loginotp = Regotp;
    user.save();
    res.json({ message: "otp is send to the mail please verify to login" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

//method-2 : login authentication using token and cookies :
const userLoginUsingEmailAndPassword = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email) {
      res.json({ error: "email is requires for login" });
    }
    if (!password) {
      res.json({ error: "password is required for login" });
    }
    const user = await User.findOne({ email });
    if (user.length > 1) {
      res.json({ error: "Duplicate Accounts found" });
    }
    if (!user) {
      res.json({ message: "user does not exist" });
    }
    //sending an OTP after successfull credentials :
    const LoginOTP = Math.floor(100000 + Math.random() * 900000).toString();
    await SendVerificationCode(user.email, LoginOTP);
    user.expiryTime = Date.now() + 10 * 60 * 1000;
    await user.save();
    const hashedotp = (await bcrypt.hash(LoginOTP, 10)).toString();
    user.loginotp = hashedotp;
    await user.save();
    res.json({ message: "OTP Send to the email please check!" });
  } catch (error) {
    res.json({ loginError: error });
  }
};

// method - 1 = login validation using OTP :
const LoginValidated = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    const isOk = await bcrypt.compare(otp , user.registerotp);
    if (!isOk) {
      res.json({ error: "invalid OTP" });
    }
    res.json({ message: "OTP Verified Successfully" });
  } catch (error) {
    res.json({ error: `registration otp validation error : ${error}` });
  }
};

//method - 2 = login  validation using OTP and creating a token wrapping it inside a cookie :
const OtpValUsingTokenandCookie = async (req, res) => {
  const { email, OTP } = req.body;
  try {
    if (!email) {
      res.json({ error: "email is required for the login!" });
    }
    if (!OTP) {
      res.json({ error: "otp is required for the login" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      res.json({ error: "user does not exist" });
    }
    const isOTP = await bcrypt.compare(OTP, user.loginotp);
    if (!isOTP) {
      res.json({ invalid: "OTP invalid please try again" });
    }
    if (Date.now() > user.expiryTime) {
      res.json({ timeExpired: "OTP time expired please try again" });
    }
    const token = usingTokenWithCookie(res, user);
    await loginData.create({ userId: user._id, token: token, expiriryDate });
    await loginData.save();
    res.json({ seccess: "user login successfully completed" });
  } catch (error) {
    console.log(error);
    res.json({ loginError: `${error}` });
  }
};

const verifyToken = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token)
    return res
      .status(401)
      .json({ message: "Access Denied! No token provided." });

  try {
    const verifiedUser = jwt.verify(token.split(" ")[1], process.env.JWT_KEY); // Extract Bearer Token
    req.user = verifiedUser; // Attach user data to request
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid Token" });
  }
};

//verifying a cookie by decoding token inside it and matching it :
const VerifyingTokenWithCookie = async (req, res) => {
  try {
    const isVerified = await VerifyTokenWithCookie();
    if (!isVerified) {
      res.json({ error: "cookies mismatch" });
    }
  } catch (error) {
    res.json({ error: `${error}` });
  }
};

//logout using collapsing cookies  :
const LogOutUsingCookie = (req, res) => {
  res.clearCookie("authToken");
  res.json({ message: "Logged out" });
};

//forget password for user during login using a random text generation :
const forgetPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.json({ error: "user doesnot found" });
    }
    //generate a random token :
    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetPasswordToken = resetToken;
    user.expiryTime = Date.now() + 3600000; // 1 hour expiration
    await user.save();
    await resetPasswordLink(user.email, resetToken);
    res.json({ message: "Password reset email sent" });
  } catch (error) {
    res.json({ error: `${error}` });
  }
};

//forget password for user  login using a frontent link generation : this is only one way process
const forgetPasswordUsingEmailandId = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.json({ error: "user doesnot found" });
    }
    //generate a random token :
    const resetToken = `${process.env.FRONTEND_URL}/reset-password/${user._id}/${user.email}`;
    user.expiryTime = Date.now() + 3600000; // 1 hour expiration
    await user.save();
    await resetPasswordLink(user.email, resetToken);
    res.json({ message: "Password reset email sent" });
  } catch (error) {
    res.json({ error: `${error}` });
  }
};

//verify the token that has send to the mail :
const verifyEmailToken = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  const user = await User.findOne({ token });
  if (!user) {
    return res.status(400).json({ message: "user doesnot exist" });
  }
  if (Date.now() > user.expiryTime) {
    return res.status(450).json({ error: " token session expired" });
  }
  // Hash the new password :
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(password, salt);
  user.resetPasswordToken = undefined;
  user.expiryTime = undefined;
  await user.save();
  res.json({ message: "Password reset successful" });
};

//change password using token :
const ChagePasswordUsingToken = async (req, res) => {
  const token = req.header("x-token");

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    if (!decoded || !decoded.user) {
      return res.status(401).json({ message: "Invalid token structure" });
    }
    req.user = decoded.user; // Ensure req.user is properly set
    updatePasswordUsingOldPassword(req, res, decoded);
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

//update password using old and new password :
const updatePasswordUsingOldPassword = async (req, res, user) => {
  const { oldpassword, newpassword } = req.body;
  try {
    if (!oldpassword || !newpassword) {
      return res.json({
        error: "both old password and new passwords are required",
      });
    }
    const isOldPass = await bcrypt.compare(oldpassword, user.password);
    if (!isOldPass) {
      return res.json({ error: "old password is incorrect please try again" });
    }
    const newPass = bcrypt.hash(newpassword, 12);
    user.password = newPass;
    user.save();
    res.json({ data: user });
  } catch (error) {
    res.json({ updatingPassword: error });
  }
};

//authenticating user using token passing in headers for before uploading image to the data basse : 

const verifyTheToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "Access Denied" });
    try {
        const verified = jwt.verify(token, process.env.JWT_KEY);
        req.user = verified; // Attach user data to request
        res.json({message : "user accessed"});
    } catch (err) {
        res.status(400).json({ message: "Invalid Token" });
    }
};




//upload data along with image and process it using multer :
const ImageUploadWithMulter = async(req, res ) => {
    try {
        if (!req.file) return res.status(400).json({ message: "No file uploaded" });

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found" });

        user.image = req.file.path; // Save file path in DB
        await user.save();

        res.status(200).json({ message: "Image uploaded successfully", imagePath: req.file.path });
    } catch (error) {
        res.status(500).json({ message: "Server error", error });
    }
};

module.exports = {
  userRegister,
  isvalidate,
  userLogin,
  LoginValidated,
  VerifyingTokenWithCookie,
  OtpValUsingTokenandCookie,
  userLoginUsingEmailAndPassword,
  LogOutUsingCookie,
  forgetPassword,
  verifyEmailToken,
  forgetPasswordUsingEmailandId,
  verifyToken,
  ChagePasswordUsingToken,
  ImageUploadWithMulter,
  verifyTheToken,
};                          
