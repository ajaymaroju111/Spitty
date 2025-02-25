const jwt = require('jsonwebtoken');
const dotenv = require('dotenv').config();
const crypto = require('crypto');


//to generate a token based on mail id and user id : 
function generateAccessToken(user) {
  try {
    const payload = {
      id: user._id,
      email: user.email
    };
    
    const secret = process.env.JWT_KEY;
    const options = { expiresIn: '1h' };
    return jwt.sign(payload, secret, options);
  } catch (error) {
    console.log(` token creation error : ${error}`)
  }
 
}

//verify and access token from the user : 

function verifyAccessToken(token) {
  const secret = process.env.JWT_KEY;
  try {
    const decoded = jwt.verify(token, secret);
    return { success: true, data: decoded };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

//verifying token for the Authentication : 

const authMiddleware = (req, res, next) => {
  // Get token from the Authorization header
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify the token : 
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach user data to the request
    req.json({success : "ctoken verifies successfully : "})
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

//verifying token passing a token : 
const customEncrypt = function (text) {
  const algorithm = 'aes-256-cbc';  // AES encryption with CBC mode
  const key = Buffer.alloc(32, 0);  // 32-byte key (AES-256)
  const iv = Buffer.alloc(16, 0);   // 16-byte IV

  // Create cipher
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  // Encrypt the text
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');  // Append final encrypted block

  return encrypted;  // Return encrypted string in hex format
};

//using token with cookies for advance Authentication : 

const usingTokenWithCookie = (res, user) =>{
  try {
    const payload = {
      id: user._id,
      email: user.email,
    }
    const secret = process.env.JWT_KEY;
    const expiryTime = {expiresIn: '1h'}
    jwt.sign(payload , secret , expiryTime);
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: true, // Use only in HTTPS
      sameSite: "Strict",
    });
    res.json({ message: "Logged in" });
  } catch (error) {
    
  }
}

//verifying cookie using cookie in it : 

const VerifyTokenWithCookie = async(req , res) =>{
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const user = jwt.verify(token, `${process.env.JWT_KEY}`);
    res.json({ message: "protected data", user });
  } catch (error) {
    res.status(403).json({ error: "Invalid token" });
  }

}






module.exports = {generateAccessToken , verifyAccessToken, authMiddleware , customEncrypt , VerifyTokenWithCookie , usingTokenWithCookie };