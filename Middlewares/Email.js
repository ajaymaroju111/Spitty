const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
dotenv.config();

// Create a transporter object using Gmail or Ethereal SMTP settings
const transporter = nodemailer.createTransport({
  service : "gmail", // Or use 'smtp.gmail.com' for Gmail
  port: 465 || 587,
  secure: false,
  auth: {
    user: "iknowu110125@gmail.com", // Get the email from environment variables
    pass: "ibpxqbkkibbqsctr", // Get the password from environment variables (App password if 2FA enabled)
  },
});

// Function to send OTP email
const SendVerificationCode = async (email, otp) => {
  try {
    const response = await transporter.sendMail({
      from: `"donotreply@gmail.com" <${process.env.EMAIL}>`, // Use the email configured in dotenv
      to: email,
      subject: "OTP Verification for Registration",
      text: `Your OTP for registration is: ${otp}`, // Plain text version
      html: `
        <p>Hello,</p>
        <p>Your OTP for registration is:</p>
        <h2>${otp}</h2>
        <p>Please use this OTP to complete your password reset process.</p>
        <p>If you did not request this, please ignore this message.</p>
        <p>Best regards,<br>Spitty</p>
      `, // HTML version with formatting
    });
    console.log("Email sent successfully", response);
  } catch (error) {
   console.log(`error : ${error}`);
  }
};

//sending reset mail to the user : 
const resetPasswordLink = async (email, otp) => {
  try {
    const response = await transporter.sendMail({
      from: `"donotreply@gmail.com" <${process.env.EMAIL}>`, // Use the email configured in dotenv
      to: email,
      subject: "OTP Verification for Registration",
      text: `Your OTP for registration is: ${otp}`, // Plain text version
      html: `
        <p>Hello,</p>
        <p>Your link for pasword reset :</p>
        <a href=${otp}><button>Reset Password</button></a>
        <p>Please use this link to complete your password reset process.</p>
        <p>If you did not request this, please ignore this message.</p>
        <p>Best regards,<br>Spitty</p>
      `, // HTML version with formatting
    });
    console.log("Email sent successfully", response);
  } catch (error) {
   console.log(`error : ${error}`);
  }
};

//custom message to send data to the mail : 
const CutstomresetPasswordLink = async (option) => {
  try {
    const response = await transporter.sendMail({
      from: `"donotreply@gmail.com" <${process.env.EMAIL}>`, // Use the email configured in dotenv
      to: option.to,
      subject: `${option.subject}`,
      text: `${option.text}`, // Plain text version
      html: `
        ${option.html}
        <p>If you did not request this, please ignore this message.</p>
        <p>Best regards,<br>Spitty</p>
        <P>customer Service : spittyinfo@gmail.com</p>
      `, // HTML version with formatting
    });
    console.log("Email sent successfully", response);
  } catch (error) {
   console.log(`error : ${error}`);
  }
};

module.exports = {SendVerificationCode , resetPasswordLink, CutstomresetPasswordLink};
