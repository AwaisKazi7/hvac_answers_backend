const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Create an email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // or any other email service provider
    auth: {
      user: 'Tax@filewithsavvy.com',
      pass: 'savvy@CS', 
    },
  });
  
  const sendOTPEmail = async (email, otp) => {
    const mailOptions = {
      from: 'Tax@filewithsavvy.com',
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}`,
    };
  
    return transporter.sendMail(mailOptions);
  };


  module.exports = sendOTPEmail;
