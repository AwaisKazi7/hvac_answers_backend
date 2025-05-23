const nodemailer = require('nodemailer');

// Create a Nodemailer transporter instance using SMTP
const createEmailTransporter = () => {
  return nodemailer.createTransport({
    host: "webmail.hbox.digital", // Your SMTP server
    port: 465,
    secure: true, // true for port 465
    tls: {
      rejectUnauthorized: false,
    },
    auth: {
      user: "support@hbox.digital",
      pass: "Dev.Hbox.Digital123@",
    },
    

  });
};

// Generic function to send emails
const sendEmail = async (email, subject, text, html) => {
  const transporter = createEmailTransporter();
  const mailOptions = {
    from: "support@hbox.digital",
    to: email,
    subject,
    text,
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${email}`);
  } catch (error) {
    console.error(`Error sending email to ${email}:`, error);
    throw new Error('Error sending email');
  }
};

// Function to send OTP for registration/verification
const sendRegistrationOtp = async (email, otp) => {
  const subject = 'Verify Your Account';
  const text = `Your OTP for account verification is: ${otp}`;
  const html = `<p>Your OTP for account verification is: <strong>${otp}</strong></p>`;
  await sendEmail(email, subject, text, html);
};

// Function to send OTP for sendLoginOtp
const sendLoginOtp = async (email, otp) => {
  const subject = 'Verify Your Account';
  const text = `Your OTP for account verification is: ${otp}`;
  const html = `<p>Your OTP for account verification is: <strong>${otp}</strong></p>`;
  await sendEmail(email, subject, text, html);
};

// Function to send OTP for password reset
const sendPasswordResetOtp = async (email, otp) => {
  const subject = 'Password Reset OTP';
  const text = `Your OTP for password reset is: ${otp}`;
  const html = `<p>Your OTP for password reset is: <strong>${otp}</strong></p>`;
  await sendEmail(email, subject, text, html);
};

// Function to notify profile submission
const sendProfileSubmissionEmail = async (email) => {
  const subject = 'Profile Submission Received';
  const text = 'Your profile has been submitted and is awaiting approval by the admin.';
  const html = `<p>Your profile has been submitted and is awaiting approval by the admin.</p>`;
  await sendEmail(email, subject, text, html);
};

module.exports = {
  sendRegistrationOtp,
  sendPasswordResetOtp,
  sendLoginOtp,
  sendProfileSubmissionEmail,
  sendEmail,
};
