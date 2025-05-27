const db = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendResetPassword, sendPasswordResetOtp, sendRegistrationOtp } = require('../utils/emailSender');

// In-memory OTP store (for demo)
const otpStore = new Map();

// Register (Email/Password)
exports.register = async (req, res) => {
  const { username, email, phone_number, password, authentication_type } = req.body;

  console.log("api/register", req.body);

  if (!username || !email || !password || !authentication_type) {
    return res.status(400).json({ status: 400, message: 'Missing required fields.' });
  }

  try {
    const [existingUser] = await db.execute('SELECT * FROM user_table WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ status: 400, message: 'User already exists.' });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString(); // 4-digit OTP
    otpStore.set(email, { otp, purpose: 'register', expiresAt: Date.now() + 5 * 60 * 1000 });

    sendRegistrationOtp(email, otp);

    return res.status(200).json({
      status: 200,
      message: 'OTP sent for registration.',
      data: { otp } // Only for testing; in production, send via email/SMS
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Registration failed.',
      error: error.message
    });
  }
};

exports.verifyRegistrationOtp = async (req, res) => {
  const { username, email, phone_number, password, authentication_type, otp } = req.body;

  if (!otp || !email || !username || !password || !authentication_type) {
    return res.status(400).json({ status: 400, message: 'Missing required fields.' });
  }

  const storedOtpData = otpStore.get(email);

  if (!storedOtpData || storedOtpData.otp !== otp || storedOtpData.purpose !== 'register' || Date.now() > storedOtpData.expiresAt) {
    return res.status(400).json({ status: 400, message: 'Invalid or expired OTP.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'INSERT INTO user_table (username, email, phone_number, password, authentication_type) VALUES (?, ?, ?, ?, ?)',
      [username, email, phone_number || '', hashedPassword, authentication_type]
    );

    otpStore.delete(email);

    const [newUserRows] = await db.execute('SELECT id, username, email, phone_number, profile_image_url, authentication_type, create_date, last_login FROM user_table WHERE id = ?', [result.insertId]);

    const token = jwt.sign({ id: result.insertId }, process.env.JWT_SECRET || "default_jwt_secret", { expiresIn: '1d' });

    res.status(201).json({
      status: 201,
      message: 'User registered successfully.',
      token,
      data: newUserRows[0]
    });

  } catch (error) {
    res.status(500).json({ status: 500, message: 'Registration OTP verification failed.', error: error.message });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  console.log("api/login", req.body);

  if (!email || !password) {
    return res.status(400).json({ status: 400, message: 'Email and password are required.' });
  }

  try {
    const [users] = await db.execute('SELECT * FROM user_table WHERE email = ?', [email]);
    const user = users[0];

    if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 401, message: 'Invalid credentials.' });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStore.set(email, { otp, purpose: 'login', expiresAt: Date.now() + 5 * 60 * 1000 });
    sendRegistrationOtp(email, otp);
    res.status(200).json({
      status: 200,
      message: 'OTP sent for login.',
      data: { otp } // Only for testing
    });

  } catch (error) {
    res.status(500).json({ status: 500, message: 'Login failed.', error: error.message });
  }
};

exports.verifyLoginOtp = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ status: 400, message: 'Email and OTP are required.' });
  }

  const storedOtpData = otpStore.get(email);

  if (!storedOtpData || storedOtpData.otp !== otp || storedOtpData.purpose !== 'login' || Date.now() > storedOtpData.expiresAt) {
    return res.status(400).json({ status: 400, message: 'Invalid or expired OTP.' });
  }

  try {
    const [users] = await db.execute('SELECT * FROM user_table WHERE email = ?', [email]);
    const user = users[0];

    if (!user) {
      return res.status(404).json({ status: 404, message: 'User not found.' });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "default_jwt_secret", { expiresIn: '1d' });

    const { password: _, ...safeUser } = user;

    otpStore.delete(email);

    res.status(200).json({
      status: 200,
      message: 'Login successful.',
      token,
      data: safeUser
    });

  } catch (error) {
    res.status(500).json({ status: 500, message: 'OTP verification failed.', error: error.message });
  }
};
// Forget Password - Send OTP
exports.forgetPassword = async (req, res) => {
  const { email } = req.body;
  console.log("api/forgetPassword", req.body);
  if (!email) {
    return res.status(400).json({
      status: 400,
      message: 'Email is required.'
    });
  }

  try {
    const [users] = await db.execute('SELECT * FROM user_table WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({
        status: 404,
        message: 'User not found.'
      });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStore.set(email, otp); // Save in memory
    
    sendPasswordResetOtp(email, otp);
    res.status(200).json({
      status: 200,
      message: 'OTP sent successfully.',
      data: { otp } // Include in response for testing/demo
    });

  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Failed to send OTP.',
      error: error.message
    });
  }
};
// Verify OTP
exports.verifyOtp = (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      status: 400,
      message: 'Email and OTP are required.'
    });
  }

  const storedOtp = otpStore.get(email);
  if (!storedOtp || storedOtp !== otp) {
    return res.status(400).json({
      status: 400,
      message: 'Invalid or expired OTP.'
    });
  }

  res.status(200).json({
    status: 200,
    message: 'OTP verified successfully.',
    data: {}
  });
};

// Reset Password
exports.resetPassword = async (req, res) => {
  const { email, new_password } = req.body;

  if (!email || !new_password) {
    return res.status(400).json({
      status: 400,
      message: 'Email and new password are required.'
    });
  }

  try {
    const hashed = await bcrypt.hash(new_password, 10);
    await db.execute('UPDATE user_table SET password = ? WHERE email = ?', [hashed, email]);
    otpStore.delete(email);

    res.status(200).json({
      status: 200,
      message: 'Password reset successfully.',
      data: {}
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Password reset failed.',
      error: error.message
    });
  }
};

// Social Auth (Google / Apple)
exports.socialAuth = async (req, res) => {
  const { username, email, phone_number, authentication_type } = req.body;

  if (!email || !authentication_type) {
    return res.status(400).json({
      status: 400,
      message: 'Email and authentication type are required.'
    });
  }

  try {
    const [users] = await db.execute('SELECT * FROM user_table WHERE email = ?', [email]);

    if (users.length > 0) {
      const user = users[0];
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "default_jwt_secret", { expiresIn: '1d' });

      return res.status(200).json({
        status: 200,
        message: 'Login successful.',
        data: { token, user }
      });
    }

    const [result] = await db.execute(
      'INSERT INTO user_table (username, email, phone_number, authentication_type) VALUES (?, ?, ?, ?)',
      [username || '', email, phone_number || '', authentication_type]
    );

    const [newUser] = await db.execute('SELECT * FROM user_table WHERE id = ?', [result.insertId]);
    const token = jwt.sign({ id: result.insertId }, process.env.JWT_SECRET || "default_jwt_secret", { expiresIn: '1d' });

    res.status(201).json({
      status: 201,
      message: 'Social login successful.',
      data: { token, user: newUser[0] }
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Social login failed.',
      error: error.message
    });
  }
};

// Get All Users
exports.getAllUsers = async (req, res) => {
  try {
    const [users] = await db.execute('SELECT * FROM user_table');
    res.status(200).json({
      status: 200,
      message: 'Users fetched successfully.',
      data: users
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Failed to fetch users.',
      error: error.message
    });
  }
};

// Get User by ID
exports.getUserById = async (req, res) => {
  try {
    const [user] = await db.execute('SELECT * FROM user_table WHERE id = ?', [req.params.id]);
    res.status(200).json({
      status: 200,
      message: 'User fetched successfully.',
      data: user[0] || null
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Failed to fetch user.',
      error: error.message
    });
  }
};

// Update User
exports.updateUser = async (req, res) => {
  const { username, phone_number } = req.body;

  try {
    await db.execute(
      'UPDATE user_table SET username = ?, phone_number = ? WHERE id = ?',
      [username, phone_number, req.params.id]
    );

    res.status(200).json({
      status: 200,
      message: 'User updated successfully.',
      data: {}
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Update failed.',
      error: error.message
    });
  }
};

// Delete User
exports.deleteUser = async (req, res) => {
  try {
    await db.execute('DELETE FROM user_table WHERE id = ?', [req.params.id]);
    res.status(200).json({
      status: 200,
      message: 'User deleted successfully.',
      data: {}
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'Delete failed.',
      error: error.message
    });
  }
};
