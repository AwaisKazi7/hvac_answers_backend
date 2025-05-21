const db = require('../config/db');

// Create User Profile
exports.createProfile = async (req, res) => {
  const { user_id, name, email } = req.body;

  try {
    // Check if the user_id exists in the users table
    const [userRows] = await db.execute('SELECT * FROM users WHERE id = ?', [user_id]);

    // If the user doesn't exist, return an error
    if (userRows.length === 0) {
      return res.status(400).json({ error: 'Invalid user_id. User not found.' });
    }

    // Insert into the userprofile table if the user exists
    await db.execute(
      'INSERT INTO userprofile (user_id, name, email) VALUES (?, ?, ?)',
      [user_id, name, email]
    );

    return res.status(201).json({ message: 'Profile created successfully!' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// Get User Profile
exports.getUserProfile = async (req, res) => {
  const { user_id } = req.params; // Extract user_id from URL parameters

  try {
    // Query the database to get the user profile by user_id
    const [rows] = await db.execute('SELECT * FROM userprofile WHERE user_id = ?', [user_id]);
    
    // Check if the user profile exists
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User profile not found' });
    }

    // Return the user profile data
    return res.json(rows[0]);
  } catch (error) {
    // Handle errors
    return res.status(500).json({ error: error.message });
  }
};

// Update User Profile
exports.updateUserProfile = async (req, res) => {
  const { id } = req.params;
  const { user_id, name, email } = req.body;

  try {
    // Fetch the existing profile from the database using the provided ID
    const [rows] = await db.execute('SELECT * FROM userprofile WHERE id = ?', [id]);

    // If the profile doesn't exist, return a 404 error
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    // Update the database with the new data
    await db.execute(
      `UPDATE userprofile 
       SET user_id = ?, name = ?, email = ?
       WHERE id = ?`,
      [user_id, name, email, id]
    );

    // Return a success message
    return res.json({ message: 'User profile updated successfully!' });
  } catch (error) {
    // Catch and return any errors that occur
    return res.status(500).json({ error: error.message });
  }
};

// Delete User Profile
exports.deleteUserProfile = async (req, res) => {
  const { id } = req.params;

  try {
    // Fetch the user profile to check if it exists
    const [rows] = await db.execute('SELECT * FROM userprofile WHERE id = ?', [id]);

    // If the profile doesn't exist, return a 404 error
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    // Delete the user profile from the database
    await db.execute('DELETE FROM userprofile WHERE id = ?', [id]);

    return res.json({ message: 'User profile deleted successfully!' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
