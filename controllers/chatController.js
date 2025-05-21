// chatController.js
const db = require('../config/db');

// Create Chat
exports.createChat = async (req, res) => {
  const { chat_title, user_id } = req.body;

  if (!chat_title || !user_id) {
    return res.status(400).json({ message: 'chat title and user id are required.' });
  }

  try {
    const [result] = await db.execute(
      'INSERT INTO chat_table (chat_title, user_id) VALUES (?, ?)',
      [chat_title, user_id]
    );
    const [chat] = await db.execute('SELECT * FROM chat_table WHERE id = ?', [result.insertId]);
    res.status(201).json({ status: 201, message: 'Chat created successfully.', data: chat[0] });
  } catch (error) {
    res.status(500).json({ status: 500, message: 'Chat creation failed.', error: error.message });
  }
};

// Get All Chats by User ID
exports.getChatsByUserId = async (req, res) => {
  try {
    const [chats] = await db.execute('SELECT * FROM chat_table WHERE user_id = ? and visible = 1', [req.params.userId]);
    res.status(200).json({ status: 200, message: 'Chats fetched successfully.', data: chats });
  } catch (error) {
    res.status(500).json({ status: 500, message: 'Failed to fetch chats.', error: error.message });
  }
};

// Delete Chat
exports.deleteChat = async (req, res) => {
  try {
    await db.execute('DELETE FROM chat_table WHERE id = ?', [req.params.id]);
    res.status(200).json({ status: 200, message: 'Chat deleted successfully.' });
  } catch (error) {
    res.status(500).json({ status: 500, message: 'Failed to delete chat.', error: error.message });
  }
};

// Get All Messages by Chat ID
exports.getMessagesByChatId = async (req, res) => {
  try {
    const [messages] = await db.execute('SELECT * FROM message_table WHERE chat_id = ?', [req.params.chatId]);
    res.status(200).json({ status: 200, message: 'Messages fetched successfully.', data: messages });
  } catch (error) {
    res.status(500).json({ status: 500, message: 'Failed to fetch messages.', error: error.message });
  }
};

// Add Message
exports.addMessage = async (req, res) => {
  const { message, chat_id, is_user } = req.body;

  if (!message || !chat_id) {
    return res.status(400).json({ status: 400, message: 'message and chat_id are required.' });
  }

  try {
    const [result] = await db.execute(
      'INSERT INTO message_table (message, chat_id, is_user) VALUES (?, ?, ?)',
      [message, chat_id, is_user ?? true]
    );
    const [msg] = await db.execute('SELECT * FROM message_table WHERE id = ?', [result.insertId]);
    res.status(201).json({ status: 201, message: 'Message added successfully.', data: msg[0] });
  } catch (error) {
    res.status(500).json({ status: 500, message: 'Failed to add message.', error: error.message });
  }
};

// Delete Message
exports.deleteMessage = async (req, res) => {
  try {
    await db.execute('DELETE FROM message_table WHERE id = ?', [req.params.id]);
    res.status(200).json({ status: 200, message: 'Message deleted successfully.' });
  } catch (error) {
    res.status(500).json({ status: 500, message: 'Failed to delete message.', error: error.message });
  }
};
