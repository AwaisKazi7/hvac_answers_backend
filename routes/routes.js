
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const chatController = require('../controllers/chatController');
const authenticate = require('../middleware/auth');

// Auth
router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/social-auth', userController.socialAuth);

// Password Flow
router.post('/forget-password', userController.forgetPassword);
router.post('/verify-otp', userController.verifyOtp);
router.post('/reset-password', userController.resetPassword);
router.post('/verify-registration-otp', userController.verifyRegistrationOtp);
router.post('/verify-login-otp', userController.verifyLoginOtp);

// CRUD
router.get('/users', userController.getAllUsers);
router.get('/users/:id', userController.getUserById);
router.put('/users/:id', userController.updateUser);
router.delete('/users/:id', userController.deleteUser);

// Chat routes
router.post('/chats', authenticate, chatController.createChat);
router.get('/chats/user/:userId', authenticate, chatController.getChatsByUserId);
router.delete('/chats/:chatId', authenticate, chatController.deleteChat);

// Message routes
router.get('/messages/:chatId', authenticate, chatController.getMessagesByChatId);
router.post('/messages', authenticate, chatController.addMessage);
router.delete('/messages/:messageId', authenticate, chatController.deleteMessage);



module.exports = router;
