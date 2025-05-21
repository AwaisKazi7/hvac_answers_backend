const jwt = require('jsonwebtoken');
module.exports = (req, res, next) => {
  let token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });
  // Remove Bearer prefix if present
  if (token.startsWith('Bearer ')) {
    token = token.slice(7, token.length).trim();
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.userId = decoded.id;
    next();
  });
};