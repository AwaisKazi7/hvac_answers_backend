// middlewares/upload.js
const multer = require('multer');
const path = require('path');

// Configure storage for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/documents');
  },
  filename: (req, file, cb) => {
    // Generate a unique name for the file
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});


const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();

  // Check for allowed document extensions
  if (ext !== '.pdf' && ext !== '.doc' && ext !== '.docx' && ext !== '.xls' && ext !== '.xlsx') {
    return cb(new Error('Only PDF, Word, and Excel documents are allowed!'), false);
  }
  
  cb(null, true);
};

// Multer configuration
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 1024 * 1024 * 5 }, // 5MB limit
});

module.exports = upload;
