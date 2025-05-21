// utils/helperFunction.js
const path = require('path');
const fs = require('fs');

// Helper function to delete an image file
const deleteImage = (imagePath) => {
  const imageFullPath = path.join(__dirname, `../public/images/${imagePath}`);
  if (fs.existsSync(imageFullPath)) {
    fs.unlinkSync(imageFullPath); // Delete the image file
  }
};

module.exports = deleteImage;
