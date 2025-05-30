// config/db.js
const mysql = require('mysql2');

// Create the MySQL connection pool
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  database: "hvac_answers_db",
  password: "",
});

module.exports = pool.promise(); // Using promise-based queries



// const mysql = require('mysql2');  // or 'mysql' depending on your package

// const db = mysql.createConnection({
//   host: 'localhost',
//   user: 'your_database_username',  // Ensure the correct MySQL username
//   password: 'your_database_password',  // Ensure the correct MySQL password
//   database: 'your_database_name'  // Your database name
// });

// db.connect((err) => {
//   if (err) {
//     console.error('Error connecting to the database:', err.message);
//   } else {
//     console.log('Connected to the MySQL database');
//   }
// });
