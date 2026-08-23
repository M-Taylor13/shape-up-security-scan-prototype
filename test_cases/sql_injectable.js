app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: Direct interpolation of user input
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  connection.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false });
    }
  });
});