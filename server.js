const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

const SECRET_KEY = 'secret-key';

// Middleware
app.use(express.json());

const users = [];

// User registration
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (users.find(user => user.username === username)) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = { username, password: hashedPassword };
  users.push(user);
  res.status(201).json({ message: 'User created' });
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Generate a JWT token
  const token = jwt.sign({ username }, SECRET_KEY);
  res.json({ token });
});

// Protected route
app.get('/protected', (req, res) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const username = decoded.username;
    res.json({ message: `Hello, ${username}! This is a protected route.` });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

// Start the server
const port = 3001;
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
