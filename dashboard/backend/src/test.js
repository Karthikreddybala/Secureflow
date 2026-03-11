const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ===== MIDDLEWARE =====
// Allow requests from any origin (useful for testing with Postman)
app.use(cors());

// Parse incoming JSON data
app.use(express.json());

// Parse incoming form data
app.use(express.urlencoded({ extended: true }));

// ===== ROUTES =====

// 1. GET / - Welcome endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the API!',
    version: '1.0.0',
    endpoints: {
      get: ['/', '/users', '/users/:id'],
      post: ['/users'],
      put: ['/users/:id'],
      delete: ['/users/:id']
    }
  });
});

// 2. GET /users - Get all users
app.get('/users', (req, res) => {
  const users = [
    { id: 1, name: 'John Doe', email: 'john@example.com' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com' },
    { id: 3, name: 'Bob Johnson', email: 'bob@example.com' }
  ];
  
  res.json({
    success: true,
    data: users,
    message: 'Users retrieved successfully'
  });
});

// 3. GET /users/:id - Get a specific user
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  
  res.json({
    success: true,
    data: {
      id: userId,
      name: 'John Doe',
      email: 'john@example.com'
    },
    message: `User ${userId} retrieved successfully`
  });
});

// 4. POST /users - Create a new user
app.post('/users', (req, res) => {
  const { name, email } = req.body;
  
  // Simple validation
  if (!name || !email) {
    return res.status(400).json({
      success: false,
      message: 'Name and email are required',
      received: req.body
    });
  }
  
  res.status(201).json({
    success: true,
    data: {
      id: 4,
      name: name,
      email: email
    },
    message: 'User created successfully'
  });
});

// 5. PUT /users/:id - Update a user
app.put('/users/:id', (req, res) => {
  const userId = req.params.id;
  const { name, email } = req.body;
  
  res.json({
    success: true,
    data: {
      id: userId,
      name: name || 'Updated Name',
      email: email || 'updated@example.com'
    },
    message: `User ${userId} updated successfully`
  });
});

// 6. DELETE /users/:id - Delete a user
app.delete('/users/:id', (req, res) => {
  const userId = req.params.id;
  
  res.json({
    success: true,
    message: `User ${userId} deleted successfully`,
    deletedId: userId
  });
});

// 7. POST /test - Test endpoint to send data
app.post('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Test endpoint works!',
    receivedData: req.body,
    timestamp: new Date().toISOString()
  });
});

// ===== ERROR HANDLING =====
// 404 - Not Found
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║   🚀 SERVER STARTED SUCCESSFULLY 🚀   ║
╚════════════════════════════════════════╝

📍 Server running at: http://locahost:${PORT}
🧪 Test with Postman at: http://localhost:${PORT}

📚 Available Endpoints:
  GET  http://localhost:${PORT}/              (Welcome)
  GET  http://localhost:${PORT}/users         (Get all users)
  GET  http://localhost:${PORT}/users/:id     (Get user by ID)
  POST http://localhost:${PORT}/users         (Create user)
  PUT  http://localhost:${PORT}/users/:id     (Update user)
  DELETE http://localhost:${PORT}/users/:id   (Delete user)
  POST http://localhost:${PORT}/test          (Test endpoint)

Press Ctrl+C to stop the server
  `);
});
