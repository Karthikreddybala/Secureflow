# Backend API Server

A simple Express.js API server for testing and learning.

## Setup & Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Server
```bash
# Production mode
npm start

# Development mode (auto-reloads on file changes)
npm run dev
```

The server will run at `http://localhost:5000`

---

## Testing with Postman

### 1. **GET All Users**
- **Method:** GET
- **URL:** `http://localhost:5000/users`
- **Expected Response:** List of all users

### 2. **GET Specific User**
- **Method:** GET
- **URL:** `http://localhost:5000/users/1`
- **Expected Response:** User with ID 1

### 3. **CREATE a New User**
- **Method:** POST
- **URL:** `http://localhost:5000/users`
- **Headers:** `Content-Type: application/json`
- **Body (JSON):**
```json
{
  "name": "Alice Johnson",
  "email": "alice@example.com"
}
```
- **Expected Response:** New user created with ID 4

### 4. **UPDATE a User**
- **Method:** PUT
- **URL:** `http://localhost:5000/users/1`
- **Headers:** `Content-Type: application/json`
- **Body (JSON):**
```json
{
  "name": "John Updated",
  "email": "john.updated@example.com"
}
```
- **Expected Response:** Updated user data

### 5. **DELETE a User**
- **Method:** DELETE
- **URL:** `http://localhost:5000/users/1`
- **Expected Response:** Confirmation of deletion

### 6. **TEST Endpoint (Send Custom Data)**
- **Method:** POST
- **URL:** `http://localhost:5000/test`
- **Headers:** `Content-Type: application/json`
- **Body (JSON):**
```json
{
  "message": "Hello Server!",
  "test": true,
  "data": "anything you want"
}
```
- **Expected Response:** Echo back your data with timestamp

---

## Understanding the Code

### Middleware (Lines 10-15)
- **cors()** - Allows requests from different domains/Postman
- **express.json()** - Converts JSON body into JavaScript objects
- **express.urlencoded()** - Handles form data

### Routes (Lines 17-120)
- Each route handles a specific HTTP method (GET, POST, PUT, DELETE)
- Routes have **request** (req) and **response** (res) parameters
- `req.body` - Contains data sent in the request
- `req.params` - Contains URL parameters (e.g., user ID)
- `res.json()` - Sends JSON response back to client
- `res.status()` - Sets HTTP status code (200, 201, 400, 404, etc.)

### Response Format
All responses follow a consistent format:
```json
{
  "success": true/false,
  "data": {},
  "message": "Description"
}
```

---

## Common HTTP Status Codes
- **200** - OK (successful GET)
- **201** - Created (successful POST)
- **400** - Bad Request (missing/invalid data)
- **404** - Not Found (endpoint doesn't exist)
- **500** - Server Error

---

## Environment Variables (.env file)
- **PORT** - The port the server runs on (default: 5000)
- **NODE_ENV** - development or production

