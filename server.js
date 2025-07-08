require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URL = process.env.MONGODB_URL;

// MongoDB connection to ALPHA database
mongoose.connect(MONGODB_URL)
  .then(() => console.log('Connected to MongoDB ALPHA database'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// Admin Schema for the 'admins' collection
const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin' }
});

// Student Schema for the 'students' collection
const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  studentId: { type: String, unique: true, required: true },
  phone: { type: String, required: true },
  branch: { type: String, required: true },
  department: { type: String, required: true },
  dob: { type: Date, required: true }
});

const Admin = mongoose.model('Admin', adminSchema, 'admins');
const Student = mongoose.model('Student', studentSchema, 'students');

// Generate JWT token
const generateToken = (user, role) => {
  return jwt.sign(
    { id: user._id, email: user.email, role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
};

// Admin Signup
app.post('/api/admin/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: 'Missing required fields: name, email, phone, and password are required' });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ message: 'JWT_SECRET is not defined' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = new Admin({
      name,
      email,
      phone,
      password: hashedPassword,
      role: 'admin'
    });
    const newAdmin = await admin.save();
    const token = generateToken(newAdmin, 'admin');
    res.status(201).json({ 
      message: 'Admin registered successfully', 
      admin: { 
        name: newAdmin.name, 
        email: newAdmin.email, 
        phone: newAdmin.phone, 
        role: newAdmin.role 
      },
      token
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(400).json({ message: err.message, stack: err.stack });
  }
});

// Admin Signin
app.post('/api/admin/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Missing required fields: email and password are required' });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ message: 'JWT_SECRET is not defined' });
    }
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = generateToken(admin, 'admin');
    res.json({ 
      message: 'Login successful', 
      admin: { 
        name: admin.name, 
        email: admin.email, 
        phone: admin.phone, 
        role: admin.role 
      },
      token
    });
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ message: err.message, stack: err.stack });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Middleware to verify admin role
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied: Admins only' });
  }
  next();
};

// Admin: Add Student
app.post('/api/admin/student', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { name, email, studentId, phone, branch, department, dob } = req.body;
    if (!name || !email || !studentId || !phone || !branch || !department || !dob) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const student = new Student({
      name,
      email,
      studentId,
      phone,
      branch,
      department,
      dob: new Date(dob)
    });
    const newStudent = await student.save();
    res.status(201).json({ 
      message: 'Student added successfully', 
      student: { 
        name: newStudent.name, 
        email: newStudent.email, 
        studentId: newStudent.studentId, 
        phone: newStudent.phone, 
        branch: newStudent.branch, 
        department: newStudent.department, 
        dob: newStudent.dob 
      }
    });
  } catch (err) {
    console.error('Add student error:', err);
    res.status(400).json({ message: err.message, stack: err.stack });
  }
});

// Student Login
app.post('/api/student/signin', async (req, res) => {
  try {
    const { email, studentId } = req.body;
    if (!email || !studentId) {
      return res.status(400).json({ message: 'Missing required fields: email and studentId are required' });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ message: 'JWT_SECRET is not defined' });
    }
    const student = await Student.findOne({ email, studentId });
    if (!student) {
      return res.status(404).json({ message: 'Student not found or credentials do not match' });
    }
    const token = generateToken(student, 'student');
    res.json({ 
      message: 'Login successful', 
      student: { 
        name: student.name, 
        email: student.email, 
        studentId: student.studentId, 
        phone: student.phone, 
        branch: student.branch, 
        department: student.department, 
        dob: student.dob 
      },
      token
    });
  } catch (err) {
    console.error('Student signin error:', err);
    res.status(500).json({ message: err.message, stack: err.stack });
  }
});

// Student Profile (Protected)
app.get('/api/student/profile', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ message: 'Access denied: Students only' });
    }
    const student = await Student.findById(req.user.id);
    if (!student) {
      return res.status(404).json({ message: 'Student not found' });
    }
    res.json({ 
      student: { 
        name: student.name, 
        email: student.email, 
        studentId: student.studentId, 
        phone: student.phone, 
        branch: student.branch, 
        department: student.department, 
        dob: student.dob 
      }
    });
  } catch (err) {
    console.error('Student profile error:', err);
    res.status(500).json({ message: err.message, stack: err.stack });
  }
});

// Admin Profile (Protected)
app.get('/api/admin/profile', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id).select('-password');
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }
    res.json({ 
      admin: { 
        name: admin.name, 
        email: admin.email, 
        phone: admin.phone, 
        role: admin.role 
      }
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ message: err.message, stack: err.stack });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'API is running' });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});