
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://admin:admin123@volunteercluster.mongodb.net/volunteerDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'volunteer-app-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['volunteer', 'organization'], required: true },
  skills: [String],
  description: String,
  location: String,
  applications: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Opportunity' }]
}));

const Opportunity = mongoose.model('Opportunity', new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  requirements: [String],
  location: String,
  startDate: Date,
  endDate: Date,
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  organizationName: String,
  applicants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}));

// Authentication middleware
const authenticateUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'jwt-secret-key');
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

// Auth routes
app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role, skills, description, location } = req.body;
    
    // Validate required fields
    if (!name || !email || !password || !role) {
      return res.status(400).render('signup', { 
        error: 'All required fields must be filled', 
        formData: { name, email, role, skills, description, location } 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).render('signup', { 
        error: 'Email already in use',
        formData: { name, email, role, skills, description, location } 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role,
      skills: skills ? skills.split(',').map(skill => skill.trim()) : [],
      description,
      location
    });
    
    console.log('Attempting to save user:', { name, email, role });
    await user.save();
    console.log('User saved successfully with ID:', user._id);
    
    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET || 'jwt-secret-key',
      { expiresIn: '24h' }
    );
    
    res.cookie('token', token, { httpOnly: true });
    
    if (user.role === 'volunteer') {
      res.redirect('/volunteer/dashboard');
    } else {
      res.redirect('/organization/dashboard');
    }
  } catch (err) {
    console.error('Signup error details:', err);
    // More descriptive error message
    const errorMessage = err.code === 11000 ? 'Email already exists' : 
                        (err.message || 'Error creating account');
    res.status(500).render('signup', { 
      error: errorMessage,
      formData: req.body  // Return form data to repopulate fields
    });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).render('login', { error: 'Invalid email or password' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).render('login', { error: 'Invalid email or password' });
    }
    
    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET || 'jwt-secret-key',
      { expiresIn: '24h' }
    );
    
    res.cookie('token', token, { httpOnly: true });
    
    if (user.role === 'volunteer') {
      res.redirect('/volunteer/dashboard');
    } else {
      res.redirect('/organization/dashboard');
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { error: 'Login error' });
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Volunteer routes
app.get('/volunteer/dashboard', authenticateUser, async (req, res) => {
  if (req.user.role !== 'volunteer') {
    return res.redirect('/organization/dashboard');
  }
  
  try {
    const opportunities = await Opportunity.find({});
    const user = await User.findById(req.user.id).populate('applications');
    
    res.render('volunteer/dashboard', { 
      user,
      opportunities,
      applications: user.applications || []
    });
  } catch (err) {
    console.error('Error fetching volunteer dashboard:', err);
    res.status(500).render('error', { message: 'Error loading dashboard' });
  }
});

app.post('/volunteer/apply/:opportunityId', authenticateUser, async (req, res) => {
  if (req.user.role !== 'volunteer') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const opportunityId = req.params.opportunityId;
    
    // Update opportunity with applicant
    await Opportunity.findByIdAndUpdate(
      opportunityId,
      { $addToSet: { applicants: req.user.id } }
    );
    
    // Update user with application
    await User.findByIdAndUpdate(
      req.user.id,
      { $addToSet: { applications: opportunityId } }
    );
    
    res.redirect('/volunteer/dashboard');
  } catch (err) {
    console.error('Application error:', err);
    res.status(500).json({ error: 'Application error' });
  }
});

// Organization routes
app.get('/organization/dashboard', authenticateUser, async (req, res) => {
  if (req.user.role !== 'organization') {
    return res.redirect('/volunteer/dashboard');
  }
  
  try {
    const opportunities = await Opportunity.find({ organizationId: req.user.id });
    res.render('organization/dashboard', { 
      user: req.user,
      opportunities
    });
  } catch (err) {
    console.error('Error fetching organization dashboard:', err);
    res.status(500).render('error', { message: 'Error loading dashboard' });
  }
});

app.get('/organization/create-opportunity', authenticateUser, (req, res) => {
  if (req.user.role !== 'organization') {
    return res.redirect('/volunteer/dashboard');
  }
  
  res.render('organization/create-opportunity', { user: req.user });
});

app.post('/organization/create-opportunity', authenticateUser, async (req, res) => {
  if (req.user.role !== 'organization') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const { title, description, requirements, location, startDate, endDate } = req.body;
    
    const opportunity = new Opportunity({
      title,
      description,
      requirements: requirements ? requirements.split(',').map(req => req.trim()) : [],
      location,
      startDate,
      endDate,
      organizationId: req.user.id,
      organizationName: req.user.name
    });
    
    await opportunity.save();
    res.redirect('/organization/dashboard');
  } catch (err) {
    console.error('Error creating opportunity:', err);
    res.status(500).render('organization/create-opportunity', { 
      user: req.user,
      error: 'Error creating opportunity'
    });
  }
});

app.get('/organization/opportunity/:id/applicants', authenticateUser, async (req, res) => {
  if (req.user.role !== 'organization') {
    return res.redirect('/volunteer/dashboard');
  }
  
  try {
    const opportunity = await Opportunity.findById(req.params.id).populate('applicants');
    
    if (!opportunity || opportunity.organizationId.toString() !== req.user.id) {
      return res.status(404).render('error', { message: 'Opportunity not found' });
    }
    
    res.render('organization/applicants', {
      user: req.user,
      opportunity,
      applicants: opportunity.applicants
    });
  } catch (err) {
    console.error('Error fetching applicants:', err);
    res.status(500).render('error', { message: 'Error loading applicants' });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
