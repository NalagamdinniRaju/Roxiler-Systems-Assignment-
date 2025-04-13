
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const db = require('./database');

const app = express();
const PORT = 5000;
// Store JWT secret in environment variable instead of hardcoding
const JWT_SECRET =  'your_jwt_secret';

// Apply middleware
app.use(cors());
app.use(express.json());

// Add error handling for JSON parsing
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: 'Invalid JSON' });
  }
  next(err);
});

// Middleware to verify JWT token
const authenticate = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Middleware to check admin role
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Auth endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, address } = req.body;
    
    // Validation
    if (!name || !email || !password || !address) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    if (name.length < 20 || name.length > 60) {
      return res.status(400).json({ message: 'Name must be between 20 and 60 characters' });
    }
    
    if (address.length > 400) {
      return res.status(400).json({ message: 'Address cannot exceed 400 characters' });
    }
    
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,16}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ message: 'Password must be 8-16 characters with at least one uppercase letter and one special character' });
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, address, 'user'],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'Email already registered' });
          }
          console.error('Database error during registration:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        
        const token = jwt.sign(
          { id: this.lastID, email, role: 'user' },
          JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        res.status(201).json({ token });
      }
    );
  } catch (error) {
    console.error('Server error during registration:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during login:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      
      try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ message: 'Invalid credentials' });
        
        const token = jwt.sign(
          { id: user.id, email: user.email, role: user.role },
          JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
      } catch (error) {
        console.error('Password comparison error:', error);
        res.status(500).json({ message: 'Server error' });
      }
    });
  } catch (error) {
    console.error('Server error during login:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Password update
app.put('/api/user/password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current password and new password are required' });
    }
    
    // Validate new password
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,16}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ message: 'Password must be 8-16 characters with at least one uppercase letter and one special character' });
    }
    
    db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, row) => {
      if (err) {
        console.error('Database error when fetching user for password update:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      
      if (!row) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      try {
        const match = await bcrypt.compare(currentPassword, row.password);
        if (!match) return res.status(401).json({ message: 'Current password is incorrect' });
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
          if (err) {
            console.error('Database error when updating password:', err);
            return res.status(500).json({ message: 'Failed to update password' });
          }
          res.json({ message: 'Password updated successfully' });
        });
      } catch (error) {
        console.error('Password update server error:', error);
        res.status(500).json({ message: 'Server error' });
      }
    });
  } catch (error) {
    console.error('Error in password update route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin endpoints
app.get('/api/admin/dashboard', authenticate, isAdmin, (req, res) => {
  try {
    // Using promises for better error handling with nested queries
    const getUserCount = () => {
      return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as userCount FROM users', [], (err, result) => {
          if (err) reject(err);
          else resolve(result.userCount);
        });
      });
    };
    
    const getStoreCount = () => {
      return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as storeCount FROM stores', [], (err, result) => {
          if (err) reject(err);
          else resolve(result.storeCount);
        });
      });
    };
    
    const getRatingCount = () => {
      return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) as ratingCount FROM ratings', [], (err, result) => {
          if (err) reject(err);
          else resolve(result.ratingCount);
        });
      });
    };
    
    Promise.all([getUserCount(), getStoreCount(), getRatingCount()])
      .then(([userCount, storeCount, ratingCount]) => {
        res.json({ userCount, storeCount, ratingCount });
      })
      .catch(error => {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ message: 'Database error' });
      });
  } catch (error) {
    console.error('Error in admin dashboard route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  try {
    const { name, email, password, address, role } = req.body;
    
    if (!name || !email || !password || !address || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Validation
    if (name.length < 20 || name.length > 60) {
      return res.status(400).json({ message: 'Name must be between 20 and 60 characters' });
    }
    
    if (address.length > 400) {
      return res.status(400).json({ message: 'Address cannot exceed 400 characters' });
    }
    
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,16}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ message: 'Password must be 8-16 characters with at least one uppercase letter and one special character' });
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    
    const validRoles = ['user', 'admin', 'store_owner'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, address, role],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'Email already registered' });
          }
          console.error('Database error during admin user creation:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        
        res.status(201).json({ id: this.lastID, name, email, address, role });
      }
    );
  } catch (error) {
    console.error('Error in admin user creation route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/stores', authenticate, isAdmin, (req, res) => {
  try {
    const { name, email, address, owner_id } = req.body;
    
    if (!name || !email || !address) {
      return res.status(400).json({ message: 'Name, email, and address are required' });
    }
    
    // Validation
    if (name.length < 20 || name.length > 60) {
      return res.status(400).json({ message: 'Name must be between 20 and 60 characters' });
    }
    
    if (address.length > 400) {
      return res.status(400).json({ message: 'Address cannot exceed 400 characters' });
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    
    // If owner_id is provided, verify that user exists
    if (owner_id) {
      db.get('SELECT id FROM users WHERE id = ?', [owner_id], (err, user) => {
        if (err) {
          console.error('Database error checking store owner:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        
        if (!user) {
          return res.status(400).json({ message: 'Owner not found' });
        }
        
        createStore();
      });
    } else {
      createStore();
    }
    
    function createStore() {
      db.run(
        'INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)',
        [name, email, address, owner_id],
        function(err) {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ message: 'Store email already registered' });
            }
            console.error('Database error creating store:', err);
            return res.status(500).json({ message: 'Database error' });
          }
          
          if (owner_id) {
            db.run('UPDATE users SET role = "store_owner" WHERE id = ?', [owner_id], (err) => {
              if (err) {
                console.error('Error updating user role to store_owner:', err);
                // Continue despite role update error
              }
            });
          }
          
          res.status(201).json({ id: this.lastID, name, email, address, owner_id });
        }
      );
    }
  } catch (error) {
    console.error('Error in admin store creation route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/users', authenticate, isAdmin, (req, res) => {
  try {
    const { search, role } = req.query;
    
    let query = 'SELECT id, name, email, address, role FROM users';
    const params = [];
    
    if (search || role) {
      query += ' WHERE';
      
      if (search) {
        query += ' (name LIKE ? OR email LIKE ? OR address LIKE ?)';
        params.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }
      
      if (search && role) {
        query += ' AND';
      }
      
      if (role) {
        query += ' role = ?';
        params.push(role);
      }
    }
    
    db.all(query, params, (err, users) => {
      if (err) {
        console.error('Database error fetching users:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json(users);
    });
  } catch (error) {
    console.error('Error in admin users listing route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/stores', authenticate, isAdmin, (req, res) => {
  try {
    const { search } = req.query;
    
    let query = `
      SELECT s.id, s.name, s.email, s.address, s.owner_id,
             ROUND(AVG(r.rating), 1) as rating,
             COUNT(r.id) as rating_count
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
    `;
    
    const params = [];
    
    if (search) {
      query += ' WHERE s.name LIKE ? OR s.email LIKE ? OR s.address LIKE ?';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    
    query += ' GROUP BY s.id';
    
    db.all(query, params, (err, stores) => {
      if (err) {
        console.error('Database error fetching stores:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json(stores);
    });
  } catch (error) {
    console.error('Error in admin stores listing route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/user/:id', authenticate, isAdmin, (req, res) => {
  try {
    const userId = req.params.id;
    
    if (!userId || isNaN(parseInt(userId))) {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    
    db.get('SELECT id, name, email, address, role FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) {
        console.error('Database error fetching user details:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      
      if (!user) return res.status(404).json({ message: 'User not found' });
      
      if (user.role === 'store_owner') {
        db.get(
          `SELECT s.id, s.name, ROUND(AVG(r.rating), 1) as rating
           FROM stores s
           LEFT JOIN ratings r ON s.id = r.store_id
           WHERE s.owner_id = ?
           GROUP BY s.id`,
          [userId],
          (err, store) => {
            if (err) {
              console.error('Database error fetching store owner details:', err);
              return res.status(500).json({ message: 'Database error' });
            }
            user.store = store;
            res.json(user);
          }
        );
      } else {
        res.json(user);
      }
    });
  } catch (error) {
    console.error('Error in admin user details route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User endpoints
app.get('/api/stores', authenticate, (req, res) => {
  try {
    const { search } = req.query;
    const userId = req.user.id;
    
    let query = `
      SELECT s.id, s.name, s.address,
             ROUND(AVG(r.rating), 1) as overall_rating,
             COUNT(r.id) as rating_count,
             (SELECT rating FROM ratings WHERE user_id = ? AND store_id = s.id) as user_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
    `;
    
    const params = [userId];
    
    if (search) {
      query += ' WHERE s.name LIKE ? OR s.address LIKE ?';
      params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ' GROUP BY s.id';
    
    db.all(query, params, (err, stores) => {
      if (err) {
        console.error('Database error fetching stores for user:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      res.json(stores);
    });
  } catch (error) {
    console.error('Error in stores listing route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/ratings', authenticate, (req, res) => {
  try {
    const { store_id, rating } = req.body;
    const user_id = req.user.id;
    
    if (!store_id || !rating) {
      return res.status(400).json({ message: 'Store ID and rating are required' });
    }
    
    if (rating < 1 || rating > 5 || !Number.isInteger(Number(rating))) {
      return res.status(400).json({ message: 'Rating must be an integer between 1 and 5' });
    }
    
    // Verify store exists
    db.get('SELECT id FROM stores WHERE id = ?', [store_id], (err, store) => {
      if (err) {
        console.error('Database error checking store existence:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      
      if (!store) {
        return res.status(404).json({ message: 'Store not found' });
      }
      
      db.get('SELECT * FROM ratings WHERE user_id = ? AND store_id = ?', [user_id, store_id], (err, existingRating) => {
        if (err) {
          console.error('Database error checking existing rating:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        
        if (existingRating) {
          db.run(
            'UPDATE ratings SET rating = ? WHERE user_id = ? AND store_id = ?',
            [rating, user_id, store_id],
            (err) => {
              if (err) {
                console.error('Database error updating rating:', err);
                return res.status(500).json({ message: 'Failed to update rating' });
              }
              res.json({ message: 'Rating updated' });
            }
          );
        } else {
          db.run(
            'INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)',
            [user_id, store_id, rating],
            function(err) {
              if (err) {
                console.error('Database error creating rating:', err);
                return res.status(500).json({ message: 'Failed to submit rating' });
              }
              res.status(201).json({ id: this.lastID, user_id, store_id, rating });
            }
          );
        }
      });
    });
  } catch (error) {
    console.error('Error in ratings creation route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Store owner endpoints
app.get('/api/store/dashboard', authenticate, (req, res) => {
  try {
    if (req.user.role !== 'store_owner') {
      return res.status(403).json({ message: 'Store owner access required' });
    }
    
    const userId = req.user.id;
    
    db.get(
      `SELECT s.id, s.name, ROUND(AVG(r.rating), 1) as rating
       FROM stores s
       LEFT JOIN ratings r ON s.id = r.store_id
       WHERE s.owner_id = ?
       GROUP BY s.id`,
      [userId],
      (err, store) => {
        if (err) {
          console.error('Database error fetching store for owner dashboard:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        
        if (!store) return res.status(404).json({ message: 'Store not found' });
        
        db.all(
          `SELECT u.id, u.name, u.email, r.rating, r.created_at
           FROM ratings r
           JOIN users u ON r.user_id = u.id
           WHERE r.store_id = ?
           ORDER BY r.created_at DESC`,
          [store.id],
          (err, ratings) => {
            if (err) {
              console.error('Database error fetching ratings for owner dashboard:', err);
              return res.status(500).json({ message: 'Database error' });
            }
            res.json({ store, ratings });
          }
        );
      }
    );
  } catch (error) {
    console.error('Error in store owner dashboard route:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Server start with error handling
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
