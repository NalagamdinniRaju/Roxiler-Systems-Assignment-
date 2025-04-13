// components/Auth/Register.jsx
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaUser, FaLock, FaEnvelope, FaMapMarkerAlt } from 'react-icons/fa';
import axios from 'axios';
import './Auth.css';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    address: ''
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const validateForm = () => {
    const { name, email, password, address } = formData;
    
    if (name.length < 20 || name.length > 60) {
      toast.error('Name must be between 20 and 60 characters');
      return false;
    }
    
    if (address.length > 400) {
      toast.error('Address cannot exceed 400 characters');
      return false;
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      toast.error('Invalid email format');
      return false;
    }
    
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,16}$/;
    if (!passwordRegex.test(password)) {
      toast.error('Password must be 8-16 characters with at least one uppercase letter and one special character');
      return false;
    }
    
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    
    try {
      const response = await axios.post('https://roxiler-systems-assignment-backend-y31l.onrender.com/api/register', formData);
      localStorage.setItem('token', response.data.token);
      toast.success('Registration successful!');
      navigate('/stores');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>Register</h2>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <div className="input-icon">
              <FaUser />
              <input
                type="text"
                name="name"
                placeholder="Full Name (20-60 characters)"
                value={formData.name}
                onChange={handleChange}
                required
                minLength="20"
                maxLength="60"
              />
            </div>
          </div>
          <div className="form-group">
            <div className="input-icon">
              <FaEnvelope />
              <input
                type="email"
                name="email"
                placeholder="Email"
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>
          </div>
          <div className="form-group">
            <div className="input-icon">
              <FaMapMarkerAlt />
              <textarea
                name="address"
                placeholder="Address (max 400 characters)"
                value={formData.address}
                onChange={handleChange}
                required
                maxLength="400"
              />
            </div>
          </div>
          <div className="form-group">
            <div className="input-icon">
              <FaLock />
              <input
                type="password"
                name="password"
                placeholder="Password (8-16 chars, 1 uppercase, 1 special char)"
                value={formData.password}
                onChange={handleChange}
                required
              />
            </div>
          </div>
          <button type="submit" disabled={loading}>
            {loading ? 'Registering...' : 'Register'}
          </button>
        </form>
        <p>
          Already have an account? <Link to="/login">Login</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;