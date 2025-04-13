// components/Admin/AdminAddUser.jsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaUser, FaEnvelope, FaMapMarkerAlt, FaLock, FaUsersCog } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './Admin.css';

const AdminAddUser = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    address: '',
    role: 'user'
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
      const token = localStorage.getItem('token');
      await axios.post(
        'https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/users',
        formData,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('User added successfully!');
      navigate('/admin/users');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to add user');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-add-user">
      <Navbar />
      <div className="container">
        <h1>Add New User</h1>
        
        <div className="form-container">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="name">
                <FaUser /> Name
              </label>
              <input
                type="text"
                id="name"
                name="name"
                placeholder="Full Name (20-60 characters)"
                value={formData.name}
                onChange={handleChange}
                required
                minLength="20"
                maxLength="60"
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="email">
                <FaEnvelope /> Email
              </label>
              <input
                type="email"
                id="email"
                name="email"
                placeholder="Email"
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="password">
                <FaLock /> Password
              </label>
              <input
                type="password"
                id="password"
                name="password"
                placeholder="Password (8-16 chars, 1 uppercase, 1 special char)"
                value={formData.password}
                onChange={handleChange}
                required
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="address">
                <FaMapMarkerAlt /> Address
              </label>
              <textarea
                id="address"
                name="address"
                placeholder="Address (max 400 characters)"
                value={formData.address}
                onChange={handleChange}
                required
                maxLength="400"
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="role">
                <FaUsersCog /> Role
              </label>
              <select
                id="role"
                name="role"
                value={formData.role}
                onChange={handleChange}
                required
              >
                <option value="user">Normal User</option>
                <option value="admin">Admin</option>
                <option value="store_owner">Store Owner</option>
              </select>
            </div>
            
            <div className="form-actions">
              <button 
                type="button" 
                className="cancel-button"
                onClick={() => navigate('/admin/users')}
              >
                Cancel
              </button>
              <button 
                type="submit" 
                className="submit-button"
                disabled={loading}
              >
                {loading ? 'Adding User...' : 'Add User'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default AdminAddUser;