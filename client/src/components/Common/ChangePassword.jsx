// components/Common/ChangePassword.jsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaLock } from 'react-icons/fa';
import axios from 'axios';
import Navbar from './Navbar';
import './Common.css';

const ChangePassword = () => {
  const [formData, setFormData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
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
    const { currentPassword, newPassword, confirmPassword } = formData;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      toast.error('All fields are required');
      return false;
    }
    
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match');
      return false;
    }
    
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,16}$/;
    if (!passwordRegex.test(newPassword)) {
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
      await axios.put(
        'https://roxiler-systems-assignment-backend-y31l.onrender.com/api/user/password',
        {
          currentPassword: formData.currentPassword,
          newPassword: formData.newPassword
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('Password updated successfully!');
      
      const user = JSON.parse(localStorage.getItem('user') || '{}');
      if (user.role === 'admin') {
        navigate('/admin');
      } else if (user.role === 'store_owner') {
        navigate('/store-dashboard');
      } else {
        navigate('/stores');
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to update password');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="change-password">
      <Navbar />
      <div className="container">
        <h1>Change Password</h1>
        
        <div className="form-container">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="currentPassword">
                <FaLock /> Current Password
              </label>
              <input
                type="password"
                id="currentPassword"
                name="currentPassword"
                placeholder="Enter current password"
                value={formData.currentPassword}
                onChange={handleChange}
                required
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="newPassword">
                <FaLock /> New Password
              </label>
              <input
                type="password"
                id="newPassword"
                name="newPassword"
                placeholder="8-16 chars, 1 uppercase, 1 special char"
                value={formData.newPassword}
                onChange={handleChange}
                required
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="confirmPassword">
                <FaLock /> Confirm New Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                name="confirmPassword"
                placeholder="Confirm new password"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
              />
            </div>
            
            <div className="form-actions">
              <button
                type="button"
                className="cancel-button"
                onClick={() => {
                  const user = JSON.parse(localStorage.getItem('user') || '{}');
                  if (user.role === 'admin') {
                    navigate('/admin');
                  } else if (user.role === 'store_owner') {
                    navigate('/store-dashboard');
                  } else {
                    navigate('/stores');
                  }
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="submit-button"
                disabled={loading}
              >
                {loading ? 'Updating...' : 'Update Password'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ChangePassword;