// components/Admin/AdminAddStore.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaStore, FaEnvelope, FaMapMarkerAlt, FaUser } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './Admin.css';

const AdminAddStore = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    address: '',
    owner_id: ''
  });
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [fetchingUsers, setFetchingUsers] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/users', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setUsers(response.data.filter(user => user.role !== 'admin'));
      } catch (error) {
        toast.error('Failed to fetch users');
      } finally {
        setFetchingUsers(false);
      }
    };

    fetchUsers();
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const validateForm = () => {
    const { name, email, address } = formData;
    
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
        'https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/stores',
        formData,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('Store added successfully!');
      navigate('/admin/stores');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to add store');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-add-store">
      <Navbar />
      <div className="container">
        <h1>Add New Store</h1>
        
        <div className="form-container">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="name">
                <FaStore /> Store Name
              </label>
              <input
                type="text"
                id="name"
                name="name"
                placeholder="Store Name (20-60 characters)"
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
                placeholder="Store Email"
                value={formData.email}
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
                placeholder="Store Address (max 400 characters)"
                value={formData.address}
                onChange={handleChange}
                required
                maxLength="400"
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="owner_id">
                <FaUser /> Store Owner (Optional)
              </label>
              <select
                id="owner_id"
                name="owner_id"
                value={formData.owner_id}
                onChange={handleChange}
              >
                <option value="">-- Select Store Owner --</option>
                {fetchingUsers ? (
                  <option disabled>Loading users...</option>
                ) : (
                  users.map(user => (
                    <option key={user.id} value={user.id}>
                      {user.name} ({user.email})
                    </option>
                  ))
                )}
              </select>
            </div>
            
            <div className="form-actions">
              <button 
                type="button" 
                className="cancel-button"
                onClick={() => navigate('/admin/stores')}
              >
                Cancel
              </button>
              <button 
                type="submit" 
                className="submit-button"
                disabled={loading}
              >
                {loading ? 'Adding Store...' : 'Add Store'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default AdminAddStore;