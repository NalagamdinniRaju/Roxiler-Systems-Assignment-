
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaUsers, FaStore, FaStar, FaPlus } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './Admin.css';

const AdminDashboard = () => {
  const [stats, setStats] = useState({
    userCount: 0,
    storeCount: 0,
    ratingCount: 0
  });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem('token');
        
        if (!token) {
          toast.error('Authentication required');
          navigate('/login');
          return;
        }
        
        // Check if user is admin before making the request
        try {
          const userDataStr = localStorage.getItem('user');
          if (userDataStr) {
            const userData = JSON.parse(userDataStr);
            if (userData.role !== 'admin') {
              toast.error('You do not have admin privileges');
              navigate('/');
              return;
            }
          }
        } catch (err) {
          console.error('Error parsing user data:', err);
        }
        
        const response = await axios.get('https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/dashboard', {
          headers: { 
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });
        
        setStats(response.data);
      } catch (error) {
        console.error('Dashboard error:', error);
        
        // Better error handling based on status code
        if (error.response) {
          if (error.response.status === 403) {
            toast.error('You do not have permission to access the admin dashboard');
            navigate('/');
          } else if (error.response.status === 401) {
            toast.error('Session expired. Please log in again');
            localStorage.removeItem('token');
            navigate('/login');
          } else {
            toast.error('Failed to fetch dashboard data: ' + (error.response.data.message || 'Unknown error'));
          }
        } else if (error.request) {
          toast.error('Server not responding. Please try again later.');
        } else {
          toast.error('An error occurred. Please try again.');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [navigate]);

  // Function to check if token is valid
  const checkToken = () => {
    const token = localStorage.getItem('token');
    if (!token) {
      toast.error('Session expired. Please log in again');
      navigate('/login');
      return false;
    }
    return true;
  };

  return (
    <div className="admin-dashboard">
      <Navbar />
      <div className="container">
        <h1>Admin Dashboard</h1>
        
        {loading ? (
          <div className="loading">Loading dashboard data...</div>
        ) : (
          <div className="stats-container">
            <div className="stat-card">
              <div className="stat-icon">
                <FaUsers />
              </div>
              <div className="stat-info">
                <h3>Total Users</h3>
                <p>{stats.userCount}</p>
              </div>
            </div>
            
            <div className="stat-card">
              <div className="stat-icon">
                <FaStore />
              </div>
              <div className="stat-info">
                <h3>Total Stores</h3>
                <p>{stats.storeCount}</p>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">
                <FaStar />
              </div>
              <div className="stat-info">
                <h3>Total Ratings</h3>
                <p>{stats.ratingCount}</p>
              </div>
            </div>
          </div>
        )}
        
        <div className="action-buttons">
          <Link to="/admin/add-user" className="action-button" onClick={checkToken}>
            <FaPlus /> Add New User
          </Link>
          <Link to="/admin/add-store" className="action-button" onClick={checkToken}>
            <FaPlus /> Add New Store
          </Link>
        </div>
        
        <div className="navigation-links">
          <Link to="/admin/users" className="nav-link" onClick={checkToken}>
            <FaUsers /> Manage Users
          </Link>
          <Link to="/admin/stores" className="nav-link" onClick={checkToken}>
            <FaStore /> Manage Stores
          </Link>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;