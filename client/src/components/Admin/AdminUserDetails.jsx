// components/Admin/AdminUserDetails.jsx
import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaUser, FaEnvelope, FaMapMarkerAlt, FaUserTag, FaStore, FaStar } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './Admin.css';

const AdminUserDetails = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const { userId } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserDetails = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) {
          toast.error('Authentication required');
          navigate('/login');
          return;
        }

        const response = await axios.get(`https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/user/${userId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setUser(response.data);
      } catch (error) {
        console.error('Error fetching user details:', error);
        if (error.response) {
          if (error.response.status === 401) {
            toast.error('Session expired. Please log in again');
            navigate('/login');
          } else if (error.response.status === 403) {
            toast.error('You do not have permission to view this information');
            navigate('/admin');
          } else if (error.response.status === 404) {
            toast.error('User not found');
            navigate('/admin/users');
          } else {
            toast.error(error.response.data.message || 'Failed to fetch user details');
          }
        } else {
          toast.error('Network error. Please try again later');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchUserDetails();
  }, [userId, navigate]);

  return (
    <div className="admin-user-details">
      <Navbar />
      <div className="container">
        <div className="back-navigation">
          <Link to="/admin/users" className="back-button">
            &larr; Back to Users List
          </Link>
        </div>

        <h1>User Details</h1>

        {loading ? (
          <div className="loading">Loading user details...</div>
        ) : user ? (
          <div className="user-details-card">
            <div className="user-detail-item">
              <FaUser className="detail-icon" />
              <div className="detail-content">
                <h3>Name</h3>
                <p>{user.name}</p>
              </div>
            </div>

            <div className="user-detail-item">
              <FaEnvelope className="detail-icon" />
              <div className="detail-content">
                <h3>Email</h3>
                <p>{user.email}</p>
              </div>
            </div>

            <div className="user-detail-item">
              <FaMapMarkerAlt className="detail-icon" />
              <div className="detail-content">
                <h3>Address</h3>
                <p>{user.address}</p>
              </div>
            </div>

            <div className="user-detail-item">
              <FaUserTag className="detail-icon" />
              <div className="detail-content">
                <h3>Role</h3>
                <p className={`role-badge ${user.role}`}>
                  {user.role === 'admin' ? 'Admin' : 
                   user.role === 'store_owner' ? 'Store Owner' : 'Normal User'}
                </p>
              </div>
            </div>

            {user.role === 'store_owner' && user.store && (
              <div className="store-owner-details">
                <div className="user-detail-item">
                  <FaStore className="detail-icon" />
                  <div className="detail-content">
                    <h3>Store</h3>
                    <p>{user.store.name}</p>
                  </div>
                </div>

                <div className="user-detail-item">
                  <FaStar className="detail-icon" />
                  <div className="detail-content">
                    <h3>Store Rating</h3>
                    <p className="store-rating">
                      {user.store.rating ? (
                        <span>{user.store.rating} / 5</span>
                      ) : (
                        <span className="no-rating">No ratings yet</span>
                      )}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="not-found">User information not available</div>
        )}
      </div>
    </div>
  );
};

export default AdminUserDetails;