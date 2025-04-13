// components/StoreOwner/StoreOwnerDashboard.jsx
import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { FaStar, FaUser, FaCalendarAlt } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './StoreOwner.css';

const StoreOwnerDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('https://roxiler-systems-assignment-backend-y31l.onrender.com/api/store/dashboard', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setDashboardData(response.data);
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  };

  const renderStars = (rating) => {
    const stars = [];
    for (let i = 1; i <= 5; i++) {
      stars.push(
        <FaStar 
          key={i} 
          className={i <= rating ? "star-filled" : "star-empty"} 
        />
      );
    }
    return stars;
  };

  return (
    <div className="store-owner-dashboard">
      <Navbar />
      <div className="container">
        <h1>Store Dashboard</h1>
        
        {loading ? (
          <div className="loading">Loading dashboard data...</div>
        ) : dashboardData ? (
          <>
            <div className="store-info">
              <h2>{dashboardData.store.name}</h2>
              <div className="store-rating">
                <span>Average Rating:</span>
                <div className="stars">
                  {dashboardData.store.rating ? (
                    <>
                      {renderStars(dashboardData.store.rating)}
                      <span className="rating-value">({dashboardData.store.rating})</span>
                    </>
                  ) : (
                    <span className="no-rating">No ratings yet</span>
                  )}
                </div>
              </div>
            </div>
            
            <div className="ratings-section">
              <h3>Customer Ratings</h3>
              
              {dashboardData.ratings.length > 0 ? (
                <div className="ratings-list">
                  {dashboardData.ratings.map((rating) => (
                    <div key={rating.id} className="rating-card">
                      <div className="rating-header">
                        <div className="user-info">
                          <FaUser className="icon" />
                          <span>{rating.name}</span>
                        </div>
                        <div className="rating-date">
                          <FaCalendarAlt className="icon" />
                          <span>{formatDate(rating.created_at)}</span>
                        </div>
                      </div>
                      <div className="rating-stars">
                        {renderStars(rating.rating)}
                        <span className="rating-value">({rating.rating}/5)</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-data">No ratings yet</div>
              )}
            </div>
          </>
        ) : (
          <div className="no-data">
            No store information available. Please contact an administrator.
          </div>
        )}
      </div>
    </div>
  );
};

export default StoreOwnerDashboard;