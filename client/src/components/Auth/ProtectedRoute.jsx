// components/Auth/ProtectedRoute.jsx
import React from 'react';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children, role }) => {
  const token = localStorage.getItem('token');
  const user = JSON.parse(localStorage.getItem('user') || '{}');
  
  if (!token) {
    return <Navigate to="/login" />;
  }
  
  if (role && user.role !== role) {
    // Redirect based on actual role
    if (user.role === 'admin') {
      return <Navigate to="/admin" />;
    } else if (user.role === 'store_owner') {
      return <Navigate to="/store-dashboard" />;
    } else {
      return <Navigate to="/stores" />;
    }
  }
  
  return children;
};

export default ProtectedRoute;