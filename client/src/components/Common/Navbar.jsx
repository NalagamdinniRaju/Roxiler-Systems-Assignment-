// components/Common/Navbar.jsx
import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FaStore, FaUser, FaUserCog, FaSignOutAlt, FaKey, FaBars } from 'react-icons/fa';
import './Common.css';

const Navbar = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const navigate = useNavigate();
  
  const user = JSON.parse(localStorage.getItem('user') || '{}');
  
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };
  
  const getUserLinks = () => {
    switch(user.role) {
      case 'admin':
        return [
          { to: '/admin', label: 'Dashboard', icon: <FaUserCog /> },
          { to: '/admin/users', label: 'Manage Users', icon: <FaUser /> },
          { to: '/admin/stores', label: 'Manage Stores', icon: <FaStore /> }
        ];
      case 'store_owner':
        return [
          { to: '/store-dashboard', label: 'Store Dashboard', icon: <FaStore /> }
        ];
      case 'user':
      default:
        return [
          { to: '/stores', label: 'Browse Stores', icon: <FaStore /> }
        ];
    }
  };
  
  return (
    <nav className="navbar">
      <div className="navbar-container">
        <div className="navbar-brand">
          <Link to={user.role === 'admin' ? '/admin' : user.role === 'store_owner' ? '/store-dashboard' : '/stores'}>
            <FaStore /> Store Ratings
          </Link>
        </div>
        
        <div className="navbar-toggle" onClick={() => setMenuOpen(!menuOpen)}>
          <FaBars />
        </div>
        
        <div className={`navbar-menu ${menuOpen ? 'active' : ''}`}>
          <ul className="navbar-links">
            {getUserLinks().map((link, index) => (
              <li key={index}>
                <Link to={link.to} onClick={() => setMenuOpen(false)}>
                  {link.icon} {link.label}
                </Link>
              </li>
            ))}
            <li>
              <Link to="/change-password" onClick={() => setMenuOpen(false)}>
                <FaKey /> Change Password
              </Link>
            </li>
          </ul>
          
          <div className="navbar-user">
            <span className="user-name">
              <FaUser /> {user.name || 'User'}
            </span>
            <button className="logout-button" onClick={handleLogout}>
              <FaSignOutAlt /> Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;