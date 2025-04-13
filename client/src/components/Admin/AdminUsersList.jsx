// components/Admin/AdminUsersList.jsx
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaSearch, FaSort, FaSortUp, FaSortDown, FaUserPlus } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './Admin.css';

const AdminUsersList = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [sort, setSort] = useState({ field: 'name', direction: 'asc' });

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/users', {
        headers: { Authorization: `Bearer ${token}` },
        params: { search, role: roleFilter }
      });
      setUsers(response.data);
    } catch (error) {
      toast.error('Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    setLoading(true);
    fetchUsers();
  };

  const handleSort = (field) => {
    setSort({
      field,
      direction: sort.field === field && sort.direction === 'asc' ? 'desc' : 'asc'
    });
  };

  const getSortIcon = (field) => {
    if (sort.field !== field) return <FaSort />;
    return sort.direction === 'asc' ? <FaSortUp /> : <FaSortDown />;
  };

  const sortedUsers = [...users].sort((a, b) => {
    const aValue = a[sort.field]?.toLowerCase() || '';
    const bValue = b[sort.field]?.toLowerCase() || '';
    
    if (sort.direction === 'asc') {
      return aValue.localeCompare(bValue);
    } else {
      return bValue.localeCompare(aValue);
    }
  });

  return (
    <div className="admin-users-list">
      <Navbar />
      <div className="container">
        <div className="header-section">
          <h1>Manage Users</h1>
          <Link to="/admin/add-user" className="add-button">
            <FaUserPlus /> Add New User
          </Link>
        </div>
        
        <div className="filter-section">
          <form onSubmit={handleSearch} className="search-form">
            <div className="search-input">
              <input
                type="text"
                placeholder="Search by name, email or address"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <button type="submit">
                <FaSearch />
              </button>
            </div>
            
            <select
              value={roleFilter}
              onChange={(e) => {
                setRoleFilter(e.target.value);
                setLoading(true);
                setTimeout(() => fetchUsers(), 0);
              }}
            >
              <option value="">All Roles</option>
              <option value="admin">Admin</option>
              <option value="user">Normal User</option>
              <option value="store_owner">Store Owner</option>
            </select>
          </form>
        </div>
        
        {loading ? (
          <div className="loading">Loading users...</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th onClick={() => handleSort('name')}>
                    Name {getSortIcon('name')}
                  </th>
                  <th onClick={() => handleSort('email')}>
                    Email {getSortIcon('email')}
                  </th>
                  <th onClick={() => handleSort('address')}>
                    Address {getSortIcon('address')}
                  </th>
                  <th onClick={() => handleSort('role')}>
                    Role {getSortIcon('role')}
                  </th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedUsers.length > 0 ? (
                  sortedUsers.map((user) => (
                    <tr key={user.id}>
                      <td>{user.name}</td>
                      <td>{user.email}</td>
                      <td>{user.address}</td>
                      <td>
                        <span className={`role-badge ${user.role}`}>
                          {user.role === 'admin' ? 'Admin' : 
                           user.role === 'store_owner' ? 'Store Owner' : 'Normal User'}
                        </span>
                      </td>
                      <td>
                        <Link to={`/admin/user/${user.id}`} className="view-button">
                          View Details
                        </Link>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="no-data">
                      No users found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminUsersList;