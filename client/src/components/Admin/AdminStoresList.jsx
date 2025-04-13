// components/Admin/AdminStoresList.jsx
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'react-toastify';
import { FaSearch, FaSort, FaSortUp, FaSortDown, FaPlus, FaStar } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import './Admin.css';

const AdminStoresList = () => {
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState({ field: 'name', direction: 'asc' });

  useEffect(() => {
    fetchStores();
  }, []);

  const fetchStores = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('https://roxiler-systems-assignment-backend-y31l.onrender.com/api/admin/stores', {
        headers: { Authorization: `Bearer ${token}` },
        params: { search }
      });
      setStores(response.data);
    } catch (error) {
      toast.error('Failed to fetch stores');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    setLoading(true);
    fetchStores();
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

  const sortedStores = [...stores].sort((a, b) => {
    if (sort.field === 'rating') {
      const aValue = a[sort.field] || 0;
      const bValue = b[sort.field] || 0;
      return sort.direction === 'asc' ? aValue - bValue : bValue - aValue;
    } else {
      const aValue = a[sort.field]?.toLowerCase() || '';
      const bValue = b[sort.field]?.toLowerCase() || '';
      return sort.direction === 'asc' 
        ? aValue.localeCompare(bValue) 
        : bValue.localeCompare(aValue);
    }
  });

  return (
    <div className="admin-stores-list">
      <Navbar />
      <div className="container">
        <div className="header-section">
          <h1>Manage Stores</h1>
          <Link to="/admin/add-store" className="add-button">
            <FaPlus /> Add New Store
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
          </form>
        </div>
        
        {loading ? (
          <div className="loading">Loading stores...</div>
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
                  <th onClick={() => handleSort('rating')}>
                    Rating {getSortIcon('rating')}
                  </th>
                </tr>
              </thead>
              <tbody>
                {sortedStores.length > 0 ? (
                  sortedStores.map((store) => (
                    <tr key={store.id}>
                      <td>{store.name}</td>
                      <td>{store.email}</td>
                      <td>{store.address}</td>
                      <td>
                        {store.rating ? (
                          <div className="rating">
                            <span className="rating-value">{store.rating}</span>
                            <FaStar className="star-icon" />
                            <span className="rating-count">({store.rating_count} reviews)</span>
                          </div>
                        ) : (
                          <span className="no-rating">No ratings yet</span>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" className="no-data">
                      No stores found
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

export default AdminStoresList;