// components/User/UserStoresList.jsx
import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { FaSearch, FaSort, FaSortUp, FaSortDown, FaStar } from 'react-icons/fa';
import axios from 'axios';
import Navbar from '../Common/Navbar';
import StoreRatingModal from './StoreRatingModal';
import './User.css';

const UserStoresList = () => {
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState({ field: 'name', direction: 'asc' });
  const [selectedStore, setSelectedStore] = useState(null);
  const [showRatingModal, setShowRatingModal] = useState(false);

  useEffect(() => {
    fetchStores();
  }, []);

  const fetchStores = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:5000/api/stores', {
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
    if (sort.field === 'overall_rating') {
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

  const openRatingModal = (store) => {
    setSelectedStore(store);
    setShowRatingModal(true);
  };

  const handleRatingSubmit = async (rating) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        'https://roxiler-systems-assignment-backend-y31l.onrender.com/api/ratings',
        { store_id: selectedStore.id, rating },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setShowRatingModal(false);
      toast.success('Rating submitted successfully!');
      fetchStores();
    } catch (error) {
      toast.error('Failed to submit rating');
    }
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
    <div className="user-stores-list">
      <Navbar />
      <div className="container">
        <h1>Browse Stores</h1>
        
        <div className="filter-section">
          <form onSubmit={handleSearch} className="search-form">
            <div className="search-input">
              <input
                type="text"
                placeholder="Search by name or address"
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
          <div className="stores-grid">
            {sortedStores.length > 0 ? (
              sortedStores.map((store) => (
                <div key={store.id} className="store-card">
                  <h3>{store.name}</h3>
                  <p className="store-address">{store.address}</p>
                  
                  <div className="store-rating">
                    <div className="overall-rating">
                      <span>Overall Rating:</span>
                      <div className="stars">
                        {store.overall_rating ? (
                          <>
                            {renderStars(store.overall_rating)}
                            <span className="rating-value">({store.overall_rating})</span>
                          </>
                        ) : (
                          <span className="no-rating">No ratings yet</span>
                        )}
                      </div>
                    </div>
                    
                    <div className="user-rating">
                      <span>Your Rating:</span>
                      <div className="stars">
                        {store.user_rating ? (
                          <>
                            {renderStars(store.user_rating)}
                            <button 
                              className="modify-rating"
                              onClick={() => openRatingModal(store)}
                            >
                              Modify
                            </button>
                          </>
                        ) : (
                          <button 
                            className="rate-button"
                            onClick={() => openRatingModal(store)}
                          >
                            Rate this store
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="no-data">No stores found</div>
            )}
          </div>
        )}
      </div>

      {showRatingModal && (
        <StoreRatingModal
          store={selectedStore}
          initialRating={selectedStore.user_rating || 0}
          onSubmit={handleRatingSubmit}
          onClose={() => setShowRatingModal(false)}
        />
      )}
    </div>
  );
};

export default UserStoresList;