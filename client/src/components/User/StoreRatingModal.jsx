// components/User/StoreRatingModal.jsx
import React, { useState } from 'react';
import { FaStar, FaTimes } from 'react-icons/fa';
import './User.css';

const StoreRatingModal = ({ store, initialRating, onSubmit, onClose }) => {
  const [rating, setRating] = useState(initialRating);
  const [hover, setHover] = useState(0);

  return (
    <div className="modal-overlay">
      <div className="rating-modal">
        <div className="modal-header">
          <h3>Rate {store.name}</h3>
          <button className="close-button" onClick={onClose}>
            <FaTimes />
          </button>
        </div>
        
        <div className="rating-stars">
          {[...Array(5)].map((_, index) => {
            const ratingValue = index + 1;
            
            return (
              <label key={index}>
                <input
                  type="radio"
                  name="rating"
                  value={ratingValue}
                  onClick={() => setRating(ratingValue)}
                />
                <FaStar
                  className="star"
                  color={ratingValue <= (hover || rating) ? "#ffc107" : "#e4e5e9"}
                  size={40}
                  onMouseEnter={() => setHover(ratingValue)}
                  onMouseLeave={() => setHover(0)}
                />
              </label>
            );
          })}
        </div>
        
        <div className="rating-value-display">
          {rating ? `Your rating: ${rating}/5` : 'Select a rating'}
        </div>
        
        <div className="modal-actions"></div>
        <button className="cancel-button" onClick={onClose}>
            Cancel
          </button>
          <button 
            className="submit-button"
            onClick={() => onSubmit(rating)}
            disabled={rating === 0}
          >
            Submit Rating
          </button>
        </div>
      </div>
  );
};

export default StoreRatingModal;