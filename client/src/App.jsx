import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

import Login from "./components/Auth/Login";
import Register from "./components/Auth/Register";
import ProtectedRoute from "./components/Auth/ProtectedRoute";
import AdminDashboard from "./components/Admin/AdminDashboard";
import AdminUsersList from "./components/Admin/AdminUsersList";
import AdminStoresList from "./components/Admin/AdminStoresList";
import AdminAddUser from "./components/Admin/AdminAddUser";
import AdminAddStore from "./components/Admin/AdminAddStore";
import AdminUserDetails from "./components/Admin/AdminUserDetails"; // Import the new component
import UserStoresList from "./components/User/UserStoresList";
import StoreOwnerDashboard from "./components/StoreOwner/StoreOwnerDashboard";
import ChangePassword from "./components/Common/ChangePassword";
import "./App.css";

function App() {
  return (
    <Router>
      <div className="app">
        <ToastContainer position="top-right" autoClose={3000} />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Admin Routes */}
          <Route
            path="/admin"
            element={
              <ProtectedRoute role="admin">
                <AdminDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/users"
            element={
              <ProtectedRoute role="admin">
                <AdminUsersList />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/stores"
            element={
              <ProtectedRoute role="admin">
                <AdminStoresList />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/add-user"
            element={
              <ProtectedRoute role="admin">
                <AdminAddUser />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/add-store"
            element={
              <ProtectedRoute role="admin">
                <AdminAddStore />
              </ProtectedRoute>
            }
          />
          {/* Add the new route for user details */}
          <Route
            path="/admin/user/:userId"
            element={
              <ProtectedRoute role="admin">
                <AdminUserDetails />
              </ProtectedRoute>
            }
          />

          {/* User Routes */}
          <Route
            path="/stores"
            element={
              <ProtectedRoute role="user">
                <UserStoresList />
              </ProtectedRoute>
            }
          />

          {/* Store Owner Routes */}
          <Route
            path="/store-dashboard"
            element={
              <ProtectedRoute role="store_owner">
                <StoreOwnerDashboard />
              </ProtectedRoute>
            }
          />

          {/* Common Routes */}
          <Route
            path="/change-password"
            element={
              <ProtectedRoute>
                <ChangePassword />
              </ProtectedRoute>
            }
          />

          <Route path="/" element={<Navigate to="/login" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
