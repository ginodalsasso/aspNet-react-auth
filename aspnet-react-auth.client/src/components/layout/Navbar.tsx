import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import LoadingSpinner from './LoadingSpinner';
import styles from './Navbar.module.css';


const Navbar: React.FC = () => {

  const { isAuthenticated, loading, clearAuth } = useAuth();

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <nav className={styles.navbar}>
      <div className={styles.container}>
        <span className={styles.logo}>
          <Link to="/">AspNet React Auth</Link>
        </span>
        <ul className={styles.links}>
          {isAuthenticated ? (
            <>
              <li>
                <Link to="/dashboard">Dashboard</Link>
              </li>
              <li>
                <Link onClick={clearAuth}>Logout</Link>
              </li>
            </>
          ) : (
            <>
              <li>
                <Link to="/login">Login</Link>
              </li>
              <li>
                <Link to="/register">Register</Link>
              </li>
            </>
          )}
        </ul>
      </div>
    </nav>
  );
};

export default Navbar;