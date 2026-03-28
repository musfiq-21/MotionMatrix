import React from 'react';
import '../styles/HomePage.css';
import logo from '../assets/logo.jpeg';

const HomePage = ({ onNavigateToLogin }) => {
  return (
    <div className="homepage">
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-content">
          <div className="hero-header">
            <img src={logo} alt="MotionMatrix Logo" className="hero-logo" />
            <h1 className="hero-title">MotionMatrix</h1>
          </div>
          <p className="hero-subtitle">Revolutionizing Garment Factory Efficiency</p>
          <p className="hero-description">
            Automate activity tracking and real-time performance monitoring for smart factory operations
          </p>
          <div className="hero-buttons">
            <button className="btn btn-primary" onClick={onNavigateToLogin}>Get Started</button>
          </div>
        </div>
        <div className="hero-image">
          <div className="hero-graphic">
            <img src={logo} alt="MotionMatrix Logo" className="logo-image" />
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;
