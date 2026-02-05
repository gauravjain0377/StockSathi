# Stock Trading Platform  
*A full-stack, real-time trading platform built with the MERN stack.*

A modern, scalable stock trading platform designed to provide a seamless trading experience for users — from market tracking to portfolio management.  
Developed as part of a **Software Engineering Project**, this platform merges real-time data visualization, secure authentication, and an interactive dashboard within a single unified interface.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Color Palette](#color-palette)
- [Installation](#installation)
- [Version History](#version-history)
- [Project Requirements](#project-requirements)
- [First Principles](#first-principles)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Overview

The **Stock Trading Platform** is a full-stack MERN web application that enables users to register, view live stock data, manage portfolios, track performance, and simulate trades.  
It combines a **beautiful frontend**, **real-time analytics**, and a **secure backend** built for scalability.

### Preview

> 📸 The screenshots below are placeholders. Replace the files under `docs/images/` with your own assets or real application screenshots.

| Landing Page | Authentication Flow |
|-------------|---------------------|
| ![Landing Page](docs/images/landing-page.png) | ![Auth Flow](docs/images/auth-flow.png) |

| Trading Dashboard | Portfolio & Analytics |
|-------------------|-----------------------|
| ![Trading Dashboard](docs/images/trading-dashboard.png) | ![Portfolio Analytics](docs/images/portfolio-analytics.png) |

### Key Highlights
- **Real-Time Stock Data**: Integrated with APIs for live updates  
- **Portfolio Dashboard**: Manage investments, performance, and history  
- **JWT Authentication**: Secure login/signup using JSON Web Tokens  
- **Interactive Charts**: Built-in analytics for holdings and market trends  
- **Fully Responsive UI**: Optimized for both desktop and mobile users  

---

## Features

### Frontend (Landing Page + Dashboard)
- Modern and responsive React UI  
- Login/Signup pages with animations (Framer Motion)  
- Collapsible sidebar and navigation  
- Portfolio analytics and visualization  
- Real-time stock charts using Chart.js  
- Smooth transitions with Tailwind CSS and AOS  

### ⚙️ Backend
- Express.js RESTful APIs  
- MongoDB with Mongoose for data persistence  
- JWT authentication and password hashing using bcrypt  
- User, Stock, Order, and Portfolio models  
- Secure API endpoints with middleware validation  
- Integration-ready for stock data APIs (e.g., Yahoo Finance)  

---

## Tech Stack

| Layer | Technology |
|-------|-------------|
| **Frontend** | React 18, Vite, Tailwind CSS, Axios, React Router, Framer Motion |
| **Dashboard** | Integrated into `frontend/` (React components + Chart.js + Socket.io client) |
| **Backend** | Node.js, Express.js, MongoDB, Mongoose, JWT, Bcrypt, Socket.io |
| **Database** | MongoDB Atlas |
| **Version Control** | Git & GitHub |
| **Tools** | VS Code, Postman, npm |

---

## Project Structure

```
Stock Trading Platform/
├── frontend/                 # Landing page frontend
│   ├── public/
│   │   └── images/          # Static images
│   └── src/
│       ├── landing_page/     # Landing page components
│       ├── components/       # Shared components
│       └── context/          # React contexts
│
├── dashboard/                # Trading dashboard frontend
│   ├── public/
│   │   └── images/          # Static assets
│   └── src/
│       ├── components/      # Dashboard components
│       ├── context/         # React contexts
│       ├── services/        # API services
│       └── styles/          # CSS files
│
└── backend/                 # Node.js backend server
    ├── controllers/         # Route controllers
    ├── models/              # Database models
    ├── routes/              # API routes
    ├── schema/              # Database schemas
    ├── seed/                # Database seed files
    └── middleware/          # Custom middleware
```

---

## Color Palette

The Stock Trading Platform uses a consistent color system across frontend and dashboard applications.

### Primary Colors

- **Primary Teal**: `#00796b` - Main brand color, used for primary actions and accents
- **Primary Blue**: `#1976d2` - Secondary brand color, used for links and hover states
- **Background Light**: `#FAFAFA` / `#fafbfc` - Main page background
- **Background White**: `#FFFFFF` - Card and surface backgrounds

### Status Colors

- **Success/Green**: `#10b981` / `#16a34a` - Positive changes, gains, success states
- **Danger/Red**: `#ef4444` / `#dc2626` - Negative changes, losses, error states
- **Warning/Orange**: `#f59e0b` / `#fbbf24` - Warning messages and alerts
- **Info/Cyan**: `#06b6d4` / `#22d3ee` - Informational messages

### Text Colors

- **Primary Text**: `#23272f` - Main text content
- **Secondary Text**: `#888` / `#94a3b8` - Secondary information and labels
- **Muted Text**: `#94a3b8` - Disabled or less important text

### Border Colors

- **Primary Border**: `#e2e8f0` / `#e5e7eb` - Standard borders
- **Secondary Border**: `#f1f5f9` - Subtle borders
- **Accent Border**: `#cbd5e1` - Highlighted borders

### Gradients

- **Primary Gradient**: `linear-gradient(135deg, #00796b 0%, #1976d2 100%)` - Used for hero sections and CTAs
- **Secondary Gradient**: `linear-gradient(135deg, #f093fb 0%, #f5576c 100%)` - Used for special sections

### CSS Variables

The platform uses CSS custom properties for theme management:

```css
:root {
  --accent-green: #00796b;
  --accent-blue: #1976d2;
  --bg-light: #fafbfc;
  --bg-white: #fff;
  --text-main: #23272f;
  --text-muted: #888;
}
```

---

## Installation

### Prerequisites
- Node.js ≥ 18  
- npm or yarn  
- MongoDB (local instance or MongoDB Atlas)

### Setup

1. **Clone the repository**

```bash
git clone <repository-url>
cd Stock-Trading-Platform
```

2. **Install backend dependencies**

```bash
cd backend
npm install
```

3. **Install frontend dependencies**

```bash
cd ../frontend
npm install
```

4. **Install dashboard dependencies**

```bash
cd ../dashboard
npm install
```

5. **Configure environment variables**

Create a `.env` file in the `backend` directory:

```env
PORT=3000
MONGO_URL=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
FRONTEND_URL=http://localhost:5173
DASHBOARD_URL=http://localhost:5174
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

6. **Start the backend server**

```bash
cd backend
npm run dev
```

The backend will run on `http://localhost:3000`.

7. **Start the frontend (landing page)**

```bash
cd frontend
npm run dev
```

The frontend will run on `http://localhost:5173`.

8. **Start the dashboard**

```bash
cd dashboard
npm run dev
```

The dashboard will run on `http://localhost:5174`.

Your app will be live at:

- Frontend: `http://localhost:5173`  
- Dashboard: `http://localhost:5174`  
- Backend: `http://localhost:3000`  

---

## Version History

### Version 3.0 (Current)
- **Enhanced Real-time Features**: Improved WebSocket performance and reliability
- **Advanced Analytics**: New portfolio analytics dashboard with visualizations
- **Mobile Optimization**: Enhanced mobile experience with responsive sidebar
- **Performance Improvements**: Optimized rendering and data fetching
- **Security Enhancements**: Improved authentication and session management
- **UI/UX Refinements**: Modern design updates and animations

### Version 2.0
- **Dashboard Redesign**: Complete UI overhaul with modern components
- **Real-time Stock Updates**: WebSocket integration for live market data
- **Portfolio Management**: Comprehensive holdings and positions tracking
- **Order Management System**: Buy/sell order functionality
- **Chart Integration**: Advanced financial charts using Lightweight Charts
- **Responsive Design**: Mobile-first responsive layout

### Version 1.0
- **Initial Release**: Basic trading platform functionality
- **User Authentication**: Signup, login, and password reset
- **Stock Data**: Basic stock information display
- **Portfolio Tracking**: Basic portfolio overview
- **Landing Page**: Marketing website with features showcase

---

## Project Requirements

### Functional
- User registration and authentication  
- Real-time stock data fetching  
- Portfolio tracking and visualization  
- Watchlist creation  
- Order simulation (buy/sell)  

### Non-Functional
- Secure (JWT, bcrypt)  
- Fast (optimized queries, lazy loading)  
- Scalable (modular MERN architecture)  
- Responsive and interactive  

---

## First Principles

### Breaking Problems into Basic Truths & Rebuilding Solutions

This project is built on the foundation of **First Principles Thinking** - breaking down complex problems into fundamental truths and building solutions from the ground up.

### Core Principles Applied

#### 1. **User-Centric Design**
- **Truth**: Users need clear, actionable information to make trading decisions
- **Solution**: Clean, intuitive interface with real-time data and comprehensive analytics
- **Implementation**: Responsive design, clear visual hierarchy, and accessible information

#### 2. **Data Integrity**
- **Truth**: Accurate and timely data is essential for trading decisions
- **Solution**: Real-time WebSocket connections, reliable data sources, and proper error handling
- **Implementation**: Yahoo Finance API integration, WebSocket server, and data validation

#### 3. **Security First**
- **Truth**: Financial applications require robust security measures
- **Solution**: Multi-layer security with JWT, bcrypt, and secure session management
- **Implementation**: Encrypted passwords, token-based authentication, and secure API endpoints

#### 4. **Performance Optimization**
- **Truth**: Fast, responsive applications improve user experience
- **Solution**: Optimized rendering, efficient data fetching, and proper state management
- **Implementation**: React optimization, lazy loading, and efficient database queries

#### 5. **Scalability**
- **Truth**: Applications must grow with user base and features
- **Solution**: Modular architecture, scalable database design, and efficient API structure
- **Implementation**: Component-based architecture, RESTful APIs, and MongoDB for scalability

#### 6. **Maintainability**
- **Truth**: Code must be understandable and modifiable
- **Solution**: Clear code structure, comprehensive documentation, and consistent patterns
- **Implementation**: Modular components, clear naming conventions, and detailed comments

### Problem-Solving Approach

1. **Identify the Core Problem**: What is the fundamental need?
2. **Break Down to Truths**: What are the basic facts and constraints?
3. **Question Assumptions**: Challenge existing solutions and assumptions
4. **Build from Ground Up**: Create solutions based on fundamental truths
5. **Iterate and Improve**: Continuously refine based on feedback

---

## Contributing

Contributions are welcome!  
To contribute:
1. Fork the repo  
2. Create a feature branch  
3. Commit changes  
4. Submit a Pull Request  

---

## Contact

**Developed by:** Gaurav Jain  
**Email:** [jaingaurav906@gmail.com](mailto:jaingaurav906@gmail.com)  
**LinkedIn:** [this-is-gaurav-jain/](https://www.linkedin.com/in/this-is-gaurav-jain/)  
**GitHub:** [gauravjain0377](https://github.com/gauravjain0377)  
**𝕏:** [gauravjain0377](https://x.com/gauravjain0377)

---

**Built with ❤️ for Indian Traders**

*Empowering every Indian investor to make informed trading decisions.*
