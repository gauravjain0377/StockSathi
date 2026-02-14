import React, { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import { Github } from "lucide-react";
import GoogleIcon from "../../components/common/GoogleIcon";
import Navbar from "../Navbar";
import { useAuth } from "../../context/AuthContext";
import "./AuthStyles.css";

const ACCENT = '#19c37d';

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  // Environment URLs
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';
  const DASHBOARD_URL = import.meta.env.VITE_DASHBOARD_URL || 'http://localhost:5174';

  // Get redirectTo from URL query parameters
  const searchParams = new URLSearchParams(location.search);
  const redirectTo = searchParams.get('redirectTo');

  const handleLogin = async (e) => {
    e.preventDefault();
    setErrorMsg("");
    setIsLoading(true);

    // Debug: Log what we're sending
    console.log("📤 Sending login request:", { email, password: password ? "***" : "undefined" });

    try {
      const res = await axios.post(`${API_URL}/api/users/login`, {
        email,
        password,
      });

      console.log("📥 Login Response:", res.data);
      
      if (res.data.success) {
        console.log("🔐 Storing auth data:", {
          user: res.data.user,
          token: res.data.token ? "EXISTS" : "MISSING",
          tokenValue: res.data.token
        });
        
        login(res.data.user, res.data.token);
        
        // Immediate verification
        const immediateToken = localStorage.getItem('token');
        const immediateUser = localStorage.getItem('user');
        const immediateLogin = localStorage.getItem('isLoggedIn');
        console.log("🚀 Immediate verification:", {
          token: immediateToken ? "EXISTS" : "MISSING",
          tokenValue: immediateToken,
          user: immediateUser ? "EXISTS" : "MISSING",
          isLoggedIn: immediateLogin
        });
        
        // Verify storage after a delay
        setTimeout(() => {
          const storedToken = localStorage.getItem('token');
          const storedUser = localStorage.getItem('user');
          const storedLogin = localStorage.getItem('isLoggedIn');
          console.log("💾 Delayed verification - Stored data:", {
            token: storedToken ? "EXISTS" : "MISSING",
            tokenValue: storedToken,
            user: storedUser ? "EXISTS" : "MISSING",
            isLoggedIn: storedLogin
          });
          
          // Also log the actual user data for debugging
          if (storedUser) {
            try {
              const parsedUser = JSON.parse(storedUser);
              console.log("💾 Parsed user data:", parsedUser);
            } catch (e) {
              console.error("💾 Error parsing stored user data:", e);
            }
          }
        }, 100);
        
        // Show success message
        setErrorMsg("Login successful! Redirecting to dashboard...");
        
        // Immediate redirect attempt
        const immediateRedirect = () => {
          const finalToken = localStorage.getItem('token');
          const finalUser = localStorage.getItem('user');
          const finalLogin = localStorage.getItem('isLoggedIn');
          
          if (finalToken && finalUser && finalLogin === 'true') {
            console.log("🚀 Immediate redirect attempt...");
            const authParams = new URLSearchParams({
              token: finalToken,
              user: finalUser,
              isLoggedIn: finalLogin
            });
            const dashboardUrl = `${DASHBOARD_URL}?${authParams.toString()}`;
            console.log("🚀 Immediate redirect URL:", dashboardUrl);
            window.location.href = dashboardUrl;
          }
        };
        
        // Try immediate redirect
        setTimeout(immediateRedirect, 100);
        
        // Final check before redirect
        setTimeout(() => {
          const finalToken = localStorage.getItem('token');
          const finalUser = localStorage.getItem('user');
          const finalLogin = localStorage.getItem('isLoggedIn');
          console.log("🎯 Final check before redirect:", {
            token: finalToken ? "EXISTS" : "MISSING",
            tokenValue: finalToken,
            user: finalUser ? "EXISTS" : "MISSING",
            isLoggedIn: finalLogin
          });
          
          if (!finalToken || !finalUser || finalLogin !== 'true') {
            console.error("❌ CRITICAL: Auth data missing before redirect!");
            setErrorMsg("Authentication error. Please try again.");
            return;
          }
          
          console.log("🔄 Redirecting to dashboard with auth data...");
          // Pass auth data through URL parameters
          const authParams = new URLSearchParams({
            token: finalToken,
            user: finalUser,
            isLoggedIn: finalLogin
          });
          const dashboardUrl = `${DASHBOARD_URL}?${authParams.toString()}`;
          console.log("🔄 Dashboard URL:", dashboardUrl);
          
          // Try redirecting to dashboard
          try {
            window.location.href = dashboardUrl;
          } catch (error) {
            console.error("❌ Redirect failed:", error);
            // Fallback: open in new tab
            window.open(dashboardUrl, '_blank');
          }
        }, 500);
      } else {
        setErrorMsg(res.data.message || "Login failed. Please try again.");
      }
    } catch (err) {
      console.error("Login error:", err);
      console.error("Error response:", JSON.stringify(err.response?.data, null, 2));
      console.error("Error status:", err.response?.status);
      console.error("Full error object:", JSON.stringify(err, null, 2));
      setErrorMsg(err.response?.data?.message || "Login failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    window.location.href = `${API_URL}/auth/google`;
  };

    return (
    <>
      <Navbar />
      <style>{`
        input {
          background: #FAFAFA;
          color: #222;
        }
        input:focus {
          background: #fff;
          color: #222;
          border-color: #b2c7d9;
        }
        ::placeholder {
          color: #888;
          opacity: 1;
          font-weight: 500;
        }
      `}</style>
      <div style={{ background: '#FAFAFA', minHeight: '100vh', width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px 16px' }}>
        <div className="auth-split-container">
          {/* Left: Form Card */}
          <div className="auth-form-section">
            <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', gap: 10 }}>
              <img src="/media/images/logo.png" alt="Logo" style={{ height: 36, borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.04)', background: '#fff' }} />
              <span style={{ fontWeight: 700, fontSize: 20, color: '#222', letterSpacing: '-0.01em' }}>StockSathi</span>
            </div>
            <h2 style={{ fontSize: 'clamp(1.75rem, 4vw, 2.2rem)', fontWeight: 800, color: ACCENT, marginBottom: 8, fontFamily: 'Inter, Poppins, Montserrat, sans-serif' }}>Sign in to StockSathi</h2>
            <div style={{ margin: '18px 0 18px 0', display: 'flex', flexDirection: 'column', gap: 16 }}>
              <button
                onClick={handleGoogleLogin}
                style={{ display: 'flex', alignItems: 'center', gap: 14, background: '#f5f6fa', border: '1.5px solid #e0e7ef', borderRadius: 16, padding: '0 20px', height: 48, fontWeight: 600, fontSize: 17, color: '#222', boxShadow: '0 2px 8px rgba(0,0,0,0.04)', cursor: 'pointer', width: '100%', maxWidth: '100%', justifyContent: 'center', transition: 'background 0.18s' }}
              >
                <img src="/media/images/google-logo.png" alt="Google" style={{ width: 24, height: 24, background: 'none', borderRadius: 0, display: 'block' }} />
                <span style={{ fontWeight: 600, fontSize: 17 }}>Continue with Google</span>
              </button>
            </div>
            <div style={{ color: '#888', fontSize: 15, marginBottom: 18, textAlign: 'center', fontWeight: 500, letterSpacing: '0.01em' }}>or login with email</div>
            <form onSubmit={handleLogin} className="auth-form" style={{ width: '100%' }}>
              {errorMsg && (
                <div className={errorMsg.includes("successful") ? "auth-success" : "auth-error"}>
                  {errorMsg}
                </div>
              )}
              <div className="auth-input-group">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="auth-input"
                  placeholder="Email"
                  required
                  style={{ marginBottom: 16, fontSize: 16, padding: '12px 16px', border: '1.5px solid #e0e7ef', borderRadius: 12, background: '#f8fafc', color: '#222', fontWeight: 500, letterSpacing: '0.01em', boxShadow: 'none', outline: 'none', transition: 'border 0.18s', '::placeholder': { color: '#888', opacity: 1, fontWeight: 500 } }}
                />
              </div>
              <div className="auth-input-group" style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="auth-input"
                  placeholder="Password"
                  required
                  style={{ marginBottom: 8, fontSize: 16, padding: '12px 16px', border: '1.5px solid #e0e7ef', borderRadius: 12, background: '#f8fafc', color: '#222', fontWeight: 500, letterSpacing: '0.01em', boxShadow: 'none', outline: 'none', transition: 'border 0.18s', width: '100%' }}
                />
                <button type="button" onClick={() => setShowPassword(v => !v)} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, margin: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }} aria-label={showPassword ? 'Hide password' : 'Show password'}>
                  {showPassword ? (
                    // Eye open icon
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#666" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                  ) : (
                    // Eye off icon
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#666" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                      <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                  )}
                </button>
              </div>
              <div style={{ textAlign: 'right', marginBottom: 18 }}>
                <Link to="/password-reset" style={{ color: ACCENT, fontWeight: 500, fontSize: 14, textDecoration: 'none' }}>Forgot your password?</Link>
              </div>
              <button
                type="submit"
                disabled={isLoading}
                style={{
                  width: '100%',
                  background: ACCENT,
                  color: 'white',
                  fontWeight: 700,
                  fontSize: 18,
                  border: 'none',
                  borderRadius: 22,
                  padding: '12px 0',
                  marginBottom: 8,
                  boxShadow: '0 2px 8px rgba(25,195,125,0.10)',
                  cursor: isLoading ? 'not-allowed' : 'pointer',
                  transition: 'background 0.18s',
                  opacity: isLoading ? 0.9 : 1
                }}
                className={isLoading ? 'auth-btn-loading' : ''}
              >
                {isLoading ? (
                  <>
                    <span className="auth-btn-spinner" />
                    <span>Signing in...</span>
                  </>
                ) : (
                  'SIGN IN'
                )}
              </button>
              <div style={{ textAlign: 'center', marginTop: 16 }}>
                <span style={{ color: '#666', fontSize: 15 }}>Don't have an account? </span>
                <Link to="/signup" style={{ color: ACCENT, fontWeight: 600, fontSize: 15, textDecoration: 'none' }}>Sign up</Link>
              </div>
            </form>
          </div>
          {/* Right: Accent Panel */}
          <div className="auth-accent-section">
            <h2 style={{ fontSize: 'clamp(1.6rem, 3vw, 2.1rem)', fontWeight: 800, marginBottom: 12, fontFamily: 'Inter, Poppins, Montserrat, sans-serif' }}>Hello, Friend!</h2>
            <div style={{ fontSize: 'clamp(15px, 2vw, 18px)', fontWeight: 500, marginBottom: 32, textAlign: 'center', opacity: 0.95 }}>Enter your personal details<br/>and start journey with us</div>
            <Link to="/signup" style={{ border: '2px solid #fff', color: '#fff', fontWeight: 700, fontSize: 'clamp(15px, 2vw, 18px)', borderRadius: 22, padding: 'clamp(10px, 2vw, 12px) clamp(36px, 4vw, 44px)', background: 'transparent', textDecoration: 'none', transition: 'all 0.18s', boxShadow: '0 2px 8px rgba(0,0,0,0.04)', position: 'relative', overflow: 'hidden' }}
              onMouseOver={e => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseOut={e => e.currentTarget.style.background = 'transparent'}
            >
              SIGN UP
            </Link>
          </div>
        </div>
      </div>
    </>
  );
};

export default Login;