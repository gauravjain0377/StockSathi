import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import Navbar from "../Navbar";
import "./AuthStyles.css";

const ACCENT = '#19c37d';

const EmailVerification = () => {
  const [email, setEmail] = useState("");
  const [verificationCode, setVerificationCode] = useState(["", "", "", "", "", ""]);
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [isVerifying, setIsVerifying] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [timer, setTimer] = useState(0);
  const navigate = useNavigate();
  const location = useLocation();

  // Environment URLs
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

  // Get email from URL query parameters or localStorage
  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const emailParam = searchParams.get('email');
    if (emailParam) {
      setEmail(emailParam);
      console.log("[Verify] Email from URL:", emailParam);
    } else {
      const storedEmail = localStorage.getItem('verificationEmail');
      if (storedEmail) {
        setEmail(storedEmail);
        console.log("[Verify] Email from localStorage:", storedEmail);
      } else {
        console.warn("[Verify] No email found in URL or localStorage");
      }
    }
  }, [location]);

  // Timer for resend cooldown
  useEffect(() => {
    let interval = null;
    if (timer > 0) {
      interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [timer]);

  // Handle input changes for verification code
  const handleCodeChange = (index, value) => {
    // Allow only numbers
    if (value && !/^\d$/.test(value)) return;
    
    const newCode = [...verificationCode];
    newCode[index] = value;
    setVerificationCode(newCode);
    
    // Auto-focus next input
    if (value && index < 5) {
      const nextInput = document.getElementById(`code-${index + 1}`);
      if (nextInput) nextInput.focus();
    }
  };

  // Handle backspace to move to previous input
  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !verificationCode[index] && index > 0) {
      const prevInput = document.getElementById(`code-${index - 1}`);
      if (prevInput) {
        prevInput.focus();
        const newCode = [...verificationCode];
        newCode[index - 1] = "";
        setVerificationCode(newCode);
      }
    }
  };

  // Resend verification code
  const handleResendCode = async () => {
    if (isResending || timer > 0) return;
    if (!email || !email.trim()) {
      setErrorMsg("Email address is required to resend the code. Please go back to signup.");
      return;
    }
    
    setIsResending(true);
    setErrorMsg("");
    setSuccessMsg("");
    
    try {
      console.log("[Verify] Resend code request, email:", email);
      const res = await axios.post(`${API_URL}/api/users/send-verification-code`, {
        email
      });
      console.log("[Verify] Resend response:", res.data);

      if (res.data.success) {
        setSuccessMsg("Verification code sent successfully!");
        setTimer(60); // 60 seconds cooldown
      } else {
        setErrorMsg(res.data.message || "Failed to resend verification code");
      }
    } catch (err) {
      console.error("[Verify] Resend failed:", err.response?.data || err.message);
      setErrorMsg(err.response?.data?.message || "Failed to resend verification code");
    } finally {
      setIsResending(false);
    }
  };

  // Verify email with code
  const handleVerifyEmail = async (e) => {
    e.preventDefault();
    
    // Check if all code fields are filled
    if (verificationCode.some(code => !code)) {
      setErrorMsg("Please enter the complete verification code");
      return;
    }
    
    const code = verificationCode.join("");
    
    setIsVerifying(true);
    setErrorMsg("");
    setSuccessMsg("");
    
    try {
      const res = await axios.post(`${API_URL}/api/users/verify-email`, {
        email,
        code
      });
      
      if (res.data.success) {
        setSuccessMsg("Email verified successfully! You can now log in.");
        // Clear verification email from localStorage
        localStorage.removeItem('verificationEmail');
        // Redirect to login after 2 seconds
        setTimeout(() => {
          navigate("/login");
        }, 2000);
      } else {
        setErrorMsg(res.data.message || "Failed to verify email");
        // Clear code fields
        setVerificationCode(["", "", "", "", "", ""]);
        document.getElementById("code-0").focus();
      }
    } catch (err) {
      setErrorMsg(err.response?.data?.message || "Failed to verify email");
      // Clear code fields
      setVerificationCode(["", "", "", "", "", ""]);
      document.getElementById("code-0").focus();
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <>
      <Navbar />
      <div style={{ background: '#FAFAFA', minHeight: '100vh', width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px 0' }}>
        <div style={{
          display: 'flex',
          width: '100%',
          maxWidth: 900,
          minHeight: 520,
          background: 'white',
          borderRadius: 24,
          boxShadow: '0 8px 32px 0 rgba(31,38,135,0.10)',
          overflow: 'hidden',
        }}>
          {/* Left: Form Card */}
          <div style={{ flex: 1.2, padding: '48px 36px', display: 'flex', flexDirection: 'column', justifyContent: 'center', background: 'white' }}>
            <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', gap: 10 }}>
              <img src="/media/images/logo.png" alt="Logo" style={{ height: 36, borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.04)', background: '#fff' }} />
              <span style={{ fontWeight: 700, fontSize: 20, color: '#222', letterSpacing: '-0.01em' }}>StockSathi</span>
            </div>
            <h2 style={{ fontSize: '2.2rem', fontWeight: 800, color: ACCENT, marginBottom: 8, fontFamily: 'Inter, Poppins, Montserrat, sans-serif' }}>Verify Your Email</h2>
            <p style={{ color: '#666', marginBottom: 24, fontSize: 16 }}>
              Please enter the 6-digit code sent to <strong>{email}</strong>
            </p>
            
            <form onSubmit={handleVerifyEmail} className="auth-form" style={{ width: '100%' }}>
              {errorMsg && (
                <div className="auth-error">
                  {errorMsg}
                </div>
              )}
              {successMsg && (
                <div className="auth-success">
                  {successMsg}
                </div>
              )}
              
              <div style={{ marginBottom: 24 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
                  {verificationCode.map((digit, index) => (
                    <input
                      key={index}
                      id={`code-${index}`}
                      type="text"
                      maxLength="1"
                      value={digit}
                      onChange={(e) => handleCodeChange(index, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(index, e)}
                      className="auth-input"
                      style={{
                        width: 50,
                        height: 50,
                        textAlign: 'center',
                        fontSize: 24,
                        fontWeight: 'bold',
                        padding: 0,
                        border: '2px solid #e0e7ef',
                        borderRadius: 12,
                        background: '#f8fafc',
                        color: '#222',
                        outline: 'none',
                        transition: 'border 0.18s',
                        textTransform: 'uppercase'
                      }}
                      disabled={isVerifying}
                    />
                  ))}
                </div>
                <div style={{ textAlign: 'center', color: '#888', fontSize: 14 }}>
                  Enter the 6-digit code
                </div>
              </div>
              
              <button 
                type="submit" 
                style={{ 
                  width: '100%', 
                  background: ACCENT, 
                  color: 'white', 
                  fontWeight: 700, 
                  fontSize: 18, 
                  border: 'none', 
                  borderRadius: 22, 
                  padding: '12px 0', 
                  marginBottom: 16, 
                  boxShadow: '0 2px 8px rgba(25,195,125,0.10)', 
                  cursor: isVerifying ? 'not-allowed' : 'pointer', 
                  transition: 'background 0.18s',
                  opacity: isVerifying ? 0.7 : 1
                }}
                disabled={isVerifying}
              >
                {isVerifying ? 'VERIFYING...' : 'VERIFY EMAIL'}
              </button>
            </form>
            
            <div style={{ textAlign: 'center', marginTop: 16 }}>
              <p style={{ color: '#666', fontSize: 15 }}>
                Didn't receive the code?{' '}
                <button
                  onClick={handleResendCode}
                  disabled={isResending || timer > 0}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: timer > 0 ? '#999' : ACCENT,
                    fontWeight: 600,
                    cursor: timer > 0 ? 'not-allowed' : 'pointer',
                    textDecoration: 'underline',
                    fontSize: 15
                  }}
                >
                  {timer > 0 ? `Resend in ${timer}s` : 'Resend Code'}
                </button>
              </p>
            </div>
          </div>
          
          {/* Right: Accent Panel */}
          <div style={{ flex: 1, background: ACCENT, color: 'white', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 32px', position: 'relative' }}>
            <h2 style={{ fontSize: '2.1rem', fontWeight: 800, marginBottom: 12, fontFamily: 'Inter, Poppins, Montserrat, sans-serif' }}>Secure Your Account</h2>
            <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 32, textAlign: 'center', opacity: 0.95 }}>
              Email verification helps protect your account<br/>from unauthorized access
            </div>
            <div style={{ width: 80, height: 80, borderRadius: '50%', background: 'rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20 }}>
              <svg width="40" height="40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default EmailVerification;