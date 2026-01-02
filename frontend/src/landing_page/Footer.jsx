import React from "react";

export default function Footer() {
  return (
    <footer style={{ background: "#FAFAFA", fontFamily: 'Inter, Poppins, Montserrat, sans-serif', color: '#222', position: 'relative', overflow: 'hidden' }}>
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '48px 24px 0 24px', position: 'relative', zIndex: 1 }}>
        {/* Top: Logo, Brand, Tagline, Social Icons */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 0, marginBottom: 36 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
            <img src="/media/images/logo.png" alt="StockSathi Logo" style={{ height: 40, width: 40, borderRadius: 8, objectFit: 'cover', marginRight: 0 }} />
            <span style={{ fontWeight: 700, fontSize: 22, letterSpacing: 0.01 }}>StockSathi</span>
          </div>
          <div style={{ color: '#444', fontSize: 17, marginBottom: 18, maxWidth: 520, width: '100%' }}>
            India's most trusted stock trading platform with zero brokerage equity delivery and transparent pricing.
          </div>
          {/* Social Platforms Section */}
          <div style={{ marginTop: 10, marginBottom: 10, width: '100%' }}>
            <div style={{ fontWeight: 600, fontSize: 16, color: '#222', marginBottom: 8, letterSpacing: 0.01 }}>Contact</div>
            <div style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
              <a href="https://x.com/gauravjain0377" target="_blank" rel="noopener noreferrer" style={{ color: '#888', fontSize: 26, transition: 'color 0.2s' }} className="footer-social-icon"><i className="fab fa-x-twitter"></i></a>
              <a href="https://www.instagram.com/gauravjain0377/" target="_blank" rel="noopener noreferrer" style={{ color: '#888', fontSize: 26, transition: 'color 0.2s' }} className="footer-social-icon"><i className="fab fa-instagram"></i></a>
              <a href="https://www.linkedin.com/in/this-is-gaurav-jain/" target="_blank" rel="noopener noreferrer" style={{ color: '#888', fontSize: 26, transition: 'color 0.2s' }} className="footer-social-icon"><i className="fab fa-linkedin"></i></a>
              <a href="https://github.com/gauravjain0377" target="_blank" rel="noopener noreferrer" style={{ color: '#888', fontSize: 26, transition: 'color 0.2s' }} className="footer-social-icon"><i className="fab fa-github"></i></a>
            </div>
          </div>
        </div>
        {/* Divider */}
        <div style={{ borderTop: '1px solid #ececec', margin: '0 0 0 0', width: '100%' }} />
        {/* Four columns */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '32px 48px', margin: '40px 0 0 0' }}>
          <div>
            <div style={{ fontWeight: 700, marginBottom: 12, fontSize: '1.05rem' }}>Products</div>
            <div style={{ color: '#444', fontWeight: 400, fontSize: 16, lineHeight: 2 }}>
              <div>Equity Trading</div>
              <div>F&O Trading</div>
              <div>Mutual Funds</div>
              <div>IPO Applications</div>
            </div>
          </div>
          <div>
            <div style={{ fontWeight: 700, marginBottom: 12, fontSize: '1.05rem' }}>Support</div>
            <div style={{ color: '#444', fontWeight: 400, fontSize: 16, lineHeight: 2 }}>
              <div>Help Center</div>
              <div>Contact Support</div>
              <div>Trading Tutorial</div>
              <div>Market Updates</div>
            </div>
          </div>
          <div>
            <div style={{ fontWeight: 700, marginBottom: 12, fontSize: '1.05rem' }}>Legal</div>
            <div style={{ color: '#444', fontWeight: 400, fontSize: 16, lineHeight: 2 }}>
              <div>Privacy Policy</div>
              <div>Terms of Service</div>
              <div>Risk Disclosure</div>
              <div>SEBI Registration</div>
            </div>
          </div>
        </div>
        {/* Disclaimer - now full width and visually distinct */}
        <div style={{
          background: '#f5f5f5',
          borderRadius: 12,
          margin: '36px 0 0 0',
          padding: '24px 32px',
          color: '#888',
          fontWeight: 400,
          fontSize: 15,
          lineHeight: 1.8,
          textAlign: 'center',
          boxShadow: '0 2px 12px 0 rgba(0,0,0,0.03)',
          maxWidth: 900,
          marginLeft: 'auto',
          marginRight: 'auto',
          width: '100%',
        }}>
          <strong>Disclaimer:</strong> This website is a personal project created for educational and demonstration purposes only. It is not a real stock trading platform and does not provide any financial, investment, or brokerage services. This platform is not registered with SEBI, NSE, BSE, MCX, CDSL, NSDL, or any other regulatory authority.<br /><br />
          All information and features on this site are for learning purposes and should not be interpreted as financial advice or a recommendation to buy or sell any securities. Always consult a SEBI-registered stockbroker or financial advisor for real investment decisions.<br /><br />
          <strong>Note:</strong> No real transactions or user data are processed on this platform.
        </div>
        {/* Copyright */}
        <div style={{ borderTop: '1px solid #ececec', margin: '40px 0 0 0', width: '100%' }} />
        
      </div>
      {/* Large bottom text */}
      <div
        style={{
          width: '100%',
          textAlign: 'center',
          fontSize: 'clamp(3rem, 10vw, 8rem)',
          fontWeight: 800,
          color: '#cccccc',
          opacity: 0.7,
          userSelect: 'none',
          whiteSpace: 'nowrap',
          marginTop: 32,
          marginBottom: 0,
          lineHeight: 1.1,
          overflow: 'hidden',
        }}
        aria-hidden="true"
      >
        StockSathi
      </div>

      <div style={{ color: '#888', fontSize: 15, textAlign: 'center', padding: '18px 24px 8px 24px', letterSpacing: 0.01 }}>
          © 2026 StockSathi.
        </div>

      {/* FontAwesome CDN for icons (if not already included globally) */}
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
    </footer>
  );
}
