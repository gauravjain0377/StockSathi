/**
 * Email Service - Brevo (formerly Sendinblue)
 * Sends to ANY email - Resend's onboarding@resend.dev only delivers to account owner (gjain0229)
 * Brevo free tier: 300 emails/day, works on Render
 */

let fetch;
if (typeof globalThis.fetch === 'function') {
  fetch = globalThis.fetch;
} else {
  fetch = require('node-fetch');
}

class EmailService {
  constructor() {
    this.apiKey = null;
    this.senderEmail = null;
    this.isInitialized = false;
    this.provider = 'brevo';
    this.initializeService();
  }

  initializeService() {
    try {
      const apiKey = process.env.BREVO_API_KEY;

      console.log('[EMAIL] Initializing Brevo...');
      console.log('[EMAIL] BREVO_API_KEY:', apiKey ? `${apiKey.substring(0, 12)}...` : 'MISSING');

      if (!apiKey) {
        console.error('[EMAIL] ❌ Set BREVO_API_KEY in .env (get from app.brevo.com → SMTP & API → API Keys)');
        this.isInitialized = false;
        return;
      }

      this.senderEmail = process.env.BREVO_SENDER_EMAIL || process.env.EMAIL_FROM || 'gjain0229@gmail.com';
      if (!this.senderEmail.includes('@')) {
        console.error('[EMAIL] ❌ Set BREVO_SENDER_EMAIL to your verified sender (e.g. gjain0229@gmail.com)');
        this.isInitialized = false;
        return;
      }

      this.apiKey = apiKey;
      this.isInitialized = true;

      console.log('[EMAIL] ✅ Brevo ready. Sender:', this.senderEmail, '| Sends to ANY email');
    } catch (error) {
      console.error('[EMAIL] Init error:', error.message);
      this.isInitialized = false;
    }
  }

  async sendEmail({ to, subject, html, text, replyTo, from }) {
    if (!this.isInitialized || !this.apiKey) {
      throw new Error('Email not configured. Set BREVO_API_KEY and BREVO_SENDER_EMAIL.');
    }

    const recipientEmail = (typeof to === 'string' && to.trim()) ? to.trim() : null;
    if (!recipientEmail) {
      throw new Error('Recipient email is required');
    }

    const fromEmail = from || this.senderEmail;
    const fromName = process.env.EMAIL_FROM_NAME || 'StockSathi Support';

    console.log('[EMAIL] Sending to Brevo:', { to: recipientEmail, from: fromEmail, subject });

    const payload = {
      sender: { name: fromName, email: fromEmail },
      to: [{ email: recipientEmail }],
      subject,
      htmlContent: html,
      ...(text && { textContent: text }),
      ...(replyTo && { replyTo: { email: replyTo } })
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      const data = await response.json().catch(() => ({}));
      console.log('[EMAIL] Brevo response:', { status: response.status, data });

      if (!response.ok) {
        const msg = data.message || `HTTP ${response.status}`;
        if (response.status === 400 && (msg.includes('sender') || msg.includes('Sender'))) {
          throw new Error('Verify sender in Brevo: Senders & IP → Add sender → verify gjain0229@gmail.com');
        }
        throw new Error(msg);
      }

      console.log('[EMAIL] ✅ Sent to', recipientEmail);
      return { success: true, messageId: data.messageId, accepted: [recipientEmail], rejected: [] };
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') throw new Error('Email timeout');
      throw err;
    }
  }

  async sendSupportEmail({ name, email, subject, purpose, message }) {
    const mailSubject = subject?.trim() ? `[StockSathi] ${subject}` : `[StockSathi] Support: ${purpose || 'General inquiry'}`;
    const escapeHtml = (t) => !t ? '' : String(t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
    const html = `
      <div style="font-family:Arial;max-width:640px;margin:0 auto;padding:20px;">
        <h2 style="background:#0ea5e9;color:#fff;padding:16px;">StockSathi Support Request</h2>
        <p><strong>Name:</strong> ${escapeHtml(name)}</p>
        <p><strong>Email:</strong> ${escapeHtml(email)}</p>
        <p><strong>Purpose:</strong> ${escapeHtml(purpose || 'General')}</p>
        <p><strong>Message:</strong></p>
        <pre style="background:#f8fafc;padding:12px;">${escapeHtml(message)}</pre>
      </div>`;
    return this.sendEmail({
      to: process.env.SUPPORT_TO || 'gjain0229@gmail.com',
      subject: mailSubject,
      html,
      replyTo: email
    });
  }

  async sendVerificationEmail({ email, verificationCode, isWelcome = false }) {
    const escapeHtml = (t) => !t ? '' : String(t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const html = `
      <div style="font-family:Arial;max-width:640px;margin:0 auto;padding:20px;text-align:center;">
        <h2 style="background:#0ea5e9;color:#fff;padding:16px;">StockSathi</h2>
        <p>${isWelcome ? 'Welcome! Use this code to verify your email:' : 'Your verification code:'}</p>
        <p style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#0ea5e9;">${escapeHtml(String(verificationCode))}</p>
        <p style="color:#64748b;">Expires in 15 minutes.</p>
      </div>`;
    return this.sendEmail({ to: email, subject: '[StockSathi] Email Verification Code', html });
  }

  async sendPasswordResetEmail({ email, resetCode }) {
    const escapeHtml = (t) => !t ? '' : String(t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const html = `
      <div style="font-family:Arial;max-width:640px;margin:0 auto;padding:20px;text-align:center;">
        <h2 style="background:#0ea5e9;color:#fff;padding:16px;">StockSathi</h2>
        <p>Your password reset code:</p>
        <p style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#0ea5e9;">${escapeHtml(String(resetCode))}</p>
        <p style="color:#64748b;">Expires in 15 minutes.</p>
      </div>`;
    return this.sendEmail({ to: email, subject: '[StockSathi] Password Reset Code', html });
  }
}

module.exports = new EmailService();
