import { useState } from 'react';
import { motion } from 'framer-motion';
import { Mail, Check, X, AlertTriangle, ChevronRight, Shield } from 'lucide-react';

function parseHeaders(raw) {
    const lines = raw.split('\n');
    const headers = {};
    let current = '';
    for (const line of lines) {
        if (/^\s+/.test(line)) { headers[current] = (headers[current] || '') + ' ' + line.trim(); continue; }
        const m = line.match(/^([^:]+):\s*(.*)$/);
        if (m) { current = m[1].trim(); headers[current] = m[2].trim(); }
    }
    return headers;
}

function analyzeEmailHeaders(raw) {
    const headers = parseHeaders(raw);
    const results = { headers, flags: [], hops: [], auth: { spf: null, dkim: null, dmarc: null } };

    // SPF / DKIM / DMARC
    const authResults = headers['Authentication-Results'] || headers['ARC-Authentication-Results'] || '';
    results.auth.spf = authResults.includes('spf=pass') ? 'PASS' : authResults.includes('spf=fail') ? 'FAIL' : authResults.includes('spf=softfail') ? 'SOFTFAIL' : 'UNKNOWN';
    results.auth.dkim = authResults.includes('dkim=pass') ? 'PASS' : authResults.includes('dkim=fail') ? 'FAIL' : 'UNKNOWN';
    results.auth.dmarc = authResults.includes('dmarc=pass') ? 'PASS' : authResults.includes('dmarc=fail') ? 'FAIL' : 'UNKNOWN';

    // Received hops
    const received = raw.match(/^Received:.*$/gm) || [];
    results.hops = received.map((r, i) => ({
        idx: i + 1, raw: r.slice(10, 80) + (r.length > 80 ? '…' : ''),
    }));

    // Flags
    if (results.auth.spf === 'FAIL') results.flags.push({ type: 'critical', msg: 'SPF check FAILED — sender not authorized' });
    if (results.auth.dkim === 'FAIL') results.flags.push({ type: 'high', msg: 'DKIM signature verification FAILED' });
    if (results.auth.dmarc === 'FAIL') results.flags.push({ type: 'high', msg: 'DMARC policy check FAILED' });
    if (!headers['From']) results.flags.push({ type: 'medium', msg: 'No From header found — likely spoofed' });

    const from = headers['From'] || '';
    const replyTo = headers['Reply-To'] || '';
    if (replyTo && from && !replyTo.includes(from.split('@')[1])) {
        results.flags.push({ type: 'high', msg: `Reply-To domain differs from From domain — phishing indicator` });
    }
    if (received.length > 8) results.flags.push({ type: 'medium', msg: `Unusual hop count (${received.length}) — possible relay abuse` });

    results.fromAddr = from;
    results.toAddr = headers['To'] || '';
    results.subject = headers['Subject'] || '';
    results.date = headers['Date'] || '';
    results.messageId = headers['Message-ID'] || '';

    return results;
}

const SAMPLE = `Received: from mail.phishing-domain.xyz (mail.phishing-domain.xyz [185.220.101.45])
  by mx.google.com with ESMTP id abc123
From: "Bank Security" <security@phishing-domain.xyz>
Reply-To: attacker@gmail.com
To: victim@gmail.com
Subject: URGENT: Verify your account
Date: Sat, 28 Feb 2026 10:00:00 +0000
Message-ID: <abc123@phishing-domain.xyz>
Authentication-Results: mx.google.com;
  spf=fail (google.com: domain of phishing-domain.xyz does not designate 185.220.101.45 as permitted sender);
  dkim=fail;
  dmarc=fail`;

export default function EmailHeaderAnalyzer() {
    const [raw, setRaw] = useState('');
    const [result, setResult] = useState(null);

    const analyze = () => {
        if (!raw.trim()) return;
        setResult(analyzeEmailHeaders(raw));
    };

    const authColor = (v) => v === 'PASS' ? 'var(--green)' : v === 'FAIL' ? 'var(--red)' : v === 'SOFTFAIL' ? '#ffb830' : 'var(--text-3)';

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div style={{ textAlign: 'center' }}>
                <div className="section-eyebrow" style={{ display: 'inline-flex', marginBottom: 12 }}>
                    <Mail size={12} /> Phishing Detector
                </div>
                <h2 className="syne" style={{ fontSize: 28, fontWeight: 800 }}>
                    Email Header <span className="glow-text">Analyzer</span>
                </h2>
                <p style={{ color: 'var(--text-2)', fontSize: 13, marginTop: 4 }}>
                    Paste raw email headers to detect phishing, SPF/DKIM/DMARC failures, and relay abuse.
                </p>
            </div>

            <div className="glass" style={{ padding: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 700 }}>PASTE RAW EMAIL HEADERS</span>
                    <button
                        onClick={() => setRaw(SAMPLE)}
                        style={{ fontSize: 10, color: 'var(--cyan)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 700 }}
                    >
                        Load Sample →
                    </button>
                </div>
                <textarea
                    value={raw}
                    onChange={e => setRaw(e.target.value)}
                    placeholder={`Received: from mail.example.com...\nFrom: sender@example.com\nTo: you@example.com\n...`}
                    rows={7}
                    style={{
                        width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)',
                        borderRadius: 8, padding: 12, color: 'var(--text-1)', fontSize: 11,
                        fontFamily: 'JetBrains Mono, monospace', resize: 'vertical', outline: 'none',
                        boxSizing: 'border-box',
                    }}
                />
                <motion.button
                    onClick={analyze}
                    disabled={!raw.trim()}
                    whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                    className="btn-primary"
                    style={{ marginTop: 12, width: '100%', opacity: !raw.trim() ? 0.5 : 1 }}
                >
                    <Shield size={14} /> ANALYZE HEADERS
                </motion.button>
            </div>

            {result && (
                <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    {/* Auth results */}
                    <div className="glass" style={{ padding: 20 }}>
                        <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-3)', letterSpacing: '.15em', marginBottom: 14 }}>AUTHENTICATION RESULTS</div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
                            {[
                                { label: 'SPF', val: result.auth.spf },
                                { label: 'DKIM', val: result.auth.dkim },
                                { label: 'DMARC', val: result.auth.dmarc },
                            ].map(a => (
                                <div key={a.label} style={{ textAlign: 'center', padding: '12px 8px', borderRadius: 8, background: `${authColor(a.val)}12`, border: `1px solid ${authColor(a.val)}30` }}>
                                    <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>{a.label}</div>
                                    <div style={{ fontSize: 14, fontWeight: 800, color: authColor(a.val), letterSpacing: '.05em' }}>{a.val}</div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Flags */}
                    {result.flags.length > 0 && (
                        <div className="glass" style={{ padding: 20 }}>
                            <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--red)', letterSpacing: '.15em', marginBottom: 12 }}>⚠ THREAT FLAGS</div>
                            {result.flags.map((f, i) => (
                                <div key={i} style={{
                                    display: 'flex', gap: 10, padding: '8px 12px', borderRadius: 8, marginBottom: 8,
                                    background: f.type === 'critical' ? 'rgba(255,46,91,0.1)' : f.type === 'high' ? 'rgba(249,115,22,0.1)' : 'rgba(250,204,21,0.08)',
                                    borderLeft: `3px solid ${f.type === 'critical' ? 'var(--red)' : f.type === 'high' ? '#f97316' : '#facc15'}`,
                                }}>
                                    <AlertTriangle size={13} color={f.type === 'critical' ? 'var(--red)' : f.type === 'high' ? '#f97316' : '#facc15'} style={{ flexShrink: 0, marginTop: 1 }} />
                                    <span style={{ fontSize: 12, color: 'var(--text-1)' }}>{f.msg}</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Key headers */}
                    <div className="glass" style={{ padding: 20 }}>
                        <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-3)', letterSpacing: '.15em', marginBottom: 12 }}>KEY HEADERS</div>
                        {[
                            { label: 'From', val: result.fromAddr },
                            { label: 'To', val: result.toAddr },
                            { label: 'Subject', val: result.subject },
                            { label: 'Date', val: result.date },
                            { label: 'Message-ID', val: result.messageId },
                            { label: 'Hops', val: `${result.hops.length} mail servers` },
                        ].map(h => h.val && (
                            <div key={h.label} style={{ display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                                <span style={{ fontSize: 11, color: 'var(--text-3)', width: 80, flexShrink: 0 }}>{h.label}</span>
                                <span className="mono" style={{ fontSize: 11, color: 'var(--text-1)', wordBreak: 'break-all' }}>{h.val}</span>
                            </div>
                        ))}
                    </div>
                </motion.div>
            )}
        </div>
    );
}
