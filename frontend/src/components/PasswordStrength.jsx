import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Lock, Eye, EyeOff, Shield, AlertTriangle, Check, X } from 'lucide-react';

const commonWords = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'monkey', 'dragon', 'master', 'abc123'];

function analyzePassword(pwd) {
    if (!pwd) return null;
    const checks = {
        length: pwd.length >= 12,
        uppercase: /[A-Z]/.test(pwd),
        lowercase: /[a-z]/.test(pwd),
        numbers: /\d/.test(pwd),
        special: /[^A-Za-z0-9]/.test(pwd),
        noCommon: !commonWords.some(w => pwd.toLowerCase().includes(w)),
        longEnough: pwd.length >= 16,
    };
    const score = Object.values(checks).filter(Boolean).length;
    const entropy = Math.log2(
        (checks.uppercase ? 26 : 0) +
        (checks.lowercase ? 26 : 0) +
        (checks.numbers ? 10 : 0) +
        (checks.special ? 32 : 0) || 26
    ) * pwd.length;

    const crackTimes = entropy < 30 ? 'Instantly' : entropy < 45 ? 'Minutes' : entropy < 60 ? 'Days' : entropy < 80 ? 'Years' : 'Centuries';
    const strength = score <= 2 ? { label: 'VERY WEAK', color: '#ff2e5b', pct: 10 } :
        score <= 3 ? { label: 'WEAK', color: '#f97316', pct: 28 } :
            score <= 4 ? { label: 'FAIR', color: '#facc15', pct: 52 } :
                score <= 5 ? { label: 'STRONG', color: '#00f5ff', pct: 75 } :
                    { label: 'VERY STRONG', color: '#00ff88', pct: 100 };

    return { checks, score, entropy: Math.round(entropy), crackTimes, strength };
}

export default function PasswordStrength() {
    const [pwd, setPwd] = useState('');
    const [show, setShow] = useState(false);
    const result = analyzePassword(pwd);

    const RECS = [
        { key: 'length', label: 'At least 12 characters' },
        { key: 'uppercase', label: 'Uppercase letter (A–Z)' },
        { key: 'lowercase', label: 'Lowercase letter (a–z)' },
        { key: 'numbers', label: 'Number (0–9)' },
        { key: 'special', label: 'Special char (!@#$...)' },
        { key: 'noCommon', label: 'Not a common word' },
        { key: 'longEnough', label: 'At least 16 characters' },
    ];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Header */}
            <div style={{ textAlign: 'center' }}>
                <div className="section-eyebrow" style={{ display: 'inline-flex', marginBottom: 12 }}>
                    <Lock size={12} /> Password Analyzer
                </div>
                <h2 className="syne" style={{ fontSize: 28, fontWeight: 800 }}>
                    Password <span className="glow-text">Strength</span>
                </h2>
                <p style={{ color: 'var(--text-2)', fontSize: 13, marginTop: 4 }}>
                    All analysis happens locally — nothing is sent to any server.
                </p>
            </div>

            {/* Input */}
            <div className="glass" style={{ padding: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: '12px 16px' }}>
                    <Lock size={16} color="var(--cyan)" style={{ flexShrink: 0 }} />
                    <input
                        type={show ? 'text' : 'password'}
                        value={pwd}
                        onChange={e => setPwd(e.target.value)}
                        placeholder="Enter password to analyze..."
                        style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: 'var(--text-1)', fontSize: 16, fontFamily: 'JetBrains Mono, monospace', letterSpacing: show ? 'normal' : '0.2em' }}
                    />
                    <button onClick={() => setShow(p => !p)} style={{ background: 'none', border: 'none', color: 'var(--text-3)', cursor: 'pointer' }}>
                        {show ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                </div>

                {/* Strength bar */}
                {result && (
                    <div style={{ marginTop: 14 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                            <span style={{ fontSize: 11, fontWeight: 800, color: result.strength.color, letterSpacing: '.1em' }}>{result.strength.label}</span>
                            <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>{result.score}/7 criteria met</span>
                        </div>
                        <div style={{ height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                            <motion.div
                                animate={{ width: `${result.strength.pct}%` }}
                                transition={{ duration: 0.6, ease: 'easeOut' }}
                                style={{ height: '100%', background: result.strength.color, borderRadius: 3, boxShadow: `0 0 8px ${result.strength.color}60` }}
                            />
                        </div>
                    </div>
                )}
            </div>

            {result && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    {/* Entropy & crack time */}
                    <div className="glass" style={{ padding: 20 }}>
                        <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-3)', letterSpacing: '.15em', marginBottom: 16 }}>ANALYSIS</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Entropy</span>
                                <span className="mono" style={{ fontSize: 12, color: 'var(--cyan)', fontWeight: 700 }}>{result.entropy} bits</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>To crack</span>
                                <span className="mono" style={{ fontSize: 12, color: result.crackTimes === 'Instantly' ? 'var(--red)' : result.crackTimes === 'Centuries' ? 'var(--green)' : '#ffb830', fontWeight: 700 }}>{result.crackTimes}</span>
                            </div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                <span style={{ fontSize: 12, color: 'var(--text-2)' }}>Length</span>
                                <span className="mono" style={{ fontSize: 12, color: 'var(--text-1)', fontWeight: 700 }}>{pwd.length} chars</span>
                            </div>
                        </div>
                    </div>

                    {/* Criteria checklist */}
                    <div className="glass" style={{ padding: 20 }}>
                        <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-3)', letterSpacing: '.15em', marginBottom: 16 }}>CRITERIA</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                            {RECS.map(r => (
                                <div key={r.key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <div style={{ width: 16, height: 16, borderRadius: '50%', background: result.checks[r.key] ? 'rgba(0,255,136,0.15)' : 'rgba(255,46,91,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                                        {result.checks[r.key] ? <Check size={9} color="var(--green)" /> : <X size={9} color="var(--red)" />}
                                    </div>
                                    <span style={{ fontSize: 10, color: result.checks[r.key] ? 'var(--text-1)' : 'var(--text-3)' }}>{r.label}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
