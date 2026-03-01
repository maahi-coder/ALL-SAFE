import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Scanner from './components/Scanner';
import Dashboard from './components/Dashboard';
import LiveMap from './components/LiveMap';
import Crypto from './components/Crypto';
import News from './components/News';
import History from './components/History';
import Footer from './components/Footer';
import BgCanvas from './components/BgCanvas';
import Cursor from './components/Cursor';
import CommandPalette from './components/CommandPalette';
import { ToastProvider, toast } from './components/Toast';
import './index.css';

const pages = ['hero', 'scanner', 'livemap', 'dashboard', 'crypto', 'news', 'history'];

const pageVariants = {
  initial: { opacity: 0, y: 24, filter: 'blur(8px)' },
  animate: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: .55, ease: [0.16, 1, 0.3, 1] } },
  exit: { opacity: 0, y: -16, filter: 'blur(6px)', transition: { duration: .35, ease: [0.7, 0, 0.8, 1] } },
};

// Global keyboard shortcuts
const SHORTCUTS = [
  { key: 'h', page: 'hero' },
  { key: 's', page: 'scanner' },
  { key: 'm', page: 'livemap' },
  { key: 'i', page: 'dashboard' },
  { key: 'v', page: 'crypto' },
  { key: 'n', page: 'news' },
  { key: 'l', page: 'history' },
];

export default function App() {
  const [page, setPage] = useState('hero');
  const [scrolled, setScrolled] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);
  const [threatScore, setThreatScore] = useState(104523);
  const [demoInput, setDemoInput] = useState(null);

  // Threat counter ticker (live feel)
  useEffect(() => {
    const t = setInterval(() => {
      setThreatScore(p => p + Math.floor(Math.random() * 3 + 1));
    }, 600);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const h = () => setScrolled(window.scrollY > 40);
    window.addEventListener('scroll', h, { passive: true });
    return () => window.removeEventListener('scroll', h);
  }, []);

  const nav = useCallback((p) => {
    setPage(p);
    window.scrollTo({ top: 0 });
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      // Ctrl+K or Cmd+K → Command Palette
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setCmdOpen(p => !p);
        return;
      }
      // Ignore if typing in input / textarea
      if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;

      const sc = SHORTCUTS.find(s => s.key === e.key);
      if (sc) { nav(sc.page); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [nav]);

  // Show welcome toast on load
  useEffect(() => {
    const t = setTimeout(() => {
      toast.info('ALL SAFE v2.0', 'Press Ctrl+K for the command palette. Shortcuts: H=Home, S=Scanner, M=Map');
    }, 1500);
    return () => clearTimeout(t);
  }, []);

  // Demo mode: periodic critical alert toasts
  useEffect(() => {
    const ALERTS = [
      ['CRITICAL THREAT DETECTED', 'Ransomware beacon from 185.220.101.45 → Mumbai intercepted'],
      ['EXPLOIT DETECTED', 'Log4Shell CVE-2021-44228 attempt from Beijing blocked'],
      ['PHISHING CAMPAIGN', 'Spear-phish targeting executive accounts — 14 emails quarantined'],
      ['ZERO-DAY ALERT', 'Unknown exploit kit deployed from Bucharest node'],
      ['DDoS MITIGATED', '42 Gbps volumetric flood absorbed by edge nodes'],
    ];
    let i = 0;
    const t = setInterval(() => {
      const [title, msg] = ALERTS[i % ALERTS.length];
      toast.critical(title, msg);
      i++;
    }, 22000);
    return () => clearInterval(t);
  }, []);

  return (
    <ToastProvider>
      <BgCanvas />
      <div className="noise-overlay" />
      <Cursor />

      <CommandPalette
        nav={nav}
        isOpen={cmdOpen}
        onClose={() => setCmdOpen(false)}
        onScan={(val, mode) => setDemoInput({ val, mode })}
      />

      <div className="app-shell">
        <Navbar
          page={page}
          nav={nav}
          scrolled={scrolled}
          cmdOpen={() => setCmdOpen(true)}
          threatScore={threatScore}
        />

        <main>
          <AnimatePresence mode="wait">
            {page === 'hero' && (
              <motion.div key="hero" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <Hero nav={nav} />
              </motion.div>
            )}
            {page === 'scanner' && (
              <motion.div key="scanner" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <Scanner demoInput={demoInput} onDemoConsumed={() => setDemoInput(null)} />
              </motion.div>
            )}
            {page === 'dashboard' && (
              <motion.div key="dashboard" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <Dashboard />
              </motion.div>
            )}
            {page === 'livemap' && (
              <motion.div key="livemap" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <LiveMap />
              </motion.div>
            )}
            {page === 'crypto' && (
              <motion.div key="crypto" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <Crypto />
              </motion.div>
            )}
            {page === 'news' && (
              <motion.div key="news" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <News />
              </motion.div>
            )}
            {page === 'history' && (
              <motion.div key="history" variants={pageVariants} initial="initial" animate="animate" exit="exit">
                <History />
              </motion.div>
            )}
          </AnimatePresence>
        </main>

        <Footer nav={nav} />
      </div>
    </ToastProvider>
  );
}
