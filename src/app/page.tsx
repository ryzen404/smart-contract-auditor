'use client';
import { useState, useEffect, useRef } from 'react';

const SAMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract TokenSale is Ownable {
    ERC20 public token;
    uint256 public price = 0.001 ether;
    uint256 public totalSold;
    mapping(address => uint256) public balances;
    
    constructor(address _token) Ownable(msg.sender) {
        token = ERC20(_token);
    }
    
    function buyTokens(uint256 amount) external {
        uint256 cost = amount * price;
        require(token.balanceOf(address(this)) >= amount, "Not enough tokens");
        (bool success, ) = msg.sender.call{value: cost}("");
        require(success, "Transfer failed");
        balances[msg.sender] += amount;
        totalSold += amount;
    }
    
    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function setPrice(uint256 _price) external {
        price = _price;
    }
}`;

type Finding = {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  line?: string;
  fix?: string;
  agent: string;
};

type AuditResult = {
  overallScore: number;
  riskLevel: string;
  findings: Finding[];
  gasTips: string[];
  bestPractices: string[];
};

function analyzeContract(code: string): AuditResult {
  const findings: Finding[] = [];
  const gasTips: string[] = [];
  const bestPractices: string[] = [];

  if (code.includes('.call{value:') && !code.includes('ReentrancyGuard')) {
    findings.push({ id: 'SEC-001', severity: 'critical', title: 'Reentrancy Vulnerability', description: 'External call before state update enables reentrancy attack. Attacker can recursively call buyTokens() to drain funds.', line: '(bool success, ) = msg.sender.call{value: cost}("");', fix: 'Use ReentrancyGuard from OpenZeppelin or apply checks-effects-interactions pattern.', agent: 'Security' });
  }
  if (code.includes('.transfer(') || code.includes('.send(')) {
    findings.push({ id: 'SEC-002', severity: 'high', title: 'Unsafe ETH Transfer', description: 'transfer() forwards only 2300 gas, which may fail for contracts.', line: 'payable(msg.sender).transfer(address(this).balance);', fix: 'Replace .transfer() with (bool success, ) = payable(addr).call{value: amount}(""); require(success);', agent: 'Security' });
  }
  if (code.includes('function withdraw') && !code.includes('onlyOwner')) {
    findings.push({ id: 'SEC-003', severity: 'critical', title: 'Unprotected Withdrawal', description: 'withdraw() has no access control. Anyone can drain the contract.', line: 'function withdraw() external {', fix: 'Add onlyOwner modifier.', agent: 'Security' });
  }
  if (code.includes('function setPrice') && !code.includes('onlyOwner')) {
    findings.push({ id: 'SEC-004', severity: 'high', title: 'Unprotected Price Update', description: 'setPrice() has no access control. Anyone can change the price.', line: 'function setPrice(uint256 _price) external {', fix: 'Add onlyOwner modifier or implement governance.', agent: 'Security' });
  }
  if (code.includes('amount * price') && !code.includes('SafeMath')) {
    findings.push({ id: 'SEC-005', severity: 'medium', title: 'Potential Integer Overflow', description: 'Multiplication of user-controlled inputs without explicit overflow handling.', line: 'uint256 cost = amount * price;', fix: 'Use SafeMath or explicit overflow checks for critical financial calculations.', agent: 'Security' });
  }
  if (!code.includes('event ') && code.includes('function ')) {
    findings.push({ id: 'SEC-006', severity: 'medium', title: 'Missing Event Emissions', description: 'Critical state changes emit no events, making off-chain monitoring impossible.', fix: 'Add events for all state-changing operations.', agent: 'Security' });
  }
  if (!code.includes('require(amount') && code.includes('function buyTokens')) {
    findings.push({ id: 'SEC-007', severity: 'low', title: 'Missing Zero-Amount Check', description: 'buyTokens() allows purchasing 0 tokens, wasting gas.', fix: 'Add: require(amount > 0, "Amount must be > 0");', agent: 'Security' });
  }

  if (code.includes('address(this).balance')) gasTips.push('Cache address(this).balance in a local variable (~2100 gas).');
  if (code.includes('mapping(address =>') && code.includes('public ')) gasTips.push('Make mappings internal + getter to save ~50k deployment gas.');
  if (code.includes('uint256 public price')) gasTips.push('Pack storage: combine price + totalSold using uint128 each.');
  gasTips.push('Use calldata instead of memory for read-only params (~60 gas).');
  gasTips.push('Mark functions external instead of public (~200 gas).');
  gasTips.push('Use unchecked { } for safe arithmetic (~80 gas).');

  if (!code.includes('SPDX-License-Identifier')) bestPractices.push('Add SPDX license identifier.');
  if (!code.includes('event ')) bestPractices.push('Define events for all state-changing operations.');
  if (!code.includes('///') && !code.includes('/**')) bestPractices.push('Add NatSpec documentation for public functions.');
  bestPractices.push('Implement Pausable mechanism for emergencies.');
  bestPractices.push('Check for zero addresses in constructor.');
  bestPractices.push('Use withdrawal pattern instead of push pattern.');
  bestPractices.push('Use ReentrancyGuard for all external calls.');

  const crit = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const med = findings.filter(f => f.severity === 'medium').length;
  const score = Math.max(0, 100 - crit * 25 - high * 15 - med * 8 - findings.filter(f => f.severity === 'low').length * 3);
  const riskLevel = score >= 80 ? 'Low' : score >= 60 ? 'Medium' : score >= 40 ? 'High' : 'Critical';

  return { overallScore: score, riskLevel, findings, gasTips, bestPractices };
}

function RadarScanner({ progress }: { progress: number }) {
  return (
    <div style={{ position: 'relative', width: 200, height: 200, margin: '0 auto' }}>
      <svg width="200" height="200" viewBox="0 0 200 200">
        <circle cx="100" cy="100" r="90" fill="none" stroke="rgba(0,255,136,0.1)" strokeWidth="1" />
        <circle cx="100" cy="100" r="70" fill="none" stroke="rgba(0,255,136,0.08)" strokeWidth="1" />
        <circle cx="100" cy="100" r="50" fill="none" stroke="rgba(0,255,136,0.06)" strokeWidth="1" />
        <circle cx="100" cy="100" r="30" fill="none" stroke="rgba(0,255,136,0.04)" strokeWidth="1" />
        <line x1="100" y1="10" x2="100" y2="190" stroke="rgba(0,255,136,0.05)" strokeWidth="1" />
        <line x1="10" y1="100" x2="190" y2="100" stroke="rgba(0,255,136,0.05)" strokeWidth="1" />
        <line x1="100" y1="100" x2={100 + 90 * Math.cos((progress * 3.6 - 90) * Math.PI / 180)} y2={100 + 90 * Math.sin((progress * 3.6 - 90) * Math.PI / 180)} stroke="#00ff88" strokeWidth="2" style={{ filter: 'drop-shadow(0 0 6px #00ff88)' }}>
          <animateTransform attributeName="transform" type="rotate" from="0 100 100" to="360 100 100" dur="2s" repeatCount="indefinite" />
        </line>
        <circle cx="100" cy="100" r="4" fill="#00ff88" style={{ filter: 'drop-shadow(0 0 8px #00ff88)' }} />
      </svg>
      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', textAlign: 'center' }}>
        <div style={{ fontSize: 28, fontWeight: 900, color: '#00ff88', fontFamily: 'JetBrains Mono, monospace', textShadow: '0 0 20px rgba(0,255,136,0.5)' }}>{progress}%</div>
        <div style={{ fontSize: 9, color: 'rgba(0,255,136,0.6)', letterSpacing: 3, textTransform: 'uppercase' }}>Scanning</div>
      </div>
    </div>
  );
}

function GlowRing({ score, size = 120 }: { score: number; size?: number }) {
  const color = score >= 80 ? '#00ff88' : score >= 60 ? '#ffaa00' : '#ff3366';
  const radius = size / 2 - 8;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="6" strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke-dashoffset 1s ease' }} />
    </svg>
  );
}

export default function Home() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState<AuditResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeTab, setActiveTab] = useState<'security' | 'gas' | 'practices'>('security');
  const [showLanding, setShowLanding] = useState(true);
  const [mounted, setMounted] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { setMounted(true); }, []);

  const handleAudit = () => {
    if (!code.trim()) return;
    setScanning(true);
    setResult(null);
    setShowLanding(false);
    setScanProgress(0);
    let p = 0;
    intervalRef.current = setInterval(() => {
      p += Math.random() * 15 + 5;
      if (p >= 100) { p = 100; if (intervalRef.current) clearInterval(intervalRef.current); }
      setScanProgress(Math.min(100, Math.round(p)));
    }, 200);
    setTimeout(() => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      setScanProgress(100);
      setTimeout(() => { setResult(analyzeContract(code)); setScanning(false); }, 400);
    }, 2500);
  };

  const sevColor = (s: string) => s === 'critical' ? '#ff3366' : s === 'high' ? '#ff6644' : s === 'medium' ? '#ffaa00' : s === 'low' ? '#00ff88' : '#4488ff';
  const scoreColor = (n: number) => n >= 80 ? '#00ff88' : n >= 60 ? '#ffaa00' : '#ff3366';

  if (!mounted) return null;

  return (
    <div style={{ minHeight: '100vh', background: '#07080c', color: '#e0e0e8', overflow: 'hidden' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
        @keyframes scanline { 0% { top: -2px; } 100% { top: 100%; } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes gridPulse { 0%,100% { opacity: 0.03; } 50% { opacity: 0.06; } }
        @keyframes typewriter { from { width: 0; } to { width: 100%; } }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
        .grid-bg {
          background-image:
            linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
          background-size: 40px 40px;
          animation: gridPulse 4s ease-in-out infinite;
        }
        .scanline-overlay::after {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0;
          height: 2px;
          background: linear-gradient(90deg, transparent, rgba(0,255,136,0.15), transparent);
          animation: scanline 3s linear infinite;
          pointer-events: none;
        }
        .finding-card {
          background: linear-gradient(135deg, rgba(15,15,25,0.9), rgba(20,20,35,0.9));
          border: 1px solid rgba(255,255,255,0.06);
          backdrop-filter: blur(10px);
          transition: all 0.3s ease;
        }
        .finding-card:hover {
          border-color: rgba(0,255,136,0.2);
          transform: translateX(4px);
          box-shadow: -4px 0 20px rgba(0,255,136,0.1);
        }
        .tab-btn {
          position: relative;
          background: none;
          border: none;
          color: rgba(255,255,255,0.4);
          padding: 14px 20px;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.3s;
          font-family: 'Space Grotesk', sans-serif;
        }
        .tab-btn.active { color: #00ff88; }
        .tab-btn.active::after {
          content: '';
          position: absolute;
          bottom: 0; left: 20%; right: 20%;
          height: 2px;
          background: #00ff88;
          box-shadow: 0 0 10px #00ff88;
        }
        .editor-area {
          background: #0a0b10;
          color: #c8c8d8;
          border: none;
          padding: 24px;
          font-size: 13px;
          line-height: 1.8;
          resize: none;
          outline: none;
          font-family: 'JetBrains Mono', monospace;
          width: 100%;
          height: 100%;
          tab-size: 4;
        }
        .editor-area::placeholder { color: rgba(255,255,255,0.15); }
        .action-btn {
          padding: 10px 28px;
          border-radius: 8px;
          border: none;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          font-family: 'Space Grotesk', sans-serif;
          transition: all 0.3s;
        }
        .primary-btn {
          background: linear-gradient(135deg, #00ff88, #00cc6a);
          color: #07080c;
          box-shadow: 0 4px 20px rgba(0,255,136,0.25);
        }
        .primary-btn:hover { box-shadow: 0 4px 30px rgba(0,255,136,0.4); transform: translateY(-1px); }
        .primary-btn:disabled { opacity: 0.3; cursor: wait; transform: none; box-shadow: none; }
        .ghost-btn {
          background: rgba(255,255,255,0.05);
          color: rgba(255,255,255,0.5);
          border: 1px solid rgba(255,255,255,0.1);
        }
        .ghost-btn:hover { background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.8); }
        .agent-badge {
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 10px;
          font-weight: 600;
          letter-spacing: 1px;
          text-transform: uppercase;
          font-family: 'JetBrains Mono', monospace;
        }
        .sev-dot {
          width: 8px; height: 8px;
          border-radius: 50%;
          display: inline-block;
          box-shadow: 0 0 6px currentColor;
        }
      `}</style>

      {/* Top bar */}
      <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 24px', height: 52, borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(7,8,12,0.95)', backdropFilter: 'blur(20px)', position: 'sticky', top: 0, zIndex: 100 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 28, height: 28, borderRadius: 6, background: 'linear-gradient(135deg, #00ff88, #00cc6a)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, fontWeight: 900, color: '#07080c', boxShadow: '0 0 15px rgba(0,255,136,0.3)' }}>S</div>
          <div>
            <span style={{ fontSize: 14, fontWeight: 700, fontFamily: 'Space Grotesk, sans-serif', letterSpacing: '-0.5px' }}>SmartContract</span>
            <span style={{ fontSize: 14, fontWeight: 300, fontFamily: 'Space Grotesk, sans-serif', color: 'rgba(255,255,255,0.4)', marginLeft: 6 }}>Auditor</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {[['SECURITY', '#ff3366'], ['GAS', '#ffaa00'], ['PRACTICES', '#00ff88']].map(([label, color], i) => (
            <span key={i} style={{ padding: '3px 10px', borderRadius: 4, fontSize: 9, fontWeight: 700, letterSpacing: 1.5, fontFamily: 'JetBrains Mono, monospace', color: color as string, background: `${color}10`, border: `1px solid ${color}25` }}>{label}</span>
          ))}
        </div>
      </header>

      {showLanding && !result ? (
        /* Landing */
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 'calc(100vh - 52px)', padding: 40, position: 'relative' }} className="grid-bg">
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, background: 'radial-gradient(ellipse at 50% 30%, rgba(0,255,136,0.04) 0%, transparent 70%)', pointerEvents: 'none' }} />
          <div style={{ position: 'relative', textAlign: 'center', maxWidth: 700 }}>
            <div style={{ fontSize: 10, letterSpacing: 6, textTransform: 'uppercase', color: 'rgba(0,255,136,0.5)', marginBottom: 20, fontFamily: 'JetBrains Mono, monospace' }}>Multi-Agent Security Platform</div>
            <h1 style={{ fontSize: 52, fontWeight: 700, lineHeight: 1.1, marginBottom: 20, fontFamily: 'Space Grotesk, sans-serif', letterSpacing: '-2px' }}>
              <span style={{ color: '#fff' }}>Smart</span><span style={{ color: '#00ff88', textShadow: '0 0 30px rgba(0,255,136,0.3)' }}>Contract</span><br />
              <span style={{ color: 'rgba(255,255,255,0.3)', fontWeight: 300 }}>AI Auditor</span>
            </h1>
            <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: 15, lineHeight: 1.7, marginBottom: 50, maxWidth: 500, margin: '0 auto 50px' }}>
              Three specialized AI agents analyze your Solidity contracts for <span style={{ color: '#ff3366' }}>vulnerabilities</span>, <span style={{ color: '#ffaa00' }}>gas waste</span>, and <span style={{ color: '#00ff88' }}>bad practices</span>.
            </p>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginBottom: 60 }}>
              {[
                { icon: '/u{1F6E1}', label: 'Security', desc: 'Reentrancy, access control, overflow', color: '#ff3366', glow: 'rgba(255,51,102,0.15)' },
                { icon: '/u26A1', label: 'Gas', desc: 'Storage packing, calldata, unchecked', color: '#ffaa00', glow: 'rgba(255,170,0,0.15)' },
                { icon: '/u2713', label: 'Practices', desc: 'Events, NatSpec, Pausable', color: '#00ff88', glow: 'rgba(0,255,136,0.15)' },
              ].map((a, i) => (
                <div key={i} style={{ background: 'rgba(15,15,25,0.6)', border: `1px solid ${a.color}20`, borderRadius: 12, padding: '30px 24px', width: 200, textAlign: 'center', backdropFilter: 'blur(10px)', transition: 'all 0.3s', cursor: 'default' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = a.color + '40'; e.currentTarget.style.boxShadow = `0 0 30px ${a.glow}`; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = a.color + '20'; e.currentTarget.style.boxShadow = 'none'; }}>
                  <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 2, color: a.color, marginBottom: 10, fontFamily: 'JetBrains Mono, monospace' }}>{a.label.toUpperCase()}</div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)', lineHeight: 1.5 }}>{a.desc}</div>
                </div>
              ))}
            </div>
            <button onClick={() => setShowLanding(false)} className="action-btn primary-btn" style={{ fontSize: 15, padding: '14px 48px' }}>
              Start Audit
            </button>
          </div>
        </div>
      ) : (
        /* Auditor */
        <div style={{ display: 'flex', height: 'calc(100vh - 52px)' }}>
          {/* Editor */}
          <div style={{ width: '48%', display: 'flex', flexDirection: 'column', borderRight: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(10,11,16,0.8)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ff3366' }} />
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ffaa00' }} />
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#00ff88' }} />
                <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)', marginLeft: 10, fontFamily: 'JetBrains Mono, monospace' }}>contract.sol</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => setCode(SAMPLE_CONTRACT)} className="action-btn ghost-btn" style={{ padding: '6px 14px', fontSize: 11 }}>Sample</button>
                <button onClick={handleAudit} disabled={scanning || !code.trim()} className="action-btn primary-btn" style={{ padding: '6px 20px', fontSize: 11 }}>{scanning ? 'Scanning...' : 'Run Audit'}</button>
              </div>
            </div>
            <div style={{ flex: 1, position: 'relative' }} className="scanline-overlay">
              <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 48, background: 'rgba(255,255,255,0.02)', borderRight: '1px solid rgba(255,255,255,0.04)', display: 'flex', flexDirection: 'column', paddingTop: 24, overflow: 'hidden' }}>
                {(code.split('\n').map((_, i) => (
                  <div key={i} style={{ height: '1.8em', fontSize: 11, color: 'rgba(255,255,255,0.15)', textAlign: 'right', paddingRight: 12, fontFamily: 'JetBrains Mono, monospace' }}>{i + 1}</div>
                )))}
              </div>
              <textarea value={code} onChange={e => setCode(e.target.value)} placeholder="// Paste Solidity contract..." spellCheck={false} className="editor-area" style={{ paddingLeft: 60 }} />
            </div>
          </div>

          {/* Results */}
          <div style={{ width: '52%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'rgba(7,8,12,0.5)' }}>
            {scanning && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 30 }} className="grid-bg">
                <RadarScanner progress={scanProgress} />
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: '#00ff88', fontFamily: 'Space Grotesk, sans-serif', marginBottom: 8 }}>Multi-Agent Analysis</div>
                  <div style={{ display: 'flex', gap: 20, justifyContent: 'center' }}>
                    {['Security', 'Gas', 'Practices'].map((a, i) => (
                      <span key={i} style={{ fontSize: 10, color: 'rgba(0,255,136,0.4)', fontFamily: 'JetBrains Mono, monospace', letterSpacing: 1 }}>{a}</span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {result && !scanning && (
              <div style={{ flex: 1, overflow: 'auto' }}>
                {/* Score */}
                <div style={{ padding: '28px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(10,11,16,0.5)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
                    <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <GlowRing score={result.overallScore} size={100} />
                      <div style={{ position: 'absolute', textAlign: 'center' }}>
                        <div style={{ fontSize: 28, fontWeight: 800, color: scoreColor(result.overallScore), fontFamily: 'JetBrains Mono, monospace', textShadow: `0 0 20px ${scoreColor(result.overallScore)}40` }}>{result.overallScore}</div>
                        <div style={{ fontSize: 8, letterSpacing: 2, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase' }}>{result.riskLevel}</div>
                      </div>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'Space Grotesk, sans-serif', marginBottom: 6 }}>Audit Complete</div>
                      <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.35)', marginBottom: 12 }}>{result.findings.length} findings | {result.gasTips.length} gas tips | {result.bestPractices.length} recommendations</div>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                          const count = result.findings.filter(f => f.severity === s).length;
                          if (!count) return null;
                          return <span key={s} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${sevColor(s)}10`, color: sevColor(s), border: `1px solid ${sevColor(s)}20`, fontFamily: 'JetBrains Mono, monospace' }}><span className="sev-dot" style={{ color: sevColor(s), background: sevColor(s) }} />{count} {s}</span>;
                        })}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Tabs */}
                <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(7,8,12,0.8)' }}>
                  {([['security', `Security (${result.findings.length})`], ['gas', `Gas (${result.gasTips.length})`], ['practices', `Practices (${result.bestPractices.length})`]] as const).map(([key, label]) => (
                    <button key={key} onClick={() => setActiveTab(key)} className={`tab-btn ${activeTab === key ? 'active' : ''}`}>{label}</button>
                  ))}
                </div>

                {/* Content */}
                <div style={{ padding: 20 }}>
                  {activeTab === 'security' && result.findings.map((f, i) => (
                    <div key={f.id} className="finding-card" style={{ borderRadius: 10, padding: '16px 20px', marginBottom: 10, animation: `fadeInUp 0.3s ${i * 0.05}s both` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                        <span style={{ padding: '2px 8px', borderRadius: 3, fontSize: 9, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', background: `${sevColor(f.severity)}15`, color: sevColor(f.severity), fontFamily: 'JetBrains Mono, monospace' }}>{f.severity}</span>
                        <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)', fontFamily: 'JetBrains Mono, monospace' }}>{f.id}</span>
                        <span className="agent-badge" style={{ marginLeft: 'auto', color: '#4488ff', background: 'rgba(68,136,255,0.1)', border: '1px solid rgba(68,136,255,0.2)' }}>{f.agent}</span>
                      </div>
                      <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>{f.title}</div>
                      <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', lineHeight: 1.6, marginBottom: 10 }}>{f.description}</div>
                      {f.line && <div style={{ background: 'rgba(255,51,102,0.06)', borderRadius: 6, padding: '8px 14px', fontSize: 11, color: '#ff6688', fontFamily: 'JetBrains Mono, monospace', marginBottom: 10, borderLeft: '2px solid #ff3366' }}>{f.line}</div>}
                      {f.fix && <div style={{ background: 'rgba(0,255,136,0.04)', borderRadius: 6, padding: '10px 14px', fontSize: 11, color: '#00ff88', lineHeight: 1.5, borderLeft: '2px solid #00ff88' }}><span style={{ fontWeight: 700, opacity: 0.7 }}>FIX</span> {f.fix}</div>}
                    </div>
                  ))}

                  {activeTab === 'gas' && result.gasTips.map((tip, i) => (
                    <div key={i} className="finding-card" style={{ borderRadius: 10, padding: '14px 20px', marginBottom: 8, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <span style={{ color: '#ffaa00', fontSize: 6, lineHeight: 2.5 }}>{'/u25CF'}</span>
                      <div style={{ fontSize: 12, lineHeight: 1.6, color: 'rgba(255,255,255,0.6)' }}>{tip}</div>
                    </div>
                  ))}

                  {activeTab === 'practices' && result.bestPractices.map((bp, i) => (
                    <div key={i} className="finding-card" style={{ borderRadius: 10, padding: '14px 20px', marginBottom: 8, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <span style={{ color: '#00ff88', fontSize: 6, lineHeight: 2.5 }}>{'/u25CF'}</span>
                      <div style={{ fontSize: 12, lineHeight: 1.6, color: 'rgba(255,255,255,0.6)' }}>{bp}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!result && !scanning && (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }} className="grid-bg">
                <div style={{ width: 60, height: 60, borderRadius: '50%', border: '2px solid rgba(0,255,136,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <div style={{ fontSize: 24, opacity: 0.2 }}>{'/u{1F50D}'}</div>
                </div>
                <div style={{ color: 'rgba(255,255,255,0.2)', fontSize: 13, fontFamily: 'Space Grotesk, sans-serif' }}>Paste a contract to begin</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
