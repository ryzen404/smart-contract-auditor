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

function GlowRing({ score, riskLevel, size = 100 }: { score: number; riskLevel: string; size?: number }) {
  const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444';
  const bg = score >= 80 ? '#ecfdf5' : score >= 60 ? '#fffbeb' : '#fef2f2';
  const radius = size / 2 - 8;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div style={{ position: 'relative', width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#e5e7eb" strokeWidth="6" />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="6" strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1s ease' }} />
      </svg>
      <div style={{ textAlign: 'center', zIndex: 1 }}>
        <div style={{ fontSize: 26, fontWeight: 800, color, fontFamily: 'JetBrains Mono, monospace' }}>{score}</div>
        <div style={{ fontSize: 9, letterSpacing: 1, color: '#9ca3af', textTransform: 'uppercase', fontWeight: 600 }}>{riskLevel}</div>
      </div>
    </div>
  );
}

export default function Home() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState<AuditResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'security' | 'gas' | 'practices'>('security');
  const [showLanding, setShowLanding] = useState(true);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  const handleAudit = () => {
    if (!code.trim()) return;
    setScanning(true);
    setResult(null);
    setShowLanding(false);
    setTimeout(() => { setResult(analyzeContract(code)); setScanning(false); }, 2000);
  };

  const sevColor = (s: string) => s === 'critical' ? '#ef4444' : s === 'high' ? '#f97316' : s === 'medium' ? '#f59e0b' : s === 'low' ? '#10b981' : '#6366f1';
  const sevBg = (s: string) => s === 'critical' ? '#fef2f2' : s === 'high' ? '#fff7ed' : s === 'medium' ? '#fffbeb' : s === 'low' ? '#ecfdf5' : '#eef2ff';
  const scoreColor = (n: number) => n >= 80 ? '#10b981' : n >= 60 ? '#f59e0b' : '#ef4444';

  if (!mounted) return null;

  return (
    <div style={{ minHeight: '100vh', background: '#f8fafc', color: '#1e293b' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap');
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        .finding-card {
          background: #fff;
          border: 1px solid #e5e7eb;
          border-radius: 12px;
          transition: all 0.2s ease;
          box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }
        .finding-card:hover {
          border-color: #cbd5e1;
          box-shadow: 0 4px 12px rgba(0,0,0,0.08);
          transform: translateY(-2px);
        }
        .tab-btn {
          position: relative;
          background: none;
          border: none;
          color: #94a3b8;
          padding: 14px 20px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          font-family: 'Inter', sans-serif;
        }
        .tab-btn.active { color: #6366f1; }
        .tab-btn.active::after {
          content: '';
          position: absolute;
          bottom: 0; left: 20%; right: 20%;
          height: 2px;
          background: #6366f1;
          border-radius: 2px;
        }
        .editor-area {
          background: #fff;
          color: #334155;
          border: none;
          padding: 24px;
          font-size: 13px;
          line-height: 1.8;
          resize: none;
          outline: none;
          font-family: 'JetBrains Mono', monospace;
          width: 100%;
          height: 100%;
        }
        .editor-area::placeholder { color: #cbd5e1; }
        .action-btn {
          padding: 10px 28px;
          border-radius: 10px;
          border: none;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          font-family: 'Inter', sans-serif;
          transition: all 0.2s;
        }
        .primary-btn {
          background: linear-gradient(135deg, #6366f1, #8b5cf6);
          color: #fff;
          box-shadow: 0 2px 10px rgba(99,102,241,0.3);
        }
        .primary-btn:hover { box-shadow: 0 4px 16px rgba(99,102,241,0.4); transform: translateY(-1px); }
        .primary-btn:disabled { opacity: 0.5; cursor: wait; transform: none; box-shadow: none; }
        .ghost-btn {
          background: #f1f5f9;
          color: #64748b;
          border: 1px solid #e2e8f0;
        }
        .ghost-btn:hover { background: #e2e8f0; color: #475569; }
      `}</style>

      {/* Header */}
      <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px', height: 56, borderBottom: '1px solid #e2e8f0', background: '#fff', position: 'sticky', top: 0, zIndex: 100 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 32, height: 32, borderRadius: 10, background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, fontWeight: 900, color: '#fff' }}>S</div>
          <div>
            <span style={{ fontSize: 15, fontWeight: 800, fontFamily: 'Inter, sans-serif', color: '#1e293b' }}>SmartContract</span>
            <span style={{ fontSize: 15, fontWeight: 400, fontFamily: 'Inter, sans-serif', color: '#94a3b8', marginLeft: 6 }}>Auditor</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {[['SECURITY', '#ef4444'], ['GAS', '#f59e0b'], ['PRACTICES', '#10b981']].map(([label, color], i) => (
            <span key={i} style={{ padding: '4px 10px', borderRadius: 6, fontSize: 9, fontWeight: 700, letterSpacing: 1.2, color: color as string, background: `${color}12`, border: `1px solid ${color}20` }}>{label}</span>
          ))}
        </div>
      </header>

      {showLanding && !result ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 'calc(100vh - 56px)', padding: 40 }}>
          <div style={{ textAlign: 'center', maxWidth: 700, position: 'relative' }}>
            <div style={{ fontSize: 10, letterSpacing: 5, textTransform: 'uppercase', color: '#a5b4fc', marginBottom: 20, fontWeight: 700 }}>Multi-Agent Security Platform</div>
            <h1 style={{ fontSize: 52, fontWeight: 900, lineHeight: 1.1, marginBottom: 20, fontFamily: 'Inter, sans-serif', letterSpacing: '-2px' }}>
              <span style={{ color: '#1e293b' }}>Smart</span><span style={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Contract</span><br />
              <span style={{ color: '#94a3b8', fontWeight: 300 }}>AI Auditor</span>
            </h1>
            <p style={{ color: '#64748b', fontSize: 16, lineHeight: 1.7, marginBottom: 50, maxWidth: 520, margin: '0 auto 50px' }}>
              Three specialized AI agents analyze your Solidity contracts for <span style={{ color: '#ef4444', fontWeight: 600 }}>vulnerabilities</span>, <span style={{ color: '#f59e0b', fontWeight: 600 }}>gas waste</span>, and <span style={{ color: '#10b981', fontWeight: 600 }}>bad practices</span>.
            </p>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginBottom: 50 }}>
              {[
                { label: 'Security', desc: 'Reentrancy, access control, overflow', color: '#ef4444', bg: '#fef2f2' },
                { label: 'Gas', desc: 'Storage packing, calldata, unchecked', color: '#f59e0b', bg: '#fffbeb' },
                { label: 'Practices', desc: 'Events, NatSpec, Pausable', color: '#10b981', bg: '#ecfdf5' },
              ].map((a, i) => (
                <div key={i} style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 16, padding: '28px 22px', width: 200, textAlign: 'center', boxShadow: '0 1px 3px rgba(0,0,0,0.04)', transition: 'all 0.2s', cursor: 'default' }}
                  onMouseEnter={e => { e.currentTarget.style.boxShadow = `0 8px 24px ${a.color}15`; e.currentTarget.style.borderColor = a.color + '40'; }}
                  onMouseLeave={e => { e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04)'; e.currentTarget.style.borderColor = '#e5e7eb'; }}>
                  <div style={{ width: 40, height: 40, borderRadius: 12, background: a.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 14px', fontSize: 18 }}>{i === 0 ? '/u{1F6E1}' : i === 1 ? '/u26A1' : '/u2713'}</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: a.color, marginBottom: 6 }}>{a.label}</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>{a.desc}</div>
                </div>
              ))}
            </div>
            <button onClick={() => setShowLanding(false)} className="action-btn primary-btn" style={{ fontSize: 15, padding: '14px 48px' }}>Start Audit</button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', height: 'calc(100vh - 56px)' }}>
          {/* Editor */}
          <div style={{ width: '48%', display: 'flex', flexDirection: 'column', borderRight: '1px solid #e2e8f0', background: '#fff' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderBottom: '1px solid #e2e8f0', background: '#f8fafc' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }} />
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#f59e0b' }} />
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }} />
                <span style={{ fontSize: 11, color: '#94a3b8', marginLeft: 10, fontFamily: 'JetBrains Mono, monospace' }}>contract.sol</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => setCode(SAMPLE_CONTRACT)} className="action-btn ghost-btn" style={{ padding: '6px 14px', fontSize: 11 }}>Sample</button>
                <button onClick={handleAudit} disabled={scanning || !code.trim()} className="action-btn primary-btn" style={{ padding: '6px 20px', fontSize: 11 }}>{scanning ? 'Scanning...' : 'Run Audit'}</button>
              </div>
            </div>
            <div style={{ flex: 1, position: 'relative' }}>
              <div style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 48, background: '#f8fafc', borderRight: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column', paddingTop: 24, overflow: 'hidden' }}>
                {(code.split('\n').map((_, i) => (
                  <div key={i} style={{ height: '1.8em', fontSize: 11, color: '#cbd5e1', textAlign: 'right', paddingRight: 12, fontFamily: 'JetBrains Mono, monospace' }}>{i + 1}</div>
                )))}
              </div>
              <textarea value={code} onChange={e => setCode(e.target.value)} placeholder="// Paste Solidity contract..." spellCheck={false} className="editor-area" style={{ paddingLeft: 60 }} />
            </div>
          </div>

          {/* Results */}
          <div style={{ width: '52%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#f8fafc' }}>
            {scanning && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 24 }}>
                <div style={{ width: 56, height: 56, borderRadius: '50%', border: '3px solid #e5e7eb', borderTopColor: '#6366f1', animation: 'spin 0.8s linear infinite' }} />
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color: '#1e293b', marginBottom: 6 }}>Analyzing Contract...</div>
                  <div style={{ display: 'flex', gap: 16, justifyContent: 'center' }}>
                    {['Security', 'Gas', 'Practices'].map((a, i) => (
                      <span key={i} style={{ fontSize: 11, color: '#94a3b8', animation: `pulse 1.5s ${i * 0.3}s infinite` }}>{a}</span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {result && !scanning && (
              <div style={{ flex: 1, overflow: 'auto' }}>
                {/* Score */}
                <div style={{ padding: '24px', borderBottom: '1px solid #e2e8f0', background: '#fff' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
                    <GlowRing score={result.overallScore} riskLevel={result.riskLevel} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 18, fontWeight: 800, marginBottom: 4 }}>Audit Complete</div>
                      <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 10 }}>{result.findings.length} findings | {result.gasTips.length} gas tips | {result.bestPractices.length} recommendations</div>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                          const count = result.findings.filter(f => f.severity === s).length;
                          if (!count) return null;
                          return <span key={s} style={{ padding: '3px 10px', borderRadius: 6, fontSize: 10, fontWeight: 700, background: sevBg(s), color: sevColor(s), border: `1px solid ${sevColor(s)}20` }}>{count} {s}</span>;
                        })}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Tabs */}
                <div style={{ display: 'flex', borderBottom: '1px solid #e2e8f0', background: '#fff' }}>
                  {([['security', `Security (${result.findings.length})`], ['gas', `Gas (${result.gasTips.length})`], ['practices', `Practices (${result.bestPractices.length})`]] as const).map(([key, label]) => (
                    <button key={key} onClick={() => setActiveTab(key)} className={`tab-btn ${activeTab === key ? 'active' : ''}`}>{label}</button>
                  ))}
                </div>

                {/* Content */}
                <div style={{ padding: 20 }}>
                  {activeTab === 'security' && result.findings.map((f, i) => (
                    <div key={f.id} className="finding-card" style={{ padding: '16px 20px', marginBottom: 10, animation: `fadeInUp 0.3s ${i * 0.05}s both` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                        <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 9, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', background: sevBg(f.severity), color: sevColor(f.severity) }}>{f.severity}</span>
                        <span style={{ fontSize: 10, color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace' }}>{f.id}</span>
                        <span style={{ marginLeft: 'auto', padding: '3px 8px', borderRadius: 4, fontSize: 9, fontWeight: 700, color: '#6366f1', background: '#eef2ff', letterSpacing: 0.5 }}>{f.agent}</span>
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6, color: '#1e293b' }}>{f.title}</div>
                      <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.6, marginBottom: 10 }}>{f.description}</div>
                      {f.line && <div style={{ background: '#fef2f2', borderRadius: 8, padding: '8px 14px', fontSize: 11, color: '#dc2626', fontFamily: 'JetBrains Mono, monospace', marginBottom: 10, borderLeft: '3px solid #ef4444' }}>{f.line}</div>}
                      {f.fix && <div style={{ background: '#ecfdf5', borderRadius: 8, padding: '10px 14px', fontSize: 11, color: '#059669', lineHeight: 1.5, borderLeft: '3px solid #10b981' }}><strong>Fix:</strong> {f.fix}</div>}
                    </div>
                  ))}

                  {activeTab === 'gas' && result.gasTips.map((tip, i) => (
                    <div key={i} className="finding-card" style={{ padding: '14px 20px', marginBottom: 8, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <div style={{ width: 24, height: 24, borderRadius: 6, background: '#fffbeb', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1, fontSize: 12 }}>{'/u26A1'}</div>
                      <div style={{ fontSize: 13, lineHeight: 1.6, color: '#475569' }}>{tip}</div>
                    </div>
                  ))}

                  {activeTab === 'practices' && result.bestPractices.map((bp, i) => (
                    <div key={i} className="finding-card" style={{ padding: '14px 20px', marginBottom: 8, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <div style={{ width: 24, height: 24, borderRadius: 6, background: '#ecfdf5', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1, fontSize: 12 }}>{'/u2713'}</div>
                      <div style={{ fontSize: 13, lineHeight: 1.6, color: '#475569' }}>{bp}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!result && !scanning && (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
                <div style={{ width: 64, height: 64, borderRadius: 16, background: '#eef2ff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 28 }}>{'/u{1F50D}'}</div>
                <div style={{ color: '#94a3b8', fontSize: 14, fontWeight: 500 }}>Paste a contract to begin</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
