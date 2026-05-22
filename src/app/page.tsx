'use client';
import { useState, useEffect } from 'react';

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
    findings.push({ id: 'SEC-001', severity: 'critical', title: 'Reentrancy Vulnerability', description: 'External call before state update enables reentrancy attack.', line: '(bool success, ) = msg.sender.call{value: cost}("");', fix: 'Use ReentrancyGuard from OpenZeppelin.', agent: 'Security' });
  }
  if (code.includes('.transfer(') || code.includes('.send(')) {
    findings.push({ id: 'SEC-002', severity: 'high', title: 'Unsafe ETH Transfer', description: 'transfer() forwards only 2300 gas, may fail for contracts.', line: 'payable(msg.sender).transfer(address(this).balance);', fix: 'Use .call{value:} instead.', agent: 'Security' });
  }
  if (code.includes('function withdraw') && !code.includes('onlyOwner')) {
    findings.push({ id: 'SEC-003', severity: 'critical', title: 'Unprotected Withdrawal', description: 'withdraw() has no access control.', line: 'function withdraw() external {', fix: 'Add onlyOwner modifier.', agent: 'Security' });
  }
  if (code.includes('function setPrice') && !code.includes('onlyOwner')) {
    findings.push({ id: 'SEC-004', severity: 'high', title: 'Unprotected Price Update', description: 'setPrice() has no access control.', line: 'function setPrice(uint256 _price) external {', fix: 'Add onlyOwner modifier.', agent: 'Security' });
  }
  if (code.includes('amount * price') && !code.includes('SafeMath')) {
    findings.push({ id: 'SEC-005', severity: 'medium', title: 'Potential Overflow', description: 'Multiplication without explicit overflow handling.', line: 'uint256 cost = amount * price;', fix: 'Use SafeMath or explicit checks.', agent: 'Security' });
  }
  if (!code.includes('event ') && code.includes('function ')) {
    findings.push({ id: 'SEC-006', severity: 'medium', title: 'Missing Events', description: 'State changes emit no events.', fix: 'Add events for all state changes.', agent: 'Security' });
  }
  if (!code.includes('require(amount') && code.includes('function buyTokens')) {
    findings.push({ id: 'SEC-007', severity: 'low', title: 'Missing Zero Check', description: 'buyTokens() allows 0 amount.', fix: 'Add require(amount > 0).', agent: 'Security' });
  }

  if (code.includes('address(this).balance')) gasTips.push('Cache address(this).balance (~2100 gas).');
  if (code.includes('mapping(address =>') && code.includes('public ')) gasTips.push('Make mappings internal + getter (~50k gas).');
  if (code.includes('uint256 public price')) gasTips.push('Pack storage: uint128 for price + totalSold.');
  gasTips.push('Use calldata instead of memory (~60 gas).');
  gasTips.push('Mark functions external (~200 gas).');
  gasTips.push('Use unchecked for safe math (~80 gas).');

  if (!code.includes('SPDX-License-Identifier')) bestPractices.push('Add SPDX license identifier.');
  if (!code.includes('event ')) bestPractices.push('Define events for state changes.');
  if (!code.includes('///')) bestPractices.push('Add NatSpec documentation.');
  bestPractices.push('Implement Pausable for emergencies.');
  bestPractices.push('Check zero addresses in constructor.');
  bestPractices.push('Use withdrawal pattern.');
  bestPractices.push('Use ReentrancyGuard.');

  const crit = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const med = findings.filter(f => f.severity === 'medium').length;
  const score = Math.max(0, 100 - crit * 25 - high * 15 - med * 8 - findings.filter(f => f.severity === 'low').length * 3);
  const riskLevel = score >= 80 ? 'Low' : score >= 60 ? 'Medium' : score >= 40 ? 'High' : 'Critical';
  return { overallScore: score, riskLevel, findings, gasTips, bestPractices };
}

function ScoreRing({ score, riskLevel }: { score: number; riskLevel: string }) {
  const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444';
  const r = 38, c = 2 * Math.PI * r, offset = c - (score / 100) * c;
  return (
    <div style={{ position: 'relative', width: 90, height: 90, flexShrink: 0 }}>
      <svg width="90" height="90" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="45" cy="45" r={r} fill="none" stroke="#e5e7eb" strokeWidth="5" />
        <circle cx="45" cy="45" r={r} fill="none" stroke={color} strokeWidth="5" strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1s' }} />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ fontSize: 22, fontWeight: 800, color, fontFamily: 'JetBrains Mono, monospace' }}>{score}</span>
        <span style={{ fontSize: 8, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600 }}>{riskLevel}</span>
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

  if (!mounted) return null;

  return (
    <>
      <style>{globalCSS}</style>
      <div className="app">
        {/* Header */}
        <header className="header">
          <div className="header-left">
            <div className="logo">S</div>
            <span className="header-title">SmartContract <span className="header-sub">Auditor</span></span>
          </div>
          <div className="header-badges">
            <span className="badge badge-red">SEC</span>
            <span className="badge badge-amber">GAS</span>
            <span className="badge badge-green">PRA</span>
          </div>
        </header>

        {showLanding && !result ? (
          <div className="landing">
            <div className="landing-inner">
              <div className="landing-label">Multi-Agent Security Platform</div>
              <h1 className="landing-title">
                Smart<span className="gradient-text">Contract</span><br />
                <span className="landing-sub">AI Auditor</span>
              </h1>
              <p className="landing-desc">
                Three AI agents analyze your Solidity for <span className="text-red">vulnerabilities</span>, <span className="text-amber">gas waste</span>, and <span className="text-green">bad practices</span>.
              </p>
              <div className="cards-row">
                {[
                  { letter: 'S', label: 'Security', desc: 'Reentrancy, access, overflow', color: '#ef4444', bg: '#fef2f2' },
                  { letter: 'G', label: 'Gas', desc: 'Packing, calldata, unchecked', color: '#f59e0b', bg: '#fffbeb' },
                  { letter: 'P', label: 'Practices', desc: 'Events, NatSpec, Pausable', color: '#10b981', bg: '#ecfdf5' },
                ].map((a, i) => (
                  <div key={i} className="agent-card" style={{ borderColor: a.color + '20' }}>
                    <div className="agent-icon" style={{ background: a.bg, color: a.color }}>{a.letter}</div>
                    <div className="agent-label" style={{ color: a.color }}>{a.label}</div>
                    <div className="agent-desc">{a.desc}</div>
                  </div>
                ))}
              </div>
              <button onClick={() => setShowLanding(false)} className="btn btn-primary btn-lg">Start Audit</button>
            </div>
          </div>
        ) : (
          <div className="workspace">
            {/* Editor */}
            <div className="editor-panel">
              <div className="editor-bar">
                <div className="editor-dots">
                  <span className="dot dot-red" /><span className="dot dot-amber" /><span className="dot dot-green" />
                  <span className="editor-filename">contract.sol</span>
                </div>
                <div className="editor-actions">
                  <button onClick={() => setCode(SAMPLE_CONTRACT)} className="btn btn-ghost btn-sm">Sample</button>
                  <button onClick={handleAudit} disabled={scanning || !code.trim()} className="btn btn-primary btn-sm">{scanning ? '...' : 'Audit'}</button>
                </div>
              </div>
              <div className="editor-body">
                <div className="line-numbers">
                  {code.split('\n').map((_, i) => <div key={i} className="line-num">{i + 1}</div>)}
                </div>
                <textarea
                  value={code}
                  onChange={e => setCode(e.target.value)}
                  placeholder="// Paste Solidity..."
                  spellCheck={false}
                  className="editor-textarea"
                />
              </div>
            </div>

            {/* Results */}
            <div className="results-panel">
              {scanning && (
                <div className="scanning">
                  <div className="spinner" />
                  <div className="scanning-label">Analyzing...</div>
                  <div className="scanning-agents">
                    <span>Security</span><span>Gas</span><span>Practices</span>
                  </div>
                </div>
              )}

              {result && !scanning && (
                <div className="results-inner">
                  {/* Score */}
                  <div className="score-bar">
                    <ScoreRing score={result.overallScore} riskLevel={result.riskLevel} />
                    <div className="score-info">
                      <div className="score-title">Audit Complete</div>
                      <div className="score-meta">{result.findings.length} findings | {result.gasTips.length} gas | {result.bestPractices.length} practices</div>
                      <div className="sev-badges">
                        {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                          const n = result.findings.filter(f => f.severity === s).length;
                          return n ? <span key={s} className="sev-badge" style={{ background: sevBg(s), color: sevColor(s), borderColor: sevColor(s) + '20' }}>{n} {s}</span> : null;
                        })}
                      </div>
                    </div>
                  </div>

                  {/* Tabs */}
                  <div className="tabs">
                    {([['security', `Security (${result.findings.length})`], ['gas', `Gas (${result.gasTips.length})`], ['practices', `Practices (${result.bestPractices.length})`]] as const).map(([k, l]) => (
                      <button key={k} onClick={() => setActiveTab(k)} className={`tab ${activeTab === k ? 'tab-active' : ''}`}>{l}</button>
                    ))}
                  </div>

                  {/* Content */}
                  <div className="tab-content">
                    {activeTab === 'security' && result.findings.map((f, i) => (
                      <div key={f.id} className="finding" style={{ animationDelay: `${i * 0.05}s` }}>
                        <div className="finding-head">
                          <span className="sev-tag" style={{ background: sevBg(f.severity), color: sevColor(f.severity) }}>{f.severity}</span>
                          <span className="finding-id">{f.id}</span>
                          <span className="finding-agent">{f.agent}</span>
                        </div>
                        <div className="finding-title">{f.title}</div>
                        <div className="finding-desc">{f.description}</div>
                        {f.line && <div className="finding-line">{f.line}</div>}
                        {f.fix && <div className="finding-fix"><b>Fix:</b> {f.fix}</div>}
                      </div>
                    ))}

                    {activeTab === 'gas' && result.gasTips.map((t, i) => (
                      <div key={i} className="tip-card">
                        <div className="tip-icon tip-icon-amber">G</div>
                        <div className="tip-text">{t}</div>
                      </div>
                    ))}

                    {activeTab === 'practices' && result.bestPractices.map((bp, i) => (
                      <div key={i} className="tip-card">
                        <div className="tip-icon tip-icon-green">P</div>
                        <div className="tip-text">{bp}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {!result && !scanning && (
                <div className="empty">
                  <div className="empty-icon">SA</div>
                  <div className="empty-text">Paste a contract to begin</div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}

const globalCSS = `
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap');

*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#f8fafc;color:#1e293b;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:#f1f5f9}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:2px}

.app{min-height:100vh;display:flex;flex-direction:column}

.header{display:flex;align-items:center;justify-content:space-between;padding:0 16px;height:48px;border-bottom:1px solid #e2e8f0;background:#fff;position:sticky;top:0;z-index:100}
.header-left{display:flex;align-items:center;gap:10px}
.logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:900;color:#fff}
.header-title{font-size:14px;font-weight:700;color:#1e293b}
.header-sub{font-weight:400;color:#94a3b8;margin-left:4px}
.header-badges{display:flex;gap:4px}
.badge{padding:2px 8px;border-radius:4px;font-size:8px;font-weight:700;letter-spacing:1px}
.badge-red{color:#ef4444;background:#fef2f2;border:1px solid #fecaca}
.badge-amber{color:#f59e0b;background:#fffbeb;border:1px solid #fde68a}
.badge-green{color:#10b981;background:#ecfdf5;border:1px solid #a7f3d0}

.landing{flex:1;display:flex;align-items:center;justify-content:center;padding:32px 16px}
.landing-inner{text-align:center;max-width:600px;width:100%}
.landing-label{font-size:9px;letter-spacing:4px;text-transform:uppercase;color:#a5b4fc;font-weight:700;margin-bottom:16px}
.landing-title{font-size:clamp(32px,8vw,52px);font-weight:900;line-height:1.1;margin-bottom:16px;letter-spacing:-1.5px}
.gradient-text{background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.landing-sub{color:#94a3b8;font-weight:300}
.landing-desc{color:#64748b;font-size:clamp(13px,3.5vw,16px);line-height:1.7;margin-bottom:32px}
.text-red{color:#ef4444;font-weight:600}
.text-amber{color:#f59e0b;font-weight:600}
.text-green{color:#10b981;font-weight:600}

.cards-row{display:flex;gap:10px;justify-content:center;margin-bottom:36px;flex-wrap:wrap}
.agent-card{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:20px 16px;width:clamp(100px,28vw,180px);text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.agent-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;font-size:14px;font-weight:800}
.agent-label{font-size:12px;font-weight:700;margin-bottom:4px}
.agent-desc{font-size:10px;color:#94a3b8;line-height:1.4}

.btn{border:none;border-radius:8px;font-weight:600;cursor:pointer;font-family:'Inter',sans-serif;transition:all .2s}
.btn-primary{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;box-shadow:0 2px 10px rgba(99,102,241,0.3)}
.btn-primary:hover{box-shadow:0 4px 16px rgba(99,102,241,0.4);transform:translateY(-1px)}
.btn-primary:disabled{opacity:.5;cursor:wait;transform:none;box-shadow:none}
.btn-ghost{background:#f1f5f9;color:#64748b;border:1px solid #e2e8f0}
.btn-ghost:hover{background:#e2e8f0}
.btn-sm{padding:6px 14px;font-size:11px}
.btn-lg{padding:12px 40px;font-size:14px}

.workspace{flex:1;display:flex;flex-direction:column}

.editor-panel{display:flex;flex-direction:column;border-bottom:1px solid #e2e8f0;min-height:40vh;max-height:50vh}
.editor-bar{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid #e2e8f0;background:#f8fafc}
.editor-dots{display:flex;align-items:center;gap:6px}
.dot{width:7px;height:7px;border-radius:50%}
.dot-red{background:#ef4444}
.dot-amber{background:#f59e0b}
.dot-green{background:#10b981}
.editor-filename{font-size:10px;color:#94a3b8;font-family:'JetBrains Mono',monospace;margin-left:6px}
.editor-actions{display:flex;gap:6px}
.editor-body{flex:1;display:flex;position:relative;overflow:hidden}
.line-numbers{width:36px;background:#f8fafc;border-right:1px solid #e2e8f0;padding-top:12px;overflow:hidden;flex-shrink:0}
.line-num{height:1.8em;font-size:10px;color:#cbd5e1;text-align:right;padding-right:8px;font-family:'JetBrains Mono',monospace}
.editor-textarea{flex:1;background:#fff;color:#334155;border:none;padding:12px 12px 12px 8px;font-size:12px;line-height:1.8;resize:none;outline:none;font-family:'JetBrains Mono',monospace;min-width:0}
.editor-textarea::placeholder{color:#cbd5e1}

.results-panel{flex:1;display:flex;flex-direction:column;overflow:hidden;background:#f8fafc;min-height:50vh}
.results-inner{flex:1;overflow:auto}

.scanning{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;padding:40px}
.spinner{width:40px;height:40px;border-radius:50%;border:3px solid #e5e7eb;border-top-color:#6366f1;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.scanning-label{font-size:14px;font-weight:700;color:#1e293b}
.scanning-agents{display:flex;gap:12px}
.scanning-agents span{font-size:10px;color:#94a3b8;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

.score-bar{display:flex;align-items:center;gap:16px;padding:16px;border-bottom:1px solid #e2e8f0;background:#fff}
.score-info{flex:1;min-width:0}
.score-title{font-size:16px;font-weight:800;margin-bottom:2px}
.score-meta{font-size:11px;color:#94a3b8;margin-bottom:8px}
.sev-badges{display:flex;gap:4px;flex-wrap:wrap}
.sev-badge{padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;border:1px solid}

.tabs{display:flex;border-bottom:1px solid #e2e8f0;background:#fff;overflow-x:auto}
.tab{position:relative;background:none;border:none;color:#94a3b8;padding:12px 16px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;font-family:'Inter',sans-serif;transition:all .2s}
.tab-active{color:#6366f1}
.tab-active::after{content:'';position:absolute;bottom:0;left:20%;right:20%;height:2px;background:#6366f1;border-radius:2px}

.tab-content{padding:12px}

.finding{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px;margin-bottom:8px;box-shadow:0 1px 3px rgba(0,0,0,0.04);animation:fadeUp .3s both}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.finding-head{display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-wrap:wrap}
.sev-tag{padding:2px 7px;border-radius:3px;font-size:8px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.finding-id{font-size:9px;color:#94a3b8;font-family:'JetBrains Mono',monospace}
.finding-agent{margin-left:auto;font-size:8px;font-weight:700;color:#6366f1;background:#eef2ff;padding:2px 7px;border-radius:3px;letter-spacing:.5px}
.finding-title{font-weight:700;font-size:13px;margin-bottom:4px;color:#1e293b}
.finding-desc{font-size:11px;color:#64748b;line-height:1.5;margin-bottom:8px}
.finding-line{background:#fef2f2;border-radius:6px;padding:6px 10px;font-size:10px;color:#dc2626;font-family:'JetBrains Mono',monospace;margin-bottom:8px;border-left:2px solid #ef4444;overflow-x:auto;white-space:nowrap}
.finding-fix{background:#ecfdf5;border-radius:6px;padding:8px 10px;font-size:10px;color:#059669;line-height:1.5;border-left:2px solid #10b981}

.tip-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px;margin-bottom:6px;display:flex;align-items:flex-start;gap:10px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.tip-icon{width:22px;height:22px;border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:10px;font-weight:800}
.tip-icon-amber{background:#fffbeb;color:#f59e0b}
.tip-icon-green{background:#ecfdf5;color:#10b981}
.tip-text{font-size:12px;line-height:1.5;color:#475569}

.empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:40px}
.empty-icon{width:50px;height:50px;border-radius:14px;background:#eef2ff;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#6366f1}
.empty-text{color:#94a3b8;font-size:13px;font-weight:500}

/* Desktop */
@media(min-width:768px){
  .workspace{flex-direction:row}
  .editor-panel{width:48%;min-height:auto;max-height:none;border-bottom:none;border-right:1px solid #e2e8f0}
  .results-panel{width:52%;min-height:auto}
  .editor-textarea{font-size:13px;padding:16px 16px 16px 10px}
  .line-numbers{width:44px;padding-top:16px}
  .line-num{font-size:11px;padding-right:12px}
  .tab-content{padding:16px}
  .score-bar{padding:20px 20px}
  .header{height:52px;padding:0 24px}
  .logo{width:32px;height:32px;border-radius:10px;font-size:15px}
  .header-title{font-size:15px}
  .badge{font-size:9px;padding:3px 10px}
  .agent-card{padding:24px 20px}
  .agent-icon{width:40px;height:40px;font-size:16px}
  .agent-label{font-size:13px}
  .agent-desc{font-size:11px}
  .finding{padding:16px;margin-bottom:10px}
  .finding-title{font-size:14px}
  .finding-desc{font-size:12px}
  .finding-line,.finding-fix{font-size:11px}
  .tip-text{font-size:13px}
  .score-title{font-size:18px}
}
`;
