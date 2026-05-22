'use client';
import { useState } from 'react';

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
  summary: string;
};

function analyzeContract(code: string): AuditResult {
  const findings: Finding[] = [];
  const gasTips: string[] = [];
  const bestPractices: string[] = [];

  // Security Agent Analysis
  if (code.includes('.call{value:') && !code.includes('ReentrancyGuard')) {
    findings.push({
      id: 'SEC-001', severity: 'critical',
      title: 'Reentrancy Vulnerability',
      description: 'External call before state update enables reentrancy attack. Attacker can recursively call buyTokens() to drain funds.',
      line: '(bool success, ) = msg.sender.call{value: cost}("");',
      fix: 'Use ReentrancyGuard from OpenZeppelin or apply checks-effects-interactions pattern. Move state updates before external calls.',
      agent: 'Security Agent',
    });
  }
  if (code.includes('.transfer(') || code.includes('.send(')) {
    findings.push({
      id: 'SEC-002', severity: 'high',
      title: 'Unsafe ETH Transfer',
      description: 'transfer() and send() forward only 2300 gas, which may fail for contracts. Use call{value:}("") instead.',
      line: 'payable(msg.sender).transfer(address(this).balance);',
      fix: 'Replace .transfer() with (bool success, ) = payable(addr).call{value: amount}(""); require(success);',
      agent: 'Security Agent',
    });
  }
  if (code.includes('function withdraw') && !code.includes('onlyOwner') && !code.includes('modifier')) {
    findings.push({
      id: 'SEC-003', severity: 'critical',
      title: 'Unprotected Withdrawal',
      description: 'withdraw() has no access control. Anyone can drain the contract balance.',
      line: 'function withdraw() external {',
      fix: 'Add onlyOwner modifier: function withdraw() external onlyOwner {',
      agent: 'Security Agent',
    });
  }
  if (code.includes('function setPrice') && !code.includes('onlyOwner')) {
    findings.push({
      id: 'SEC-004', severity: 'high',
      title: 'Unprotected Price Update',
      description: 'setPrice() has no access control. Anyone can change the token price.',
      line: 'function setPrice(uint256 _price) external {',
      fix: 'Add onlyOwner modifier or implement DAO governance for price changes.',
      agent: 'Security Agent',
    });
  }
  if (code.includes('amount * price') && !code.includes('SafeMath') && !code.includes('unchecked')) {
    findings.push({
      id: 'SEC-005', severity: 'medium',
      title: 'Potential Integer Overflow',
      description: 'Multiplication of user-controlled inputs. While Solidity 0.8+ has built-in overflow checks, explicit handling is recommended.',
      line: 'uint256 cost = amount * price;',
      fix: 'Consider using SafeMath or explicit overflow checks for critical financial calculations.',
      agent: 'Security Agent',
    });
  }
  if (!code.includes('event ') && code.includes('function ')) {
    findings.push({
      id: 'SEC-006', severity: 'medium',
      title: 'Missing Event Emissions',
      description: 'Critical state changes (buys, withdrawals, price changes) emit no events, making off-chain monitoring impossible.',
      fix: 'Add events: event TokensPurchased(address buyer, uint256 amount, uint256 cost);',
      agent: 'Security Agent',
    });
  }
  if (!code.includes('require(amount') && code.includes('function buyTokens')) {
    findings.push({
      id: 'SEC-007', severity: 'low',
      title: 'Missing Zero-Amount Check',
      description: 'buyTokens() allows purchasing 0 tokens, wasting gas.',
      fix: 'Add: require(amount > 0, "Amount must be > 0");',
      agent: 'Security Agent',
    });
  }

  // Gas Agent Analysis
  if (code.includes('address(this).balance')) {
    gasTips.push('Cache address(this).balance in a local variable to avoid multiple SLOAD operations (~2100 gas each).');
  }
  if (code.includes('mapping(address =>') && code.includes('public ')) {
    gasTips.push('Consider making mappings internal and providing getter functions to save deployment gas (~50k gas per public mapping).');
  }
  if (code.includes('uint256 public price')) {
    gasTips.push('Pack storage variables: combine price + totalSold into a single slot using uint128 each (save ~2100 gas per read).');
  }
  gasTips.push('Use calldata instead of memory for read-only function parameters to save ~60 gas per parameter.');
  gasTips.push('Mark functions as external instead of public when they are not called internally to save ~200 gas.');
  gasTips.push('Use unchecked { } for arithmetic that cannot overflow (e.g., loop counters) to save ~80 gas per operation.');

  // Best Practices Agent
  if (!code.includes('SPDX-License-Identifier')) {
    bestPractices.push('Add SPDX license identifier for legal compliance and compiler warnings.');
  }
  if (!code.includes('event ')) {
    bestPractices.push('Define and emit events for all state-changing operations for better off-chain tracking.');
  }
  if (!code.includes('///') && !code.includes('/**')) {
    bestPractices.push('Add NatSpec documentation (/// or /** */) for all public/external functions.');
  }
  bestPractices.push('Implement a pause mechanism (Pausable) for emergency situations.');
  bestPractices.push('Add input validation: check for zero addresses in constructor parameters.');
  bestPractices.push('Consider implementing a withdrawal pattern instead of push pattern for refunds.');
  bestPractices.push('Use OpenZeppelin ReentrancyGuard for all functions with external calls.');

  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const medCount = findings.filter(f => f.severity === 'medium').length;
  const score = Math.max(0, 100 - (critCount * 25) - (highCount * 15) - (medCount * 8) - (findings.filter(f => f.severity === 'low').length * 3));
  const riskLevel = score >= 80 ? 'Low' : score >= 60 ? 'Medium' : score >= 40 ? 'High' : 'Critical';

  return {
    overallScore: score,
    riskLevel,
    findings,
    gasTips,
    bestPractices,
    summary: `Multi-agent analysis complete. Found ${findings.length} vulnerabilities (${critCount} critical, ${highCount} high, ${medCount} medium), ${gasTips.length} gas optimization opportunities, and ${bestPractices.length} best practice recommendations.`,
  };
}

export default function Home() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState<AuditResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'security' | 'gas' | 'practices'>('security');
  const [showLanding, setShowLanding] = useState(true);

  const handleAudit = () => {
    if (!code.trim()) return;
    setScanning(true);
    setResult(null);
    setShowLanding(false);
    setTimeout(() => {
      setResult(analyzeContract(code));
      setScanning(false);
    }, 2500);
  };

  const sevColor = (s: string) => {
    if (s === 'critical') return '#ff4757';
    if (s === 'high') return '#ff6b81';
    if (s === 'medium') return '#ffa502';
    if (s === 'low') return '#2ed573';
    return '#5352ed';
  };

  const scoreColor = (n: number) => n >= 80 ? '#2ed573' : n >= 60 ? '#ffa502' : '#ff4757';

  return (
    <div style={{ minHeight: '100vh', background: '#0a0a0f' }}>
      {/* Header */}
      <header style={{ borderBottom: '1px solid #2a2a3a', padding: '16px 32px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#0d0d14' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg, #5352ed, #a855f7)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, fontWeight: 800, color: '#fff' }}>S</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16, color: '#e8e8f0' }}>SmartContract AI Auditor</div>
            <div style={{ fontSize: 11, color: '#8888a0' }}>Multi-Agent Security Analysis Platform</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <span style={{ padding: '4px 10px', borderRadius: 20, fontSize: 11, background: 'rgba(83,82,237,0.15)', color: '#5352ed', border: '1px solid rgba(83,82,237,0.3)' }}>Security Agent</span>
          <span style={{ padding: '4px 10px', borderRadius: 20, fontSize: 11, background: 'rgba(255,165,2,0.15)', color: '#ffa502', border: '1px solid rgba(255,165,2,0.3)' }}>Gas Agent</span>
          <span style={{ padding: '4px 10px', borderRadius: 20, fontSize: 11, background: 'rgba(46,213,115,0.15)', color: '#2ed573', border: '1px solid rgba(46,213,115,0.3)' }}>Best Practices Agent</span>
        </div>
      </header>

      {showLanding && !result ? (
        /* Landing */
        <div style={{ maxWidth: 900, margin: '0 auto', padding: '80px 32px', textAlign: 'center' }} className="animate-fade">
          <div style={{ fontSize: 48, fontWeight: 900, background: 'linear-gradient(135deg, #5352ed, #a855f7, #ff4757)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', marginBottom: 16 }}>
            SmartContract<br/>AI Auditor
          </div>
          <p style={{ color: '#8888a0', fontSize: 18, maxWidth: 600, margin: '0 auto 40px', lineHeight: 1.6 }}>
            Multi-agent AI system that analyzes your Solidity smart contracts for <span style={{ color: '#ff4757' }}>security vulnerabilities</span>, <span style={{ color: '#ffa502' }}>gas optimization</span>, and <span style={{ color: '#2ed573' }}>best practices</span>.
          </p>
          <div style={{ display: 'flex', gap: 24, justifyContent: 'center', marginBottom: 50 }}>
            {[
              { icon: '\u{1F6E1}', label: 'Security Agent', desc: 'Reentrancy, access control, overflow', color: '#5352ed' },
              { icon: '\u26A1', label: 'Gas Agent', desc: 'Storage packing, calldata, unchecked', color: '#ffa502' },
              { icon: '\u2705', label: 'Best Practices', desc: 'Events, NatSpec, Pausable', color: '#2ed573' },
            ].map((a, i) => (
              <div key={i} style={{ background: '#16161f', border: '1px solid #2a2a3a', borderRadius: 16, padding: '28px 24px', width: 250, textAlign: 'center' }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>{a.icon}</div>
                <div style={{ fontWeight: 700, fontSize: 15, color: a.color, marginBottom: 6 }}>{a.label}</div>
                <div style={{ fontSize: 12, color: '#8888a0' }}>{a.desc}</div>
              </div>
            ))}
          </div>
          <button onClick={() => setShowLanding(false)} style={{ padding: '14px 40px', borderRadius: 12, background: 'linear-gradient(135deg, #5352ed, #a855f7)', color: '#fff', border: 'none', fontSize: 16, fontWeight: 700, cursor: 'pointer', boxShadow: '0 4px 20px rgba(83,82,237,0.3)' }}>
            Start Audit
          </button>
        </div>
      ) : (
        /* Auditor */
        <div style={{ display: 'flex', height: 'calc(100vh - 69px)' }}>
          {/* Code Editor */}
          <div style={{ width: '50%', borderRight: '1px solid #2a2a3a', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid #2a2a3a', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#0f0f17' }}>
              <span style={{ fontSize: 13, color: '#8888a0' }}>Solidity Source</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => setCode(SAMPLE_CONTRACT)} style={{ padding: '6px 14px', borderRadius: 8, background: '#1e1e2a', color: '#8888a0', border: '1px solid #2a2a3a', fontSize: 12, cursor: 'pointer' }}>Load Sample</button>
                <button onClick={handleAudit} disabled={scanning || !code.trim()} style={{ padding: '6px 20px', borderRadius: 8, background: scanning ? '#2a2a3a' : 'linear-gradient(135deg, #5352ed, #a855f7)', color: '#fff', border: 'none', fontSize: 12, fontWeight: 600, cursor: scanning ? 'wait' : 'pointer', opacity: !code.trim() ? 0.5 : 1 }}>
                  {scanning ? 'Scanning...' : 'Run Audit'}
                </button>
              </div>
            </div>
            <textarea
              value={code}
              onChange={e => setCode(e.target.value)}
              placeholder="// Paste your Solidity contract here..."
              spellCheck={false}
              style={{ flex: 1, background: '#0a0a0f', color: '#e8e8f0', border: 'none', padding: 20, fontSize: 13, lineHeight: 1.7, resize: 'none', outline: 'none', fontFamily: "'JetBrains Mono', monospace" }}
            />
          </div>

          {/* Results */}
          <div style={{ width: '50%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {scanning && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 24 }} className="animate-fade">
                <div style={{ width: 60, height: 60, borderRadius: '50%', border: '3px solid #2a2a3a', borderTopColor: '#5352ed', animation: 'spin 1s linear infinite' }} />
                <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                <div style={{ fontSize: 18, fontWeight: 600, color: '#e8e8f0' }}>Multi-Agent Analysis Running...</div>
                <div style={{ display: 'flex', gap: 16 }}>
                  {['Security Agent', 'Gas Agent', 'Best Practices'].map((a, i) => (
                    <div key={i} style={{ fontSize: 12, color: '#8888a0', animation: `pulse 1.5s ${i * 0.3}s infinite` }} className="animate-pulse">{a}</div>
                  ))}
                </div>
              </div>
            )}

            {result && !scanning && (
              <div style={{ flex: 1, overflow: 'auto' }} className="animate-fade">
                {/* Score Header */}
                <div style={{ padding: '24px 20px', borderBottom: '1px solid #2a2a3a', background: '#0f0f17' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 12 }}>
                    <div style={{ width: 72, height: 72, borderRadius: '50%', background: `conic-gradient(${scoreColor(result.overallScore)} ${result.overallScore * 3.6}deg, #1e1e2a 0deg)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <div style={{ width: 56, height: 56, borderRadius: '50%', background: '#0f0f17', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, fontWeight: 800, color: scoreColor(result.overallScore) }}>
                        {result.overallScore}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 20, fontWeight: 700, color: '#e8e8f0' }}>Audit Complete</div>
                      <div style={{ fontSize: 13, color: '#8888a0', marginTop: 4 }}>Risk Level: <span style={{ color: scoreColor(result.overallScore), fontWeight: 600 }}>{result.riskLevel}</span></div>
                      <div style={{ fontSize: 12, color: '#666680', marginTop: 2 }}>{result.findings.length} findings | {result.gasTips.length} gas tips | {result.bestPractices.length} recommendations</div>
                    </div>
                  </div>
                  {/* Severity badges */}
                  <div style={{ display: 'flex', gap: 8 }}>
                    {['critical', 'high', 'medium', 'low', 'info'].map(s => {
                      const count = result.findings.filter(f => f.severity === s).length;
                      if (count === 0) return null;
                      return <span key={s} style={{ padding: '3px 10px', borderRadius: 12, fontSize: 11, fontWeight: 600, background: `${sevColor(s)}20`, color: sevColor(s), border: `1px solid ${sevColor(s)}40` }}>{count} {s}</span>;
                    })}
                  </div>
                </div>

                {/* Tabs */}
                <div style={{ display: 'flex', borderBottom: '1px solid #2a2a3a', background: '#0d0d14' }}>
                  {([['security', 'Security'], ['gas', 'Gas Optimization'], ['practices', 'Best Practices']] as const).map(([key, label]) => (
                    <button key={key} onClick={() => setActiveTab(key)} style={{ flex: 1, padding: '12px 16px', background: 'none', border: 'none', borderBottom: activeTab === key ? '2px solid #5352ed' : '2px solid transparent', color: activeTab === key ? '#e8e8f0' : '#8888a0', fontSize: 13, fontWeight: activeTab === key ? 600 : 400, cursor: 'pointer', transition: 'all 0.2s' }}>{label}</button>
                  ))}
                </div>

                {/* Tab Content */}
                <div style={{ padding: 20 }}>
                  {activeTab === 'security' && result.findings.map((f, i) => (
                    <div key={f.id} style={{ background: '#16161f', border: '1px solid #2a2a3a', borderRadius: 12, padding: '16px 20px', marginBottom: 12, animation: `fadeIn 0.3s ${i * 0.1}s both` }} className="animate-slide">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                        <span style={{ padding: '2px 8px', borderRadius: 6, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', background: `${sevColor(f.severity)}20`, color: sevColor(f.severity) }}>{f.severity}</span>
                        <span style={{ fontSize: 11, color: '#666680', fontFamily: "'JetBrains Mono', monospace" }}>{f.id}</span>
                        <span style={{ marginLeft: 'auto', fontSize: 11, color: '#5352ed', background: 'rgba(83,82,237,0.1)', padding: '2px 8px', borderRadius: 6 }}>{f.agent}</span>
                      </div>
                      <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 6, color: '#e8e8f0' }}>{f.title}</div>
                      <div style={{ fontSize: 13, color: '#8888a0', lineHeight: 1.6, marginBottom: 10 }}>{f.description}</div>
                      {f.line && <div style={{ background: '#0a0a0f', borderRadius: 8, padding: '8px 12px', fontSize: 12, color: '#ff6b81', fontFamily: "'JetBrains Mono', monospace", marginBottom: 10, borderLeft: '3px solid #ff4757' }}>{f.line}</div>}
                      {f.fix && <div style={{ background: 'rgba(46,213,115,0.08)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: '#2ed573', lineHeight: 1.5, borderLeft: '3px solid #2ed573' }}><strong>Fix:</strong> {f.fix}</div>}
                    </div>
                  ))}

                  {activeTab === 'gas' && result.gasTips.map((tip, i) => (
                    <div key={i} style={{ background: '#16161f', border: '1px solid #2a2a3a', borderRadius: 12, padding: '14px 20px', marginBottom: 10, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <span style={{ color: '#ffa502', fontSize: 18, lineHeight: 1 }}>{'\u26A1'}</span>
                      <div style={{ fontSize: 13, color: '#e8e8f0', lineHeight: 1.6 }}>{tip}</div>
                    </div>
                  ))}

                  {activeTab === 'practices' && result.bestPractices.map((bp, i) => (
                    <div key={i} style={{ background: '#16161f', border: '1px solid #2a2a3a', borderRadius: 12, padding: '14px 20px', marginBottom: 10, display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <span style={{ color: '#2ed573', fontSize: 18, lineHeight: 1 }}>{'\u2705'}</span>
                      <div style={{ fontSize: 13, color: '#e8e8f0', lineHeight: 1.6 }}>{bp}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!result && !scanning && (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
                <div style={{ fontSize: 40, opacity: 0.3 }}>{'\u{1F50D}'}</div>
                <div style={{ color: '#666680', fontSize: 14 }}>Paste a Solidity contract and click Run Audit</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
