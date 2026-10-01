import React, { useState } from 'react';
import './App.css';
import SingleAnalyzer from './components/SingleAnalyzer';
import BulkAuditor from './components/BulkAuditor';
import ReportViewer from './components/ReportViewer';
import ComplianceGuide from './components/ComplianceGuide';

function App() {
  const [activeTab, setActiveTab] = useState('analyzer');
  const [selectedReportId, setSelectedReportId] = useState(null);

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <h1>🔐 Password Security Auditor</h1>
          <p>Kenya Data Protection Act Compliance Tool</p>
        </div>
      </header>

      <nav className="nav-tabs">
        <button
          className={`tab ${activeTab === 'analyzer' ? 'active' : ''}`}
          onClick={() => setActiveTab('analyzer')}
        >
          Single Password Analyzer
        </button>
        <button
          className={`tab ${activeTab === 'bulk' ? 'active' : ''}`}
          onClick={() => setActiveTab('bulk')}
        >
          Bulk Audit
        </button>
        <button
          className={`tab ${activeTab === 'reports' ? 'active' : ''}`}
          onClick={() => setActiveTab('reports')}
        >
          Reports
        </button>
        <button
          className={`tab ${activeTab === 'guide' ? 'active' : ''}`}
          onClick={() => setActiveTab('guide')}
        >
          ODPC Compliance Guide
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'analyzer' && <SingleAnalyzer />}
        
        {activeTab === 'bulk' && <BulkAuditor onAuditComplete={(id) => {
          setSelectedReportId(id);
          setActiveTab('reports');
        }} />}
        
        {activeTab === 'reports' && <ReportViewer selectedReportId={selectedReportId} />}
        
        {activeTab === 'guide' && <ComplianceGuide />}
      </main>

      <footer className="footer">
        <p>Project #22: Password Security Auditor | Built for Kenya Cybersecurity Job Market</p>
        <p>GitHub: <a href="https://github.com/Korir555/password-security-auditor" target="_blank">Korir555/password-security-auditor</a></p>
      </footer>
    </div>
  );
}

export default App;
