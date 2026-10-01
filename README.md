# Password Security Auditor - Project #22

**Compliance Tool for Kenya Data Protection Act | ODPC-Ready Reporting**

## Overview

Corporate password security auditing tool aligned with Kenya Data Protection Act (2019) requirements. Features entropy-based strength assessment, pattern detection, bulk audit capability, and ODPC-compliant reporting.

Built to demonstrate:
- **GRC (Governance, Risk, Compliance) specialization** (gap in current portfolio)
- **Compliance tool development** (direct hiring demand from banks, ODPC)
- **Practical ODPC/DPA enforcement understanding** (Kenya regulatory context)

## Features

### 1. Single Password Analyzer
- Real-time strength assessment (weak/medium/strong)
- Entropy calculation using Shannon entropy formula
- Pattern detection (sequential, keyboard walks, dictionary words)
- Issue identification and recommendations
- REST API endpoint for integration

### 2. Bulk Audit System
- CSV file upload (username + password pairs)
- Batch analysis of corporate password lists
- Automated compliance scoring
- Dashboard visualization
- Exportable audit reports

### 3. Compliance Reporting
- Organization-level summary statistics
- Individual finding details with remediation steps
- ODPC regulatory context and minimum requirements
- Priority-based recommendations (critical/high/medium/low)
- Export-ready JSON format for PDF generation

### 4. ODPC Integration
- Kenya Data Protection Act alignment
- Minimum 8-character password enforcement
- Mixed character type requirements
- Compliance score tracking (target: 70%+)
- Regulatory framework documentation

## Technical Architecture

```
password-security-auditor/
├── backend/
│   ├── app.py                 # Flask REST API (13 endpoints)
│   ├── requirements.txt       # Dependencies
│   └── models/
│       ├── AuditReport        # Report metadata
│       └── PasswordFinding    # Individual password findings
├── frontend/
│   ├── App.jsx               # Main React component
│   ├── components/
│   │   ├── SingleAnalyzer.jsx   # Single password UI
│   │   ├── BulkAuditor.jsx      # CSV upload & analysis
│   │   ├── ReportViewer.jsx     # Report details & visualization
│   │   └── ComplianceGuide.jsx  # ODPC requirements guide
│   ├── App.css               # Styling
│   └── main.jsx              # React entry point
└── docs/
    ├── API.md                # REST API documentation
    ├── SETUP.md              # Deployment guide
    └── COMPLIANCE.md         # ODPC requirements
```

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/analyze` | POST | Analyze single password |
| `/api/audit/upload` | POST | Upload CSV for bulk audit |
| `/api/audit/<id>` | GET | Retrieve audit report |
| `/api/audit/<id>/export` | GET | Export audit report (PDF-ready) |
| `/api/reports` | GET | List all audit reports |

### Example: Single Password Analysis

**Request:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ss2024", "username": "john.doe"}'
```

**Response:**
```json
{
  "strength": "strong",
  "score": 78,
  "entropy": 56.2,
  "issues": [],
  "recommendations": [
    "Consider increasing to 14+ characters for maximum security"
  ]
}
```

### Example: Bulk Audit Upload

**CSV Format:**
```csv
username,password,last_changed
user1,Admin@2024,2024-01-15
user2,password123,2023-06-20
user3,K3nYa@Secure,2024-09-01
```

**Request:**
```bash
curl -X POST http://localhost:5000/api/audit/upload \
  -F "file=@passwords.csv" \
  -F "organization=Equity Bank"
```

**Response:**
```json
{
  "report_id": 1,
  "organization": "Equity Bank",
  "total_passwords": 3,
  "weak": 1,
  "medium": 1,
  "strong": 1,
  "compliance_score": 66.67,
  "message": "Audit completed: 3 passwords analyzed"
}
```

## Installation & Setup

### Backend Setup

```bash
# Clone and navigate
git clone https://github.com/Korir555/password-security-auditor.git
cd password-security-auditor/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run Flask server
python3 app.py
# Server runs on http://localhost:5000
```

### Frontend Setup

```bash
# Navigate to frontend
cd ../frontend

# Install Node dependencies
npm install

# Run React dev server
npm run dev
# App runs on http://localhost:5173
```

### Docker Deployment (Optional)

```bash
# Build and run with Docker
docker-compose up --build

# Backend: http://localhost:5000
# Frontend: http://localhost:3000
```

## Password Strength Criteria

### Scoring Algorithm (0-100)

| Component | Points | Criteria |
|---|---|---|
| **Entropy** | 0-40 | Based on character set and length |
| **Length** | 0-20 | Bonus for 12+, 16+ characters |
| **Variety** | 0-20 | Mixed uppercase, lowercase, numbers, symbols |
| **Patterns** | -0-20 | Penalties for weak patterns |
| **Total** | 0-100 | Final strength score |

### Strength Levels

- **Strong (70-100):** 12+ characters, mixed types, no weak patterns
- **Medium (50-70):** 8-11 characters, some variety, minor issues
- **Weak (0-50):** <8 characters, limited variety, common patterns

### ODPC Minimum Requirements

Per Kenya Data Protection Act:
- ✓ Minimum 8 characters (we recommend 12+)
- ✓ Mixed character types (uppercase, lowercase, numbers, symbols)
- ✓ No default/common passwords
- ✓ Changed every 90 days (tracked in audit)
- ✓ Hashed with strong algorithm (SHA-256)

## Use Cases

### 1. Safaricom (M-PESA Operations)
"We need password security audits for payment systems. This tool identifies weak credentials before they become vulnerabilities in high-value transactions."

### 2. Equity Bank (Information Security)
"Compliance tool for DPA requirements. Audits employee credentials quarterly, generates audit trail for regulators."

### 3. ODPC (Office of Data Protection Commissioner)
"Organizations can self-audit password security and demonstrate ODPC compliance without manual spreadsheets."

### 4. Consulting/Auditing Firms
"Resellable compliance assessment tool for client security baselines."

## Compliance Features

### ODPC Reporting
- ✅ Regulatory framework documentation
- ✅ Compliance scoring (DPA-aligned)
- ✅ Gap analysis and remediation
- ✅ Executive summary for audit teams
- ✅ Individual findings with severity

### Interview Value
- Shows understanding of Kenya's regulatory environment
- Demonstrates GRC tool development skills
- Proves ability to build compliance-first applications
- Positions for compliance officer / security analyst roles

## Portfolio Context

**Interview Talking Point:**
"I built a compliance tool that audits corporate passwords against Kenya Data Protection Act standards. It takes a CSV of usernames and passwords, assesses strength using entropy calculations and pattern detection, and generates ODPC-ready reports with compliance scores and remediation recommendations. This directly addresses the compliance gap in my portfolio and shows I understand the regulatory context that banks and government agencies care about."

**GitHub Summary:**
GRC-focused security tool demonstrating compliance tool development, password analysis, and Kenya regulatory alignment. 500+ LOC backend, 300+ LOC frontend.

## Project Metrics

| Metric | Value |
|---|---|
| Backend LOC | 550+ |
| Frontend LOC | 300+ |
| API Endpoints | 6 |
| React Components | 4 |
| Database Tables | 2 |
| Build Time | 2-3 weeks |

## Technical Skills Demonstrated

- ✅ **Backend:** Flask REST API, SQLAlchemy ORM, password analysis algorithms
- ✅ **Frontend:** React components, form handling, data visualization
- ✅ **Security:** Entropy calculation, pattern detection, hash generation
- ✅ **Compliance:** Regulatory requirements, audit reporting, policy alignment
- ✅ **DevOps:** Environment setup, Docker, Git workflows

## Next Steps / Extensions

1. **Machine Learning:** Train anomaly detection on password change patterns
2. **Integration:** LDAP/Active Directory integration for enterprise SSO
3. **Advanced Reporting:** PDF export with branding, compliance frameworks comparison
4. **Multi-Language:** Swahili reporting for Kenyan government agencies
5. **Real-Time Monitoring:** Integrate with password managers, flag breached passwords

## Deployment

### Production Deployment (AWS/Heroku)

```bash
# Set environment variables
export FLASK_ENV=production
export DATABASE_URL=postgresql://...

# Deploy to Heroku
heroku create password-auditor
git push heroku main
```

### GitHub Integration

```bash
# Initialize and push to GitHub
git init
git add .
git commit -m "Initial commit: Password Security Auditor"
git remote add origin https://github.com/Korir555/password-security-auditor.git
git branch -M main
git push -u origin main
```

## License

MIT License (see LICENSE file)

## Hiring Manager Notes

**Why hire for this project:**
- Demonstrates understanding of Kenya's regulatory environment (critical for banks, government)
- Shows GRC specialization (differentiates from typical security projects)
- Proves ability to build compliance-first tools (high-value skill for regulated industries)
- Combines security + business domain knowledge
- Interview signal: Candidate understands what Safaricom/Equity/ODPC actually need

---

**Built by:** Emmanuel Kibet Korir (Trevor)  
**Portfolio:** [korir555.github.io/cybersecurity-portfolio](https://korir555.github.io/cybersecurity-portfolio)  
**GitHub:** [Korir555/password-security-auditor](https://github.com/Korir555/password-security-auditor)  
**Date:** October 2026
