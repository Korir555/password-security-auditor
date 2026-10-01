"""
Password Security Auditor - Flask Backend
Corporate password compliance tool aligned with Kenya Data Protection Act
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import json
import re
import math
import csv
import io
from datetime import datetime
from werkzeug.utils import secure_filename
import hashlib

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_auditor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['UPLOAD_EXTENSIONS'] = {'csv', 'txt'}

db = SQLAlchemy(app)

# =====================
# DATABASE MODELS
# =====================

class AuditReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.String(200), nullable=False)
    audit_date = db.Column(db.DateTime, default=datetime.utcnow)
    total_passwords = db.Column(db.Integer, default=0)
    weak_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    strong_count = db.Column(db.Integer, default=0)
    compliance_score = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default='pending')
    findings = db.relationship('PasswordFinding', backref='report', lazy=True, cascade='all, delete-orphan')

class PasswordFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('audit_report.id'), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    entropy_score = db.Column(db.Float, default=0.0)
    strength_level = db.Column(db.String(20), default='weak')  # weak, medium, strong
    issues = db.Column(db.Text, default='')  # JSON array
    last_changed = db.Column(db.String(50), default='unknown')

# =====================
# PASSWORD ANALYSIS LOGIC
# =====================

class PasswordAnalyzer:
    """Analyze password strength using entropy and pattern matching"""
    
    # Common patterns that weaken passwords
    COMMON_PATTERNS = {
        'sequential': [r'abc', r'123', r'xyz'],
        'keyboard_walks': [r'qwerty', r'asdf', r'zxcv'],
        'user_info': [r'admin', r'password', r'test', r'user'],
        'year_patterns': [r'20\d{2}', r'19\d{2}'],
        'month_patterns': [r'(01|02|03|04|05|06|07|08|09|10|11|12)'],
    }
    
    COMMON_PASSWORDS = {
        'password', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
        '123456', '123456789', 'qwerty', 'abc123', 'password123',
        'admin123', 'test', 'test123', 'user', 'username'
    }
    
    @staticmethod
    def calculate_entropy(password):
        """Calculate Shannon entropy of password"""
        if not password:
            return 0.0
        
        # Count unique character types
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0.0
        
        # Entropy = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    @staticmethod
    def check_common_patterns(password):
        """Detect common weak patterns"""
        issues = []
        
        # Check against common passwords
        if password.lower() in PasswordAnalyzer.COMMON_PASSWORDS:
            issues.append("Uses commonly compromised password")
        
        # Check for sequential patterns
        if re.search(r'abc|bcd|cde|def|xyz', password.lower()):
            issues.append("Contains sequential character patterns")
        
        # Check for keyboard walks
        if re.search(r'qwerty|asdf|zxcv|qwertz', password.lower()):
            issues.append("Contains keyboard walk patterns")
        
        # Check for common words
        if re.search(r'admin|password|test|user|root|login', password.lower()):
            issues.append("Contains common dictionary words")
        
        # Check for dates
        if re.search(r'\b(19|20)\d{2}\b', password):
            issues.append("Contains year pattern (likely date-based)")
        
        # All numbers
        if re.match(r'^\d+$', password):
            issues.append("Uses only numeric characters")
        
        # All lowercase
        if password.islower():
            issues.append("Uses only lowercase letters (no uppercase)")
        
        # Less than 8 characters
        if len(password) < 8:
            issues.append("Password length less than 8 characters (ODPC minimum)")
        
        return issues
    
    @staticmethod
    def assess_strength(password):
        """Assess password strength: weak/medium/strong"""
        entropy = PasswordAnalyzer.calculate_entropy(password)
        issues = PasswordAnalyzer.check_common_patterns(password)
        
        # Scoring logic
        score = 0
        
        # Entropy contribution (0-40 points)
        if entropy >= 64:
            score += 40
        elif entropy >= 50:
            score += 30
        elif entropy >= 40:
            score += 20
        elif entropy >= 28:
            score += 10
        
        # Length contribution (0-20 points)
        if len(password) >= 16:
            score += 20
        elif len(password) >= 12:
            score += 15
        elif len(password) >= 8:
            score += 10
        
        # Character variety (0-20 points)
        char_types = 0
        if re.search(r'[a-z]', password):
            char_types += 1
        if re.search(r'[A-Z]', password):
            char_types += 1
        if re.search(r'[0-9]', password):
            char_types += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            char_types += 1
        
        score += (char_types * 5)
        
        # Issue penalties (0-20 points)
        score -= (len(issues) * 3)
        
        # Cap score at 100
        score = min(100, max(0, score))
        
        # Determine strength level
        if score >= 70:
            return 'strong', score
        elif score >= 50:
            return 'medium', score
        else:
            return 'weak', score
    
    @staticmethod
    def analyze_password(password, username=''):
        """Complete password analysis"""
        strength, score = PasswordAnalyzer.assess_strength(password)
        entropy = PasswordAnalyzer.calculate_entropy(password)
        issues = PasswordAnalyzer.check_common_patterns(password)
        
        return {
            'strength': strength,
            'score': score,
            'entropy': round(entropy, 2),
            'issues': issues,
            'recommendations': PasswordAnalyzer.get_recommendations(strength, issues)
        }
    
    @staticmethod
    def get_recommendations(strength, issues):
        """Provide remediation recommendations"""
        recommendations = []
        
        if strength == 'weak':
            recommendations.append("Increase password length to 12+ characters")
            recommendations.append("Mix uppercase, lowercase, numbers, and symbols")
            recommendations.append("Avoid dictionary words and common patterns")
        
        if 'Contains sequential character patterns' in issues:
            recommendations.append("Remove sequential patterns (abc, 123, xyz)")
        
        if 'Contains keyboard walk patterns' in issues:
            recommendations.append("Avoid keyboard walks (qwerty, asdf)")
        
        if 'Contains common dictionary words' in issues:
            recommendations.append("Use unrelated words or randomized strings")
        
        if 'Uses only numeric characters' in issues:
            recommendations.append("Add letters and special characters")
        
        if 'Uses only lowercase letters' in issues:
            recommendations.append("Include uppercase letters and numbers")
        
        if strength == 'medium':
            recommendations.append("Consider increasing to 14+ characters for strong rating")
            recommendations.append("Add special characters if not already present")
        
        return recommendations

# =====================
# API ENDPOINTS
# =====================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'Password Security Auditor'})

@app.route('/api/analyze', methods=['POST'])
def analyze_single_password():
    """Analyze a single password"""
    data = request.json
    password = data.get('password', '')
    username = data.get('username', '')
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    analysis = PasswordAnalyzer.analyze_password(password, username)
    return jsonify(analysis)

@app.route('/api/audit/upload', methods=['POST'])
def upload_audit():
    """Upload CSV file with usernames and passwords for bulk audit"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    organization = request.form.get('organization', 'Unknown')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith(('.csv', '.txt')):
        return jsonify({'error': 'Only CSV and TXT files allowed'}), 400
    
    try:
        # Create audit report
        report = AuditReport(organization_name=organization)
        db.session.add(report)
        db.session.flush()  # Get ID before commit
        
        # Parse file
        stream = io.StringIO(file.stream.read().decode('utf-8'))
        reader = csv.DictReader(stream)
        
        findings = []
        weak_count = 0
        medium_count = 0
        strong_count = 0
        
        for row in reader:
            username = row.get('username', row.get('user', '')).strip()
            password = row.get('password', row.get('pass', '')).strip()
            last_changed = row.get('last_changed', 'unknown')
            
            if not username or not password:
                continue
            
            analysis = PasswordAnalyzer.analyze_password(password, username)
            
            finding = PasswordFinding(
                report_id=report.id,
                username=username,
                password_hash=hashlib.sha256(password.encode()).hexdigest(),
                entropy_score=analysis['entropy'],
                strength_level=analysis['strength'],
                issues=json.dumps(analysis['issues']),
                last_changed=last_changed
            )
            findings.append(finding)
            
            # Tally
            if analysis['strength'] == 'weak':
                weak_count += 1
            elif analysis['strength'] == 'medium':
                medium_count += 1
            else:
                strong_count += 1
        
        # Update report
        report.total_passwords = len(findings)
        report.weak_count = weak_count
        report.medium_count = medium_count
        report.strong_count = strong_count
        
        total = len(findings)
        if total > 0:
            report.compliance_score = ((medium_count * 0.7 + strong_count) / total) * 100
        
        report.status = 'completed'
        
        db.session.add_all(findings)
        db.session.commit()
        
        return jsonify({
            'report_id': report.id,
            'organization': organization,
            'total_passwords': total,
            'weak': weak_count,
            'medium': medium_count,
            'strong': strong_count,
            'compliance_score': round(report.compliance_score, 2),
            'message': f'Audit completed: {total} passwords analyzed'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit/<int:report_id>', methods=['GET'])
def get_audit_report(report_id):
    """Get detailed audit report"""
    report = AuditReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    findings_data = []
    for finding in report.findings:
        findings_data.append({
            'id': finding.id,
            'username': finding.username,
            'strength': finding.strength_level,
            'entropy': finding.entropy_score,
            'issues': json.loads(finding.issues) if finding.issues else [],
            'last_changed': finding.last_changed
        })
    
    return jsonify({
        'id': report.id,
        'organization': report.organization_name,
        'audit_date': report.audit_date.isoformat(),
        'total_passwords': report.total_passwords,
        'weak': report.weak_count,
        'medium': report.medium_count,
        'strong': report.strong_count,
        'compliance_score': report.compliance_score,
        'status': report.status,
        'findings': findings_data,
        'dpa_compliant': report.compliance_score >= 70,
        'recommendations': generate_recommendations(report)
    })

@app.route('/api/audit/<int:report_id>/export', methods=['GET'])
def export_audit_report(report_id):
    """Export audit report as PDF-ready JSON (for frontend rendering)"""
    report = AuditReport.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    findings_data = []
    for finding in report.findings:
        findings_data.append({
            'username': finding.username,
            'strength': finding.strength_level,
            'entropy': finding.entropy_score,
            'issues': json.loads(finding.issues) if finding.issues else [],
        })
    
    return jsonify({
        'title': 'Password Security Audit Report',
        'organization': report.organization_name,
        'audit_date': report.audit_date.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total': report.total_passwords,
            'weak': report.weak_count,
            'medium': report.medium_count,
            'strong': report.strong_count,
            'compliance_score': report.compliance_score,
            'dpa_compliant': report.compliance_score >= 70,
        },
        'findings': findings_data,
        'recommendations': generate_recommendations(report),
        'regulatory_context': {
            'framework': 'Kenya Data Protection Act (2019)',
            'enforcer': 'Office of Data Protection Commissioner (ODPC)',
            'minimum_requirements': [
                'Passwords must be at least 8 characters',
                'Passwords must include mixed character types',
                'Passwords must be changed every 90 days',
                'Default/weak passwords must not be used',
                'Password hashes must use strong algorithms'
            ]
        }
    })

def generate_recommendations(report):
    """Generate organization-level recommendations"""
    recommendations = []
    
    weak_pct = (report.weak_count / report.total_passwords * 100) if report.total_passwords > 0 else 0
    
    if report.compliance_score < 50:
        recommendations.append({
            'priority': 'critical',
            'action': 'Immediate password reset required',
            'description': f'{report.weak_count} users ({weak_pct:.1f}%) have weak passwords'
        })
    
    if report.compliance_score < 70:
        recommendations.append({
            'priority': 'high',
            'action': 'Implement password policy enforcement',
            'description': 'Enforce minimum 12-character passwords with mixed character types'
        })
    
    if report.weak_count > 0:
        recommendations.append({
            'priority': 'medium',
            'action': 'Password security training',
            'description': 'Conduct user training on password best practices'
        })
    
    recommendations.append({
        'priority': 'medium',
        'action': 'Regular audits (quarterly)',
        'description': 'Schedule password security audits every 90 days'
    })
    
    recommendations.append({
        'priority': 'low',
        'action': 'Consider password manager adoption',
        'description': 'Enterprise password manager can enforce policies automatically'
    })
    
    return recommendations

@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all audit reports"""
    reports = AuditReport.query.all()
    return jsonify([{
        'id': r.id,
        'organization': r.organization_name,
        'audit_date': r.audit_date.isoformat(),
        'total_passwords': r.total_passwords,
        'compliance_score': r.compliance_score,
        'status': r.status
    } for r in reports])

# =====================
# ERROR HANDLERS
# =====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
