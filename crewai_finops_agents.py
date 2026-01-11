"""
Enterprise FinOps & Compliance AI Agents
========================================
Production-grade AI analysis using Anthropic Claude API.
Designed for enterprise reliability, auditability, and performance.

Architecture: Direct Claude API with custom orchestration
Model: Claude Sonnet 4 (claude-sonnet-4-20250514)

Author: Ajit Sharma
Version: 2.0.0 Enterprise
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import streamlit as st

# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class EnterpriseConfig:
    """Enterprise configuration for AI analysis system"""
    
    model_name: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.2  # Lower for more consistent enterprise outputs
    timeout_seconds: int = 120
    retry_attempts: int = 3
    
    # Cost thresholds
    anomaly_threshold_percent: float = 25.0
    savings_minimum_dollars: float = 100.0
    
    # Compliance frameworks
    supported_frameworks: List[str] = field(default_factory=lambda: [
        "PCI-DSS v4.0", "HIPAA", "SOC 2 Type II", 
        "ISO 27001:2022", "NIST CSF 2.0", "CIS AWS Benchmark v3.0"
    ])
    
    # Enterprise features
    enable_caching: bool = True
    cache_ttl_minutes: int = 15
    enable_audit_logging: bool = True


# =============================================================================
# ANTHROPIC CLIENT - ENTERPRISE WRAPPER
# =============================================================================

class EnterpriseClaudeClient:
    """
    Enterprise-grade Claude API wrapper with:
    - Connection pooling
    - Retry logic
    - Response caching
    - Audit logging
    - Error handling
    """
    
    def __init__(self, config: EnterpriseConfig = None):
        self.config = config or EnterpriseConfig()
        self._client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Anthropic client with proper error handling"""
        api_key = self._get_api_key()
        
        if not api_key:
            self._client = None
            return
        
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key)
        except Exception as e:
            print(f"❌ Failed to initialize Anthropic client: {e}")
            self._client = None
    
    def _get_api_key(self) -> Optional[str]:
        """Get API key from multiple sources"""
        # 1. Streamlit secrets (nested)
        if hasattr(st, 'secrets'):
            try:
                if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                    return st.secrets['anthropic']['api_key']
            except:
                pass
        
        # 2. Streamlit secrets (direct)
        if hasattr(st, 'secrets'):
            try:
                key = st.secrets.get('ANTHROPIC_API_KEY')
                if key:
                    return key
            except:
                pass
        
        # 3. Environment variable
        return os.environ.get('ANTHROPIC_API_KEY')
    
    @property
    def is_available(self) -> bool:
        return self._client is not None
    
    def _get_cache_key(self, prompt: str, context: str = "") -> str:
        """Generate cache key for response caching"""
        content = f"{prompt}:{context}:{self.config.model_name}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[Dict]:
        """Get cached response if valid"""
        if not self.config.enable_caching:
            return None
        
        cache = st.session_state.get('ai_response_cache', {})
        if cache_key in cache:
            cached = cache[cache_key]
            cache_time = cached.get('timestamp')
            if cache_time:
                age_minutes = (datetime.now() - cache_time).total_seconds() / 60
                if age_minutes < self.config.cache_ttl_minutes:
                    return cached.get('response')
        return None
    
    def _cache_response(self, cache_key: str, response: Dict):
        """Cache response for future use"""
        if not self.config.enable_caching:
            return
        
        if 'ai_response_cache' not in st.session_state:
            st.session_state.ai_response_cache = {}
        
        st.session_state.ai_response_cache[cache_key] = {
            'response': response,
            'timestamp': datetime.now()
        }
    
    def _log_audit(self, action: str, details: Dict):
        """Log action for audit trail"""
        if not self.config.enable_audit_logging:
            return
        
        if 'ai_audit_log' not in st.session_state:
            st.session_state.ai_audit_log = []
        
        st.session_state.ai_audit_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details
        })
    
    def analyze(self, prompt: str, context: str = "", use_cache: bool = True) -> Dict:
        """
        Execute analysis with enterprise features.
        
        Args:
            prompt: The analysis prompt
            context: Additional context data
            use_cache: Whether to use response caching
            
        Returns:
            Dict with 'success', 'result', 'metadata'
        """
        if not self.is_available:
            return {
                'success': False,
                'error': 'Claude API not configured. Add ANTHROPIC_API_KEY to secrets.',
                'result': None
            }
        
        # Check cache
        cache_key = self._get_cache_key(prompt, context)
        if use_cache:
            cached = self._get_cached_response(cache_key)
            if cached:
                self._log_audit('cache_hit', {'cache_key': cache_key})
                return {**cached, 'from_cache': True}
        
        # Execute API call with retry
        for attempt in range(self.config.retry_attempts):
            try:
                start_time = datetime.now()
                
                message = self._client.messages.create(
                    model=self.config.model_name,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    messages=[{"role": "user", "content": f"{context}\n\n{prompt}"}]
                )
                
                duration = (datetime.now() - start_time).total_seconds()
                
                response = {
                    'success': True,
                    'result': message.content[0].text,
                    'metadata': {
                        'model': self.config.model_name,
                        'tokens_used': message.usage.input_tokens + message.usage.output_tokens,
                        'duration_seconds': round(duration, 2),
                        'timestamp': datetime.now().isoformat()
                    }
                }
                
                # Cache successful response
                self._cache_response(cache_key, response)
                
                # Audit log
                self._log_audit('api_call', {
                    'model': self.config.model_name,
                    'tokens': response['metadata']['tokens_used'],
                    'duration': duration
                })
                
                return response
                
            except Exception as e:
                if attempt < self.config.retry_attempts - 1:
                    continue
                
                self._log_audit('api_error', {'error': str(e), 'attempt': attempt + 1})
                return {
                    'success': False,
                    'error': f'API call failed after {self.config.retry_attempts} attempts: {str(e)}',
                    'result': None
                }


# =============================================================================
# ENTERPRISE AI SERVICES
# =============================================================================

class FinOpsAnalysisService:
    """Enterprise FinOps Analysis Service"""
    
    def __init__(self, client: EnterpriseClaudeClient):
        self.client = client
    
    def analyze_costs(self, cost_data: Dict = None) -> Dict:
        """Comprehensive cost analysis"""
        
        # Get cost context from session or use provided data
        if cost_data is None:
            cost_data = self._get_cost_context()
        
        prompt = """As a Senior FinOps Analyst, analyze the following AWS cost data and provide:

## Executive Summary
2-3 sentences summarizing the current cost posture.

## Key Metrics
- Total spend and trend
- Top cost drivers
- Cost efficiency score (1-100)

## Cost Anomalies
List any unusual spending patterns with severity (Critical/High/Medium/Low).

## Optimization Opportunities
Top 5 recommendations with:
- Description
- Estimated monthly savings
- Implementation effort (Low/Medium/High)
- Risk level

## 90-Day Action Plan
Prioritized list of actions by ROI.

Format the response in clean markdown suitable for executive presentation."""

        context = f"""COST DATA:
{json.dumps(cost_data, indent=2, default=str)}

DATA SOURCE: {cost_data.get('data_source', 'Unknown')}
ANALYSIS DATE: {datetime.now().strftime('%Y-%m-%d %H:%M')}"""

        return self.client.analyze(prompt, context)
    
    def _get_cost_context(self) -> Dict:
        """Get cost data from AWS Cost Explorer or fall back to demo data"""
        is_demo = st.session_state.get('demo_mode', False)
        
        # Try to get REAL AWS data if not in demo mode
        if not is_demo:
            real_data = self._fetch_real_aws_costs()
            if real_data:
                return real_data
        
        # Fall back to demo data
        if is_demo:
            return {
                'data_source': 'Demo Data',
                'total_monthly_cost': 2800000,
                'currency': 'USD',
                'period': 'Last 30 Days',
                'month_over_month_change': '+8.2%',
                'top_services': {
                    'Amazon EC2': 1150000,
                    'Amazon RDS': 520000,
                    'Amazon S3': 280000,
                    'AWS Lambda': 185000,
                    'Amazon EKS': 165000,
                    'Amazon CloudFront': 120000,
                    'Data Transfer': 95000,
                    'Amazon DynamoDB': 85000
                },
                'anomalies_detected': 3,
                'potential_savings': 285000,
                'reserved_coverage': '62%',
                'spot_usage': '18%',
                'account_count': '640+'
            }
        else:
            # Live mode but couldn't fetch real data
            return {
                'data_source': 'Fallback (AWS API unavailable)',
                'total_monthly_cost': 'Unable to fetch - check AWS credentials',
                'note': 'Configure AWS Cost Explorer access for real data',
                'top_services': {},
                'anomalies_detected': 0,
                'potential_savings': 'Unknown'
            }
    
    def _fetch_real_aws_costs(self) -> Optional[Dict]:
        """Fetch actual cost data from AWS Cost Explorer"""
        try:
            # Get AWS clients from session state
            clients = st.session_state.get('aws_clients', {})
            ce_client = clients.get('ce')
            
            if not ce_client:
                print("⚠️ Cost Explorer client not available")
                return None
            
            # Calculate date range (last 30 days)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            
            # Fetch cost and usage data grouped by service
            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['BlendedCost', 'UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            # Process service costs
            service_costs = {}
            total_cost = 0
            
            for result in response.get('ResultsByTime', []):
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    cost = float(group['Metrics']['BlendedCost']['Amount'])
                    service_costs[service] = service_costs.get(service, 0) + cost
                    total_cost += cost
            
            # Sort by cost and get top services
            sorted_services = dict(sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10])
            
            # Try to get forecast
            forecast = None
            try:
                forecast_response = ce_client.get_cost_forecast(
                    TimePeriod={
                        'Start': end_date.strftime('%Y-%m-%d'),
                        'End': (end_date + timedelta(days=30)).strftime('%Y-%m-%d')
                    },
                    Metric='BLENDED_COST',
                    Granularity='MONTHLY'
                )
                forecast = float(forecast_response.get('Total', {}).get('Amount', 0))
            except Exception as e:
                print(f"Forecast not available: {e}")
            
            # Try to get anomalies
            anomaly_count = 0
            try:
                anomaly_response = ce_client.get_anomalies(
                    DateInterval={
                        'StartDate': start_date.strftime('%Y-%m-%d'),
                        'EndDate': end_date.strftime('%Y-%m-%d')
                    },
                    MaxResults=10
                )
                anomaly_count = len(anomaly_response.get('Anomalies', []))
            except Exception as e:
                print(f"Anomalies not available: {e}")
            
            # Try to get reservation coverage
            reservation_coverage = 'N/A'
            try:
                coverage_response = ce_client.get_reservation_coverage(
                    TimePeriod={
                        'Start': start_date.strftime('%Y-%m-%d'),
                        'End': end_date.strftime('%Y-%m-%d')
                    }
                )
                total_coverage = coverage_response.get('Total', {}).get('CoverageHours', {})
                if total_coverage:
                    coverage_pct = float(total_coverage.get('CoverageHoursPercentage', 0))
                    reservation_coverage = f"{coverage_pct:.1f}%"
            except Exception as e:
                print(f"Reservation coverage not available: {e}")
            
            # Get account ID
            account_id = st.session_state.get('aws_account_id', 'Unknown')
            
            # Calculate month-over-month change (fetch previous month data)
            mom_change = 'N/A'
            try:
                prev_start = start_date - timedelta(days=30)
                prev_response = ce_client.get_cost_and_usage(
                    TimePeriod={
                        'Start': prev_start.strftime('%Y-%m-%d'),
                        'End': start_date.strftime('%Y-%m-%d')
                    },
                    Granularity='MONTHLY',
                    Metrics=['BlendedCost']
                )
                prev_cost = 0
                for result in prev_response.get('ResultsByTime', []):
                    prev_cost += float(result.get('Total', {}).get('BlendedCost', {}).get('Amount', 0))
                
                if prev_cost > 0:
                    change_pct = ((total_cost - prev_cost) / prev_cost) * 100
                    mom_change = f"{change_pct:+.1f}%"
            except Exception as e:
                print(f"MoM change calculation failed: {e}")
            
            return {
                'data_source': 'AWS Cost Explorer (Live)',
                'account_id': account_id,
                'period': f"{start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')}",
                'total_monthly_cost': round(total_cost, 2),
                'currency': 'USD',
                'month_over_month_change': mom_change,
                'forecast_next_month': round(forecast, 2) if forecast else 'N/A',
                'top_services': {k: round(v, 2) for k, v in sorted_services.items()},
                'anomalies_detected': anomaly_count,
                'reservation_coverage': reservation_coverage,
                'services_count': len(service_costs)
            }
            
        except Exception as e:
            print(f"❌ Error fetching AWS cost data: {e}")
            return None


class ComplianceAssessmentService:
    """Enterprise Compliance Assessment Service"""
    
    FRAMEWORKS = {
        'PCI-DSS': {'controls': 12, 'requirements': 300},
        'HIPAA': {'controls': 18, 'requirements': 180},
        'SOC 2': {'controls': 5, 'requirements': 64},
        'ISO 27001': {'controls': 14, 'requirements': 114},
        'NIST CSF': {'controls': 5, 'requirements': 108},
        'CIS AWS': {'controls': 9, 'requirements': 55}
    }
    
    def __init__(self, client: EnterpriseClaudeClient):
        self.client = client
    
    def assess_compliance(self, frameworks: List[str] = None) -> Dict:
        """Multi-framework compliance assessment"""
        
        if frameworks is None:
            frameworks = list(self.FRAMEWORKS.keys())
        
        # Get real compliance data if available
        compliance_context = self._get_compliance_context()
        
        prompt = f"""As a Chief Compliance Officer with CISSP, CISA, and CRISC certifications, 
assess AWS compliance against the following frameworks: {', '.join(frameworks)}

For each framework, provide:

## Framework Assessment

### [Framework Name]
- **Compliance Score**: X/100
- **Status**: Compliant / Partially Compliant / Non-Compliant
- **Critical Gaps**: List top 3 gaps with remediation priority
- **Risk Rating**: Critical / High / Medium / Low

## Cross-Framework Analysis
- Common control gaps affecting multiple frameworks
- Shared remediation opportunities
- Control mapping synergies

## Remediation Roadmap
Priority-ordered list of remediation actions with:
- Gap description
- Affected frameworks
- Remediation steps
- Estimated effort
- Business risk if not addressed

## Executive Risk Summary
2-3 sentence summary suitable for board presentation.

Format in clean markdown."""

        context = f"""COMPLIANCE CONTEXT:
{json.dumps(compliance_context, indent=2, default=str)}

Assessment Date: {datetime.now().strftime('%Y-%m-%d')}"""

        return self.client.analyze(prompt, context)
    
    def _get_compliance_context(self) -> Dict:
        """Get compliance data from Security Hub or fallback"""
        is_demo = st.session_state.get('demo_mode', False)
        
        if not is_demo:
            real_data = self._fetch_security_hub_findings()
            if real_data:
                return real_data
        
        # Fallback context
        if is_demo:
            return {
                'data_source': 'Demo Data',
                'aws_account_type': 'Enterprise Multi-Account (640+ accounts)',
                'security_hub_enabled': True,
                'findings_summary': {
                    'critical': 12,
                    'high': 45,
                    'medium': 128,
                    'low': 234
                },
                'config_rules_active': 156,
                'guardduty_enabled': True,
                'compliance_standards_enabled': ['AWS Foundational Security', 'CIS AWS', 'PCI-DSS']
            }
        else:
            return {
                'data_source': 'Fallback (Security Hub not connected)',
                'aws_account_type': 'Unknown',
                'security_hub_enabled': 'Unknown',
                'note': 'Connect to AWS Security Hub for accurate compliance data'
            }
    
    def _fetch_security_hub_findings(self) -> Optional[Dict]:
        """Fetch real Security Hub findings"""
        try:
            clients = st.session_state.get('aws_clients', {})
            sh_client = clients.get('securityhub')
            
            if not sh_client:
                return None
            
            # Get findings summary
            findings_summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            try:
                # Get findings by severity
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    response = sh_client.get_findings(
                        Filters={
                            'SeverityLabel': [{'Value': severity, 'Comparison': 'EQUALS'}],
                            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
                        },
                        MaxResults=100
                    )
                    findings_summary[severity.lower()] = len(response.get('Findings', []))
            except Exception as e:
                print(f"Error fetching findings: {e}")
            
            # Get enabled standards
            enabled_standards = []
            try:
                standards_response = sh_client.get_enabled_standards()
                for standard in standards_response.get('StandardsSubscriptions', []):
                    standard_arn = standard.get('StandardsArn', '')
                    if 'aws-foundational' in standard_arn.lower():
                        enabled_standards.append('AWS Foundational Security')
                    elif 'cis-aws' in standard_arn.lower():
                        enabled_standards.append('CIS AWS')
                    elif 'pci-dss' in standard_arn.lower():
                        enabled_standards.append('PCI-DSS')
            except Exception as e:
                print(f"Error fetching standards: {e}")
            
            account_id = st.session_state.get('aws_account_id', 'Unknown')
            
            return {
                'data_source': 'AWS Security Hub (Live)',
                'account_id': account_id,
                'security_hub_enabled': True,
                'findings_summary': findings_summary,
                'total_active_findings': sum(findings_summary.values()),
                'compliance_standards_enabled': enabled_standards,
                'guardduty_enabled': 'guardduty' in clients
            }
            
        except Exception as e:
            print(f"❌ Error fetching Security Hub data: {e}")
            return None


class ExecutiveReportService:
    """Enterprise Executive Report Service"""
    
    def __init__(self, client: EnterpriseClaudeClient, finops_service: 'FinOpsAnalysisService' = None):
        self.client = client
        self.finops_service = finops_service
    
    def generate_summary(self, include_financials: bool = True, include_compliance: bool = True) -> Dict:
        """Generate C-level executive summary"""
        
        # Get real cost data if available
        cost_context = self._get_cost_context()
        
        prompt = """As VP of Cloud Operations presenting to the C-suite, generate an executive summary that includes:

## Executive Dashboard

### Key Performance Indicators
| Metric | Current | Trend | Status |
|--------|---------|-------|--------|
(Include: Cost, Compliance, Security, Performance)

### Risk Summary
Top 3 risks requiring executive attention with business impact.

### Financial Overview
- Current cloud spend vs budget
- Optimization opportunities
- ROI of recommended actions

### Compliance Status
- Overall compliance posture
- Critical gaps requiring attention
- Audit readiness assessment

### Strategic Recommendations
Top 5 recommendations for next quarter with:
- Business justification
- Expected ROI
- Resource requirements
- Risk if not implemented

### 90-Day Priorities
Numbered priority list with owners and deadlines.

## Appendix
Key metrics and trends for reference.

Format for executive presentation. Use business language, not technical jargon.
Include specific dollar amounts and percentages."""

        context = f"""CONTEXT:
{json.dumps(cost_context, indent=2, default=str)}

Compliance Frameworks: PCI-DSS, HIPAA, SOC 2, ISO 27001
Report Date: {datetime.now().strftime('%Y-%m-%d')}"""

        return self.client.analyze(prompt, context)
    
    def _get_cost_context(self) -> Dict:
        """Get cost context for executive report"""
        is_demo = st.session_state.get('demo_mode', False)
        
        # Try to get real data
        if not is_demo and self.finops_service:
            real_data = self.finops_service._fetch_real_aws_costs()
            if real_data:
                return {
                    'data_source': real_data.get('data_source', 'AWS Cost Explorer'),
                    'organization_type': 'Enterprise',
                    'monthly_cloud_spend': f"${real_data.get('total_monthly_cost', 0):,.2f}",
                    'month_over_month': real_data.get('month_over_month_change', 'N/A'),
                    'top_services': real_data.get('top_services', {}),
                    'anomalies': real_data.get('anomalies_detected', 0),
                    'reservation_coverage': real_data.get('reservation_coverage', 'N/A'),
                    'account_id': real_data.get('account_id', 'Unknown')
                }
        
        # Fallback to static context
        if is_demo:
            return {
                'data_source': 'Demo Data',
                'organization_type': 'Enterprise',
                'aws_accounts': '640+',
                'monthly_cloud_spend': '$2.8M',
                'month_over_month': '+8.2%'
            }
        else:
            return {
                'data_source': 'Fallback (AWS not connected)',
                'organization_type': 'Enterprise',
                'aws_accounts': 'Unknown',
                'monthly_cloud_spend': 'Unable to fetch',
                'note': 'Connect to AWS for accurate data'
            }


# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

class EnterpriseAIOrchestrator:
    """
    Main orchestrator for enterprise AI analysis.
    Coordinates between different analysis services.
    """
    
    def __init__(self, config: EnterpriseConfig = None):
        self.config = config or EnterpriseConfig()
        self.client = EnterpriseClaudeClient(self.config)
        
        # Initialize services
        self.finops = FinOpsAnalysisService(self.client)
        self.compliance = ComplianceAssessmentService(self.client)
        self.executive = ExecutiveReportService(self.client, self.finops)  # Pass finops for data access
    
    @property
    def is_ready(self) -> bool:
        return self.client.is_available
    
    def run_cost_analysis(self) -> Dict:
        """Run FinOps cost analysis"""
        return self.finops.analyze_costs()
    
    def run_compliance_assessment(self, frameworks: List[str] = None) -> Dict:
        """Run compliance assessment"""
        return self.compliance.assess_compliance(frameworks)
    
    def run_executive_summary(self) -> Dict:
        """Generate executive summary"""
        return self.executive.generate_summary()
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log for compliance"""
        return st.session_state.get('ai_audit_log', [])
    
    def clear_cache(self):
        """Clear response cache"""
        st.session_state.ai_response_cache = {}


# =============================================================================
# STREAMLIT UI COMPONENT
# =============================================================================

def render_crewai_agents_tab():
    """
    Render the Enterprise AI Analysis Center.
    Production-ready UI with proper error handling.
    """
    
    # Header
    st.markdown("""
    <div style='background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); 
         padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>🤖 AI Agent Analysis Center</h2>
        <p style='color: #b8c5d6; margin: 0.5rem 0 0 0;'>
            Multi-Agent AI System for FinOps & Compliance • Powered by Claude
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize orchestrator
    orchestrator = EnterpriseAIOrchestrator()
    
    # Status indicators
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if orchestrator.is_ready:
            st.success("✅ Claude API: Connected")
        else:
            st.error("❌ Claude API: Not configured")
    
    with col2:
        is_demo = st.session_state.get('demo_mode', False)
        if is_demo:
            st.info("📊 Mode: Demo Data")
        else:
            # Check if AWS Cost Explorer is available
            clients = st.session_state.get('aws_clients', {})
            ce_client = clients.get('ce')
            if ce_client:
                st.success("🔴 Mode: Live AWS")
            else:
                st.warning("🟡 Mode: Live (No AWS)")
    
    with col3:
        cache_size = len(st.session_state.get('ai_response_cache', {}))
        st.info(f"💾 Cache: {cache_size} items")
    
    # Show AWS connection details
    is_demo = st.session_state.get('demo_mode', False)
    if not is_demo:
        clients = st.session_state.get('aws_clients', {})
        ce_client = clients.get('ce')
        account_id = st.session_state.get('aws_account_id', 'Not connected')
        
        if ce_client:
            st.success(f"✅ AWS Cost Explorer connected | Account: {account_id}")
        else:
            st.warning("⚠️ AWS Cost Explorer not available. Cost analysis will use fallback data. Check AWS credentials.")
    
    st.markdown("---")
    
    # Agent Cards
    st.markdown("### 🤖 AI Agent Team")
    
    agents_info = [
        {
            "name": "FinOps Analyst", 
            "icon": "💰", 
            "skills": "Cost Analysis, Anomaly Detection, Rightsizing",
            "color": "#4CAF50"
        },
        {
            "name": "Compliance Officer", 
            "icon": "🛡️", 
            "skills": "PCI-DSS, HIPAA, SOC 2, ISO 27001",
            "color": "#2196F3"
        },
        {
            "name": "Executive Reporter", 
            "icon": "📋", 
            "skills": "Executive Summaries, Risk Communication",
            "color": "#FF9800"
        }
    ]
    
    cols = st.columns(3)
    for i, agent in enumerate(agents_info):
        with cols[i]:
            st.markdown(f"""
            <div style='background: #1a1a2e; border-radius: 10px; padding: 15px; 
                 border-left: 4px solid {agent['color']}; margin: 5px 0; min-height: 80px;'>
                <h4 style='margin: 0; color: white;'>{agent['icon']} {agent['name']}</h4>
                <p style='color: #b0b0b0; font-size: 0.85em; margin: 5px 0 0 0;'>{agent['skills']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Analysis Actions
    st.markdown("### ⚡ Run AI Analysis")
    
    if not orchestrator.is_ready:
        st.warning("⚠️ Configure ANTHROPIC_API_KEY in secrets to enable AI analysis")
        st.code("""
# Add to .streamlit/secrets.toml:
[anthropic]
api_key = "sk-ant-api03-your-key-here"
        """)
        return
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("💰 Cost Analysis", type="primary", use_container_width=True, 
                     key="enterprise_cost_btn"):
            with st.spinner("🤖 Analyzing costs..."):
                results = orchestrator.run_cost_analysis()
                st.session_state['enterprise_cost_results'] = results
    
    with col2:
        if st.button("🛡️ Compliance Check", use_container_width=True,
                     key="enterprise_compliance_btn"):
            with st.spinner("🤖 Assessing compliance..."):
                results = orchestrator.run_compliance_assessment()
                st.session_state['enterprise_compliance_results'] = results
    
    with col3:
        if st.button("📋 Executive Summary", use_container_width=True,
                     key="enterprise_executive_btn"):
            with st.spinner("🤖 Generating summary..."):
                results = orchestrator.run_executive_summary()
                st.session_state['enterprise_executive_results'] = results
    
    # Clear cache button
    col1, col2, col3 = st.columns([1, 1, 1])
    with col3:
        if st.button("🗑️ Clear Cache", key="clear_cache_btn"):
            orchestrator.clear_cache()
            st.success("Cache cleared!")
    
    st.markdown("---")
    
    # Display Results
    st.markdown("### 📊 Analysis Results")
    
    result_tabs = st.tabs(["💰 Cost Analysis", "🛡️ Compliance", "📋 Executive Summary", "📝 Audit Log"])
    
    with result_tabs[0]:
        _render_results('enterprise_cost_results', 'Cost Analysis')
    
    with result_tabs[1]:
        _render_results('enterprise_compliance_results', 'Compliance Check')
    
    with result_tabs[2]:
        _render_results('enterprise_executive_results', 'Executive Summary')
    
    with result_tabs[3]:
        _render_audit_log()


def _render_results(session_key: str, analysis_name: str):
    """Helper to render analysis results"""
    if session_key in st.session_state:
        results = st.session_state[session_key]
        
        if results.get('success'):
            # Metadata
            meta = results.get('metadata', {})
            col1, col2, col3 = st.columns(3)
            with col1:
                st.caption(f"🕐 {meta.get('timestamp', 'N/A')}")
            with col2:
                st.caption(f"📊 Tokens: {meta.get('tokens_used', 'N/A')}")
            with col3:
                st.caption(f"⏱️ {meta.get('duration_seconds', 'N/A')}s")
            
            if results.get('from_cache'):
                st.info("📦 Result from cache")
            
            st.markdown("---")
            st.markdown(results.get('result', 'No results available'))
        else:
            st.error(results.get('error', 'Analysis failed'))
    else:
        st.info(f"👆 Click '{analysis_name}' to run AI-powered analysis")


def _render_audit_log():
    """Render audit log for compliance"""
    audit_log = st.session_state.get('ai_audit_log', [])
    
    if not audit_log:
        st.info("No audit entries yet. Run an analysis to generate audit logs.")
        return
    
    st.markdown(f"**Total Entries:** {len(audit_log)}")
    
    # Show last 20 entries
    for entry in reversed(audit_log[-20:]):
        with st.expander(f"{entry['timestamp']} - {entry['action']}"):
            st.json(entry['details'])


# =============================================================================
# EXPORTS
# =============================================================================

# Backward-compatible aliases for existing imports in streamlit_app.py
FinOpsComplianceCrew = EnterpriseAIOrchestrator  # Alias for backward compatibility
CrewAIConfig = EnterpriseConfig  # Alias for backward compatibility
CREWAI_AVAILABLE = True  # Always True since we use direct Claude API

__all__ = [
    'EnterpriseAIOrchestrator',
    'EnterpriseConfig',
    'EnterpriseClaudeClient',
    'FinOpsAnalysisService',
    'ComplianceAssessmentService',
    'ExecutiveReportService',
    'render_crewai_agents_tab',
    # Backward-compatible exports
    'FinOpsComplianceCrew',
    'CrewAIConfig',
    'CREWAI_AVAILABLE'
]
