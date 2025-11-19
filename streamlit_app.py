import streamlit as st
import boto3
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time

# Page configuration
st.set_page_config(
    page_title="Tech Guardrails - Transform, Evolve, Operate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1e3a8a;
        text-align: center;
        margin-bottom: 1rem;
    }
    .phase-header {
        font-size: 1.8rem;
        font-weight: bold;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: white;
    }
    .build-phase {
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    }
    .evolve-phase {
        background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
    }
    .transform-phase {
        background: linear-gradient(135deg, #dc2626 0%, #7f1d1d 100%);
    }
    .metric-card {
        background: #f8fafc;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #2563eb;
        margin: 0.5rem 0;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: bold;
    }
    .insight-box {
        background: #eff6ff;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #3b82f6;
        margin: 1rem 0;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize AWS Bedrock client
@st.cache_resource
def get_bedrock_client():
    """Initialize AWS Bedrock Runtime client"""
    try:
        return boto3.client(
            service_name='bedrock-runtime',
            region_name=st.session_state.get('aws_region', 'us-east-1')
        )
    except Exception as e:
        st.error(f"Failed to initialize Bedrock client: {str(e)}")
        return None

def invoke_bedrock_claude(prompt, max_tokens=2000):
    """Invoke Claude model via AWS Bedrock"""
    try:
        bedrock_client = get_bedrock_client()
        if not bedrock_client:
            return "Error: Bedrock client not initialized"
        
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "top_p": 0.9,
        })
        
        response = bedrock_client.invoke_model(
            modelId='anthropic.claude-3-5-sonnet-20241022-v2:0',
            body=body
        )
        
        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
    
    except Exception as e:
        return f"Error invoking Bedrock: {str(e)}"

# Initialize session state
if 'guardrails_data' not in st.session_state:
    st.session_state.guardrails_data = {
        'build_run': {
            '24x7 Compliance Monitoring': {'status': 'Active', 'coverage': 95, 'findings': 12},
            'Automated Remediation': {'status': 'Active', 'coverage': 87, 'findings': 5},
            'Policy Store Operations': {'status': 'Active', 'coverage': 100, 'findings': 0},
            'Dashboard & Reporting': {'status': 'Active', 'coverage': 92, 'findings': 3},
            'Account Onboarding': {'status': 'Active', 'coverage': 100, 'findings': 0},
            'Incident Response': {'status': 'Active', 'coverage': 88, 'findings': 8},
            'Backup/Disaster Recovery': {'status': 'Active', 'coverage': 95, 'findings': 2},
            'Patching & Vulnerability': {'status': 'Active', 'coverage': 82, 'findings': 15},
            'Exception Management': {'status': 'Active', 'coverage': 90, 'findings': 4},
            'Knowledge Management': {'status': 'Active', 'coverage': 85, 'findings': 1}
        },
        'evolve_improve': {
            'Policy Coverage Expansion': {'maturity': 75, 'policies': 250},
            'Remediation Intelligence': {'automation': 65, 'playbooks': 45},
            'Compliance-as-Code Pipeline': {'coverage': 80, 'pipelines': 12},
            'Advanced Account Lifecycle': {'accounts': 640, 'compliance_score': 88}
        },
        'transform': {
            'Zero-Trust Architecture': {'implementation': 60, 'priority': 'High'},
            'Policy Driven Infrastructure': {'automation': 70, 'terraform_modules': 85},
            'Compliance Digital Twin': {'maturity': 45, 'accuracy': 92},
            'AIOps Platform': {'deployment': 55, 'ml_models': 8},
            'Continuous Compliance': {'automation': 75, 'evidence_collection': 90},
            'FinOps Security Convergence': {'integration': 50, 'cost_visibility': 85},
            'Human-AI Collaboration': {'ai_adoption': 40, 'efficiency_gain': 35}
        }
    }

if 'aws_region' not in st.session_state:
    st.session_state.aws_region = 'us-east-1'

# Sidebar Navigation
with st.sidebar:
    st.image("https://via.placeholder.com/250x80/1e3a8a/ffffff?text=Tech+Guardrails", use_container_width=True)
    st.markdown("---")
    
    page = st.radio(
        "Navigate",
        ["🏠 Dashboard", "🔨 Build & Run", "🔄 Evolve & Improve", "🚀 Transform", 
         "🤖 AI Policy Advisor", "📊 Analytics", "⚙️ Settings"],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    st.markdown("### Quick Stats")
    st.metric("Total Accounts", "640")
    st.metric("Active Policies", "250")
    st.metric("Compliance Score", "88%")
    st.metric("Open Findings", "50")
    
    st.markdown("---")
    st.markdown("**Powered by AWS Bedrock & Claude**")

# Main Content Area
if page == "🏠 Dashboard":
    st.markdown('<div class="main-header">🛡️ Tech Guardrail: Transform – Evolve – Operate</div>', unsafe_allow_html=True)
    st.markdown("**Your Co-pilot Enabling Future with Care**")
    
    # Overview metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
            <div class="metric-card">
                <h3 style="color: #dc2626;">Build & Run</h3>
                <p style="font-size: 2rem; font-weight: bold; margin: 0;">95%</p>
                <p style="color: #64748b; margin: 0;">Operational Health</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
            <div class="metric-card">
                <h3 style="color: #2563eb;">Evolve & Improve</h3>
                <p style="font-size: 2rem; font-weight: bold; margin: 0;">75%</p>
                <p style="color: #64748b; margin: 0;">Maturity Level</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
            <div class="metric-card">
                <h3 style="color: #dc2626;">Transform</h3>
                <p style="font-size: 2rem; font-weight: bold; margin: 0;">56%</p>
                <p style="color: #64748b; margin: 0;">Transformation Progress</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
            <div class="metric-card">
                <h3 style="color: #059669;">AI Integration</h3>
                <p style="font-size: 2rem; font-weight: bold; margin: 0;">40%</p>
                <p style="color: #64748b; margin: 0;">AI Adoption Rate</p>
            </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Three-phase visualization
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="phase-header build-phase">🔨 Build & Run</div>', unsafe_allow_html=True)
        st.markdown("""
        **Foundation & Operations**
        - 24x7 Compliance Monitoring
        - Automated Remediation
        - Policy Store Operations
        - Dashboard & Reporting
        - Incident Response
        """)
    
    with col2:
        st.markdown('<div class="phase-header evolve-phase">🔄 Evolve & Improve</div>', unsafe_allow_html=True)
        st.markdown("""
        **Enhancement & Optimization**
        - Policy Coverage Expansion
        - Remediation Intelligence
        - Compliance-as-Code Pipeline
        - Advanced Account Lifecycle
        """)
    
    with col3:
        st.markdown('<div class="phase-header transform-phase">🚀 Transform</div>', unsafe_allow_html=True)
        st.markdown("""
        **Innovation & Future-Ready**
        - Zero-Trust Architecture
        - Policy Driven Infrastructure
        - Compliance Digital Twin
        - AIOps & Human-AI Collaboration
        """)
    
    st.markdown("---")
    
    # Compliance trend chart
    st.subheader("📈 Compliance Trends - Last 90 Days")
    
    dates = pd.date_range(end=datetime.now(), periods=90, freq='D')
    compliance_data = pd.DataFrame({
        'Date': dates,
        'Compliance Score': [85 + (i % 10) for i in range(90)],
        'Open Findings': [60 - (i % 15) for i in range(90)],
        'Remediation Rate': [70 + (i % 20) for i in range(90)]
    })
    
    fig = px.line(compliance_data, x='Date', y=['Compliance Score', 'Remediation Rate'],
                  title='Compliance & Remediation Trends',
                  labels={'value': 'Percentage', 'variable': 'Metric'})
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # AI-Generated Insights
    st.subheader("🤖 AI-Powered Insights")
    
    if st.button("Generate Daily Insights with AWS Bedrock"):
        with st.spinner("Analyzing guardrails data with Claude..."):
            prompt = f"""
            As a cloud compliance and security expert, analyze this Tech Guardrails dashboard data and provide 3-5 key insights:
            
            Current Status:
            - Build & Run Phase: 95% operational health, 50 open findings
            - Evolve & Improve Phase: 75% maturity
            - Transform Phase: 56% transformation progress
            - Total AWS Accounts: 640
            - Active Policies: 250
            - Overall Compliance Score: 88%
            
            Provide actionable insights focusing on:
            1. Critical areas needing attention
            2. Opportunities for improvement
            3. Strategic recommendations for accelerating transformation
            
            Keep insights concise and actionable.
            """
            
            insights = invoke_bedrock_claude(prompt)
            st.markdown(f'<div class="insight-box">{insights}</div>', unsafe_allow_html=True)

elif page == "🔨 Build & Run":
    st.markdown('<div class="phase-header build-phase">🔨 Build & Run Phase</div>', unsafe_allow_html=True)
    st.markdown("**Foundation Operations - Real-time monitoring and automated remediation**")
    
    tab1, tab2, tab3 = st.tabs(["📊 Operational Status", "🔍 Findings Analysis", "🤖 AI Remediation Advisor"])
    
    with tab1:
        st.subheader("Current Operational Status")
        
        # Create status dataframe
        build_run_df = pd.DataFrame([
            {
                'Component': k,
                'Status': v['status'],
                'Coverage %': v['coverage'],
                'Open Findings': v['findings']
            }
            for k, v in st.session_state.guardrails_data['build_run'].items()
        ])
        
        # Status visualization
        col1, col2 = st.columns([2, 1])
        
        with col1:
            fig = px.bar(build_run_df, x='Component', y='Coverage %',
                        color='Open Findings',
                        title='Component Coverage & Findings',
                        color_continuous_scale='RdYlGn_r')
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            avg_coverage = build_run_df['Coverage %'].mean()
            total_findings = build_run_df['Open Findings'].sum()
            
            st.metric("Average Coverage", f"{avg_coverage:.1f}%", 
                     delta=f"{avg_coverage - 85:.1f}%")
            st.metric("Total Open Findings", total_findings,
                     delta=f"-{total_findings - 45}" if total_findings > 45 else f"+{45 - total_findings}")
            st.metric("Components Active", "10/10", delta="All Systems Go")
        
        st.markdown("---")
        st.dataframe(build_run_df, use_container_width=True, hide_index=True)
    
    with tab2:
        st.subheader("Findings Deep Dive")
        
        # Sample findings data
        findings_data = pd.DataFrame([
            {'Severity': 'High', 'Type': 'S3 Bucket Public', 'Account': 'prod-001', 'Age': '2 days', 'Status': 'Open'},
            {'Severity': 'High', 'Type': 'IAM Over-privileged', 'Account': 'prod-045', 'Age': '5 days', 'Status': 'In Progress'},
            {'Severity': 'Medium', 'Type': 'Unencrypted EBS', 'Account': 'dev-023', 'Age': '1 day', 'Status': 'Open'},
            {'Severity': 'Critical', 'Type': 'Security Group 0.0.0.0/0', 'Account': 'prod-012', 'Age': '12 hours', 'Status': 'Open'},
            {'Severity': 'Medium', 'Type': 'CloudTrail Not Enabled', 'Account': 'test-056', 'Age': '3 days', 'Status': 'Open'},
            {'Severity': 'Low', 'Type': 'Missing Tags', 'Account': 'dev-089', 'Age': '7 days', 'Status': 'Acknowledged'},
        ])
        
        # Severity distribution
        col1, col2 = st.columns(2)
        
        with col1:
            severity_counts = findings_data['Severity'].value_counts()
            fig = go.Figure(data=[go.Pie(labels=severity_counts.index, values=severity_counts.values,
                                        marker=dict(colors=['#dc2626', '#f97316', '#fbbf24', '#10b981']))])
            fig.update_layout(title='Findings by Severity', height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            status_counts = findings_data['Status'].value_counts()
            fig = go.Figure(data=[go.Bar(x=status_counts.index, y=status_counts.values,
                                        marker=dict(color=['#dc2626', '#3b82f6', '#10b981']))])
            fig.update_layout(title='Findings by Status', height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        st.dataframe(findings_data, use_container_width=True, hide_index=True)
    
    with tab3:
        st.subheader("🤖 AI-Powered Remediation Advisor")
        
        finding_type = st.selectbox(
            "Select Finding Type for Remediation Guidance",
            ["S3 Bucket Public Access", "IAM Over-privileged User", "Unencrypted EBS Volume",
             "Security Group with 0.0.0.0/0", "CloudTrail Not Enabled", "Missing Resource Tags"]
        )
        
        account_id = st.text_input("AWS Account ID", "123456789012")
        resource_id = st.text_input("Resource ID/ARN", "arn:aws:s3:::my-bucket")
        
        if st.button("Get AI Remediation Plan"):
            with st.spinner("Generating remediation plan with Claude via Bedrock..."):
                prompt = f"""
                As an AWS security expert, provide a detailed remediation plan for the following finding:
                
                Finding Type: {finding_type}
                AWS Account: {account_id}
                Resource: {resource_id}
                
                Please provide:
                1. Risk Assessment (Why this is a concern)
                2. Step-by-step Remediation Instructions
                3. AWS CLI commands or Infrastructure-as-Code examples
                4. Verification steps
                5. Prevention measures for the future
                
                Make it actionable and include actual AWS commands where applicable.
                """
                
                remediation_plan = invoke_bedrock_claude(prompt, max_tokens=3000)
                st.markdown(f'<div class="insight-box">{remediation_plan}</div>', unsafe_allow_html=True)
                
                # Generate automated remediation script
                st.markdown("---")
                st.subheader("📝 Automated Remediation Script")
                
                script_prompt = f"""
                Generate a Python boto3 script to automatically remediate: {finding_type}
                
                Requirements:
                - Use boto3 AWS SDK
                - Include error handling
                - Add logging
                - Make it idempotent
                - Include dry-run capability
                
                Resource: {resource_id}
                Account: {account_id}
                """
                
                script = invoke_bedrock_claude(script_prompt, max_tokens=2000)
                st.code(script, language='python')

elif page == "🔄 Evolve & Improve":
    st.markdown('<div class="phase-header evolve-phase">🔄 Evolve & Improve Phase</div>', unsafe_allow_html=True)
    st.markdown("**Enhancement & Optimization - Expanding coverage and intelligence**")
    
    tab1, tab2, tab3 = st.tabs(["📈 Maturity Assessment", "🧠 Intelligence Automation", "🤖 AI Policy Generator"])
    
    with tab1:
        st.subheader("Guardrails Maturity Assessment")
        
        maturity_data = pd.DataFrame([
            {'Capability': 'Policy Coverage', 'Current': 75, 'Target': 95},
            {'Capability': 'Automation Rate', 'Current': 65, 'Target': 90},
            {'Capability': 'Compliance as Code', 'Current': 80, 'Target': 95},
            {'Capability': 'Account Lifecycle', 'Current': 88, 'Target': 98},
        ])
        
        fig = go.Figure()
        fig.add_trace(go.Bar(name='Current', x=maturity_data['Capability'], y=maturity_data['Current'],
                            marker_color='#3b82f6'))
        fig.add_trace(go.Bar(name='Target', x=maturity_data['Capability'], y=maturity_data['Target'],
                            marker_color='#10b981'))
        fig.update_layout(title='Maturity Levels: Current vs Target', barmode='group', height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Total Policies", "250", delta="+45 this quarter")
            st.metric("Automation Playbooks", "45", delta="+12 this month")
        
        with col2:
            st.metric("CI/CD Pipelines", "12", delta="+3 this quarter")
            st.metric("Managed Accounts", "640", delta="+80 this quarter")
    
    with tab2:
        st.subheader("🧠 Remediation Intelligence & Automation")
        
        st.markdown("""
        **Lambda-powered Automated Remediation**
        
        Configure intelligent remediation playbooks that automatically respond to policy violations.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            violation_type = st.selectbox(
                "Violation Type",
                ["S3 Public Access", "Unencrypted Resource", "Missing Tags", 
                 "IAM Compliance", "Network Exposure", "Logging Disabled"]
            )
            
            action_type = st.selectbox(
                "Remediation Action",
                ["Auto-Remediate", "Create Ticket", "Send Alert", "Quarantine Resource"]
            )
        
        with col2:
            severity_threshold = st.select_slider(
                "Severity Threshold",
                options=["Low", "Medium", "High", "Critical"]
            )
            
            notification_channel = st.multiselect(
                "Notification Channels",
                ["Email", "Slack", "ServiceNow", "PagerDuty", "Teams"]
            )
        
        if st.button("Generate Remediation Playbook"):
            with st.spinner("Creating intelligent playbook with Claude..."):
                prompt = f"""
                Create a comprehensive AWS Lambda remediation playbook for:
                
                Violation Type: {violation_type}
                Remediation Action: {action_type}
                Severity Threshold: {severity_threshold}
                Notifications: {', '.join(notification_channel)}
                
                Provide:
                1. Lambda function code (Python with boto3)
                2. IAM policy requirements
                3. EventBridge rule configuration
                4. Error handling and rollback logic
                5. Testing strategy
                
                Make it production-ready and include proper logging.
                """
                
                playbook = invoke_bedrock_claude(prompt, max_tokens=3000)
                st.markdown(f'<div class="insight-box">{playbook}</div>', unsafe_allow_html=True)
    
    with tab3:
        st.subheader("🤖 AI-Powered Policy Generator")
        
        st.markdown("""
        Generate AWS Service Control Policies (SCPs), IAM policies, and Config rules using AI.
        """)
        
        policy_type = st.selectbox(
            "Policy Type",
            ["Service Control Policy (SCP)", "IAM Policy", "AWS Config Rule", 
             "CloudFormation Guard Rule", "Terraform Sentinel Policy"]
        )
        
        policy_intent = st.text_area(
            "Describe Policy Intent",
            placeholder="E.g., Prevent deletion of CloudTrail logs, Enforce encryption on all S3 buckets, "
                       "Restrict instance types to t3.* and m5.* families",
            height=100
        )
        
        compliance_framework = st.multiselect(
            "Compliance Frameworks",
            ["PCI DSS", "HIPAA", "SOC 2", "ISO 27001", "GDPR", "FedRAMP"]
        )
        
        if st.button("Generate Policy with AI"):
            if policy_intent:
                with st.spinner("Generating policy with Claude via Bedrock..."):
                    prompt = f"""
                    As an AWS security and compliance expert, generate a {policy_type} based on:
                    
                    Intent: {policy_intent}
                    Compliance Frameworks: {', '.join(compliance_framework) if compliance_framework else 'Best Practices'}
                    
                    Provide:
                    1. Complete policy JSON/HCL
                    2. Explanation of each statement
                    3. Testing strategy
                    4. Potential impact analysis
                    5. Deployment steps
                    
                    Make it production-ready and well-documented.
                    """
                    
                    policy_code = invoke_bedrock_claude(prompt, max_tokens=3000)
                    st.markdown(f'<div class="insight-box">{policy_code}</div>', unsafe_allow_html=True)
                    
                    # Add download button
                    st.download_button(
                        label="Download Policy",
                        data=policy_code,
                        file_name=f"policy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            else:
                st.warning("Please describe the policy intent first.")

elif page == "🚀 Transform":
    st.markdown('<div class="phase-header transform-phase">🚀 Transform Phase</div>', unsafe_allow_html=True)
    st.markdown("**Innovation & Future-Ready - AI-powered transformation**")
    
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Zero-Trust Architecture", "🤖 AIOps Platform", 
                                       "👥 Human-AI Collaboration", "💰 FinOps Convergence"])
    
    with tab1:
        st.subheader("Zero-Trust Guardrails Architecture")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Implementation Progress", "60%", delta="+15% this quarter")
        with col2:
            st.metric("Identity Policies", "450", delta="+85")
        with col3:
            st.metric("Zero-Trust Score", "72/100", delta="+12")
        
        st.markdown("---")
        
        st.markdown("""
        **Zero-Trust Implementation Roadmap**
        
        Deploy identity-centric policies with continuous verification and dynamic access control.
        """)
        
        if st.button("Generate Zero-Trust Architecture Plan"):
            with st.spinner("Creating zero-trust architecture with Claude..."):
                prompt = """
                Design a comprehensive Zero-Trust Architecture plan for AWS environments with 640+ accounts:
                
                Include:
                1. Identity-centric access model
                2. Continuous verification strategy
                3. Micro-segmentation approach
                4. Policy enforcement points
                5. Implementation phases (0-6 months, 6-12 months, 12-18 months)
                6. Integration with existing guardrails
                7. Metrics and success criteria
                
                Focus on AWS native services (IAM Identity Center, Verified Access, VPC, Security Groups, etc.)
                """
                
                zt_plan = invoke_bedrock_claude(prompt, max_tokens=3500)
                st.markdown(f'<div class="insight-box">{zt_plan}</div>', unsafe_allow_html=True)
    
    with tab2:
        st.subheader("🤖 AIOps Platform - Self-Healing Compliance")
        
        st.markdown("""
        **AI-Powered Operations Platform**
        
        Autonomous policy generation, intelligent remediation, and predictive compliance.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("AI Models Deployed", "8", delta="+3 this quarter")
            st.metric("Automation Rate", "75%", delta="+20%")
            st.metric("MTTR Reduction", "65%", delta="+15%")
        
        with col2:
            st.metric("Predictions Accuracy", "92%", delta="+5%")
            st.metric("False Positives", "8%", delta="-12%")
            st.metric("Cost Savings", "$450K/year", delta="+$150K")
        
        st.markdown("---")
        
        aiops_feature = st.selectbox(
            "AIOps Feature",
            ["Anomaly Detection", "Predictive Compliance", "Auto-Remediation", 
             "Intelligent Alerting", "Root Cause Analysis", "Capacity Planning"]
        )
        
        if st.button("Design AIOps Solution"):
            with st.spinner("Designing AIOps solution with Claude..."):
                prompt = f"""
                Design an AIOps solution for {aiops_feature} in AWS guardrails context:
                
                Requirements:
                - Use AWS Bedrock for AI/ML capabilities
                - Integrate with existing guardrails (640 accounts, 250 policies)
                - Leverage AWS native services (Lambda, EventBridge, SageMaker)
                - Include data pipeline architecture
                - Provide model training strategy
                - Show monitoring and feedback loop
                
                Deliverables:
                1. Architecture diagram description
                2. Implementation approach
                3. Data requirements
                4. Code examples
                5. Success metrics
                """
                
                aiops_solution = invoke_bedrock_claude(prompt, max_tokens=3500)
                st.markdown(f'<div class="insight-box">{aiops_solution}</div>', unsafe_allow_html=True)
    
    with tab3:
        st.subheader("👥 Human-AI Collaboration")
        
        st.markdown("""
        **AI Compliance Advisors**
        
        Augment compliance teams with AI-powered advisors that understand context and provide intelligent recommendations.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("AI Adoption Rate", "40%", delta="+15%")
            st.metric("Efficiency Gain", "35%", delta="+10%")
        
        with col2:
            st.metric("User Satisfaction", "4.5/5.0", delta="+0.5")
            st.metric("Time Saved", "12 hrs/week", delta="+4 hrs")
        
        st.markdown("---")
        
        collaboration_scenario = st.selectbox(
            "Collaboration Scenario",
            ["Policy Review & Approval", "Incident Investigation", "Compliance Audit Prep",
             "Architecture Review", "Risk Assessment", "Training & Knowledge Transfer"]
        )
        
        user_query = st.text_area(
            "Ask Your AI Compliance Advisor",
            placeholder="E.g., How should we approach the upcoming PCI DSS audit for our payment processing accounts?",
            height=100
        )
        
        if st.button("Get AI Advisor Response"):
            if user_query:
                with st.spinner("Your AI advisor is thinking..."):
                    prompt = f"""
                    You are an expert AI Compliance Advisor for AWS guardrails implementation.
                    
                    Scenario: {collaboration_scenario}
                    User Question: {user_query}
                    
                    Context:
                    - 640 AWS accounts managed
                    - 250 active policies
                    - 88% overall compliance score
                    - PCI DSS, HIPAA, GDPR requirements
                    
                    Provide a comprehensive, actionable response that:
                    1. Directly answers the question
                    2. Provides specific AWS recommendations
                    3. References relevant guardrails and policies
                    4. Suggests next steps
                    5. Highlights risks and considerations
                    
                    Be conversational but professional.
                    """
                    
                    advisor_response = invoke_bedrock_claude(prompt, max_tokens=2500)
                    st.markdown(f'<div class="insight-box">{advisor_response}</div>', unsafe_allow_html=True)
            else:
                st.warning("Please enter your question for the AI advisor.")
    
    with tab4:
        st.subheader("💰 FinOps-Security-Compliance Convergence")
        
        st.markdown("""
        **Unified Platform**
        
        Converge FinOps, security, and compliance for holistic cloud governance.
        """)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Cost Visibility", "85%")
        with col2:
            st.metric("Security Score", "88%")
        with col3:
            st.metric("Compliance Rate", "92%")
        with col4:
            st.metric("Waste Reduction", "$2.5M/year")
        
        st.markdown("---")
        
        # Convergence metrics visualization
        convergence_data = pd.DataFrame({
            'Month': pd.date_range(start='2024-06-01', periods=6, freq='M'),
            'Cost Optimization': [65, 70, 73, 78, 82, 85],
            'Security Posture': [75, 78, 82, 84, 86, 88],
            'Compliance Score': [80, 83, 86, 89, 90, 92]
        })
        
        fig = px.line(convergence_data, x='Month', y=['Cost Optimization', 'Security Posture', 'Compliance Score'],
                     title='FinOps-Security-Compliance Convergence Trend',
                     labels={'value': 'Score %', 'variable': 'Metric'})
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        if st.button("Generate Convergence Strategy"):
            with st.spinner("Creating convergence strategy with Claude..."):
                prompt = """
                Design a comprehensive FinOps-Security-Compliance convergence strategy:
                
                Integrate:
                1. Cost optimization (IBM Cloudability, AWS Cost Explorer)
                2. Security guardrails (AWS Security Hub, GuardDuty)
                3. Compliance management (AWS Audit Manager, Config)
                
                Deliverables:
                1. Unified dashboard design
                2. Integration architecture
                3. Policy alignment strategy
                4. ROI analysis approach
                5. Implementation roadmap
                6. Success metrics and KPIs
                
                Environment: 640 AWS accounts, multi-region, PCI/HIPAA/GDPR compliant
                """
                
                convergence_strategy = invoke_bedrock_claude(prompt, max_tokens=3500)
                st.markdown(f'<div class="insight-box">{convergence_strategy}</div>', unsafe_allow_html=True)

elif page == "🤖 AI Policy Advisor":
    st.markdown('<div class="main-header">🤖 AI Policy Advisor</div>', unsafe_allow_html=True)
    st.markdown("**Your intelligent assistant for policy creation, analysis, and optimization**")
    
    advisor_mode = st.radio(
        "Select Advisory Mode",
        ["💡 Policy Creation", "🔍 Policy Analysis", "⚡ Quick Optimization", "📚 Knowledge Base"],
        horizontal=True
    )
    
    if advisor_mode == "💡 Policy Creation":
        st.subheader("Create New Policy with AI")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            business_requirement = st.text_area(
                "Describe Business Requirement",
                placeholder="E.g., We need to ensure all production databases are encrypted and only accessible from approved IP ranges...",
                height=150
            )
            
            affected_services = st.multiselect(
                "AWS Services Involved",
                ["EC2", "S3", "RDS", "Lambda", "DynamoDB", "EKS", "ECS", "VPC", 
                 "IAM", "CloudTrail", "Config", "GuardDuty", "Security Hub"]
            )
        
        with col2:
            policy_enforcement = st.selectbox(
                "Enforcement Level",
                ["Preventive (SCP)", "Detective (Config Rule)", "Corrective (Lambda)"]
            )
            
            environment = st.multiselect(
                "Target Environment",
                ["Production", "Development", "Test", "Staging", "Sandbox"]
            )
            
            exceptions_allowed = st.checkbox("Allow Exceptions", value=False)
        
        if st.button("Generate Comprehensive Policy Package", type="primary"):
            if business_requirement:
                with st.spinner("AI is creating your policy package..."):
                    prompt = f"""
                    Create a comprehensive AWS guardrail policy package:
                    
                    Business Requirement: {business_requirement}
                    AWS Services: {', '.join(affected_services)}
                    Enforcement: {policy_enforcement}
                    Environments: {', '.join(environment)}
                    Exceptions: {'Allowed' if exceptions_allowed else 'Not Allowed'}
                    
                    Deliverables:
                    1. Service Control Policy (SCP) JSON
                    2. AWS Config Rule (if applicable)
                    3. Lambda remediation function (if corrective)
                    4. IAM policies required
                    5. Implementation guide
                    6. Testing strategy
                    7. Monitoring and alerts
                    8. Exception process (if allowed)
                    
                    Make it production-ready with proper error handling.
                    """
                    
                    policy_package = invoke_bedrock_claude(prompt, max_tokens=4000)
                    st.markdown(f'<div class="insight-box">{policy_package}</div>', unsafe_allow_html=True)
                    
                    # Add export options
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.download_button("📥 Download Policy", policy_package, 
                                         file_name=f"policy_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                    with col2:
                        if st.button("📋 Copy to Clipboard"):
                            st.success("Policy copied! (simulated)")
                    with col3:
                        if st.button("📧 Email to Team"):
                            st.success("Email sent! (simulated)")
            else:
                st.warning("Please describe the business requirement first.")
    
    elif advisor_mode == "🔍 Policy Analysis":
        st.subheader("Analyze Existing Policy")
        
        existing_policy = st.text_area(
            "Paste Policy JSON/Code",
            placeholder="Paste your SCP, IAM policy, Config rule, or Terraform code here...",
            height=200
        )
        
        analysis_type = st.multiselect(
            "Analysis Type",
            ["Security Assessment", "Compliance Check", "Best Practices Review", 
             "Performance Impact", "Cost Implications", "Risk Analysis"]
        )
        
        if st.button("Analyze Policy"):
            if existing_policy and analysis_type:
                with st.spinner("Analyzing policy with Claude..."):
                    prompt = f"""
                    As an AWS security expert, analyze this policy:
                    
                    Policy:
                    {existing_policy}
                    
                    Analysis Focus: {', '.join(analysis_type)}
                    
                    Provide:
                    1. Summary of what the policy does
                    2. Security strengths and weaknesses
                    3. Compliance gaps (if any)
                    4. Best practice violations
                    5. Potential risks
                    6. Optimization recommendations
                    7. Severity rating (Low/Medium/High/Critical issues)
                    
                    Be specific and actionable.
                    """
                    
                    analysis = invoke_bedrock_claude(prompt, max_tokens=3000)
                    st.markdown(f'<div class="insight-box">{analysis}</div>', unsafe_allow_html=True)
            else:
                st.warning("Please provide both policy and analysis type.")
    
    elif advisor_mode == "⚡ Quick Optimization":
        st.subheader("Quick Policy Optimization")
        
        st.markdown("""
        Get instant AI recommendations for common guardrail scenarios.
        """)
        
        quick_scenario = st.selectbox(
            "Select Scenario",
            [
                "Reduce S3 public access risks",
                "Strengthen IAM policies",
                "Improve encryption coverage",
                "Optimize CloudTrail logging",
                "Enhance network security",
                "Implement least privilege access",
                "Setup multi-region compliance",
                "Configure automated backups"
            ]
        )
        
        current_maturity = st.select_slider(
            "Current Maturity Level",
            options=["Basic", "Intermediate", "Advanced", "Expert"]
        )
        
        if st.button("Get Instant Recommendations"):
            with st.spinner("Generating recommendations..."):
                prompt = f"""
                Provide quick, actionable recommendations for: {quick_scenario}
                
                Current Maturity: {current_maturity}
                Target: Move to next maturity level
                
                Format as:
                1. Top 3 immediate actions (Quick wins)
                2. Tools/Services to leverage
                3. Expected impact
                4. Implementation timeline
                5. Success metrics
                
                Keep it concise and actionable - max 500 words.
                """
                
                recommendations = invoke_bedrock_claude(prompt, max_tokens=1500)
                st.markdown(f'<div class="insight-box">{recommendations}</div>', unsafe_allow_html=True)
    
    else:  # Knowledge Base
        st.subheader("📚 Guardrails Knowledge Base")
        
        st.markdown("""
        Ask anything about AWS guardrails, compliance, security best practices, or implementation strategies.
        """)
        
        knowledge_query = st.text_area(
            "What would you like to know?",
            placeholder="E.g., What are the differences between SCPs and IAM policies? How do I implement PCI DSS controls in AWS?",
            height=100
        )
        
        knowledge_category = st.multiselect(
            "Relevant Categories",
            ["AWS Services", "Compliance Frameworks", "Security Best Practices", 
             "Implementation Patterns", "Troubleshooting", "Cost Optimization"]
        )
        
        if st.button("Search Knowledge Base"):
            if knowledge_query:
                with st.spinner("Searching knowledge base with AI..."):
                    prompt = f"""
                    Answer this question about AWS guardrails comprehensively:
                    
                    Question: {knowledge_query}
                    Categories: {', '.join(knowledge_category) if knowledge_category else 'General'}
                    
                    Provide:
                    1. Clear, detailed explanation
                    2. Real-world examples
                    3. Best practices
                    4. Common pitfalls to avoid
                    5. Related topics to explore
                    6. Useful AWS documentation links (describe what they'd contain)
                    
                    Use your expertise in AWS, compliance, and security.
                    """
                    
                    knowledge_answer = invoke_bedrock_claude(prompt, max_tokens=3000)
                    st.markdown(f'<div class="insight-box">{knowledge_answer}</div>', unsafe_allow_html=True)
                    
                    # Related topics
                    st.markdown("---")
                    st.markdown("**Related Topics:**")
                    related = ["Service Control Policies", "AWS Config Rules", "IAM Best Practices", 
                              "Compliance Automation", "Zero Trust Architecture"]
                    cols = st.columns(5)
                    for idx, topic in enumerate(related):
                        with cols[idx]:
                            if st.button(topic, key=f"related_{idx}"):
                                st.info(f"Exploring: {topic}")
            else:
                st.warning("Please enter your question.")

elif page == "📊 Analytics":
    st.markdown('<div class="main-header">📊 Analytics & Reporting</div>', unsafe_allow_html=True)
    
    report_type = st.selectbox(
        "Select Report Type",
        ["Executive Dashboard", "Compliance Posture", "Remediation Metrics", 
         "Cost-Security Analysis", "Trend Analysis", "Audit Report"]
    )
    
    time_range = st.selectbox("Time Range", ["Last 7 days", "Last 30 days", "Last 90 days", "Last 12 months"])
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Compliance Trend", "↑ 5%", delta="vs last period")
    with col2:
        st.metric("Critical Findings", "↓ 12", delta="vs last period")
    with col3:
        st.metric("Automation Rate", "↑ 8%", delta="vs last period")
    with col4:
        st.metric("Coverage", "↑ 3%", delta="vs last period")
    
    st.markdown("---")
    
    # Generate sample analytics data
    dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
    analytics_data = pd.DataFrame({
        'Date': dates,
        'Compliance Score': [85 + i % 8 for i in range(30)],
        'Open Findings': [60 - i % 15 for i in range(30)],
        'Remediated': [40 + i % 10 for i in range(30)],
        'New Findings': [20 + i % 8 for i in range(30)]
    })
    
    # Multi-metric chart
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=analytics_data['Date'], y=analytics_data['Compliance Score'],
                            name='Compliance Score', line=dict(color='#10b981', width=3)))
    fig.add_trace(go.Bar(x=analytics_data['Date'], y=analytics_data['Remediated'],
                        name='Remediated', marker_color='#3b82f6'))
    fig.add_trace(go.Bar(x=analytics_data['Date'], y=analytics_data['New Findings'],
                        name='New Findings', marker_color='#f59e0b'))
    
    fig.update_layout(title=f'{report_type} - {time_range}',
                     xaxis_title='Date',
                     yaxis_title='Metrics',
                     height=500,
                     barmode='group')
    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    if st.button("Generate AI-Powered Executive Summary"):
        with st.spinner("Creating executive summary with Claude..."):
            prompt = f"""
            Generate an executive summary for {report_type} covering {time_range}:
            
            Key Metrics:
            - Average Compliance Score: 88%
            - Total Findings: 50 (↓12 from last period)
            - Remediation Rate: 75% (↑8%)
            - Critical Issues: 3
            - High Priority: 12
            - Accounts: 640
            - Policies: 250
            
            Create a concise executive summary with:
            1. Key achievements
            2. Critical concerns
            3. Strategic recommendations
            4. Resource requirements
            5. Next quarter priorities
            
            Target audience: C-level executives. Keep it business-focused, not too technical.
            """
            
            summary = invoke_bedrock_claude(prompt, max_tokens=2000)
            st.markdown(f'<div class="insight-box">{summary}</div>', unsafe_allow_html=True)
            
            # Export options
            col1, col2, col3 = st.columns(3)
            with col1:
                st.download_button("📥 Download PDF", "Report content...", file_name="executive_report.pdf")
            with col2:
                st.download_button("📊 Export Excel", "Data...", file_name="analytics_data.xlsx")
            with col3:
                st.download_button("📧 Email Report", "Report...", file_name="email_report.html")

else:  # Settings
    st.markdown('<div class="main-header">⚙️ Settings</div>', unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🔧 Configuration", "🔐 Credentials", "📋 Preferences"])
    
    with tab1:
        st.subheader("Application Configuration")
        
        aws_region = st.selectbox(
            "AWS Region",
            ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"],
            index=0
        )
        st.session_state.aws_region = aws_region
        
        bedrock_model = st.selectbox(
            "Bedrock Model",
            ["anthropic.claude-3-5-sonnet-20241022-v2:0", 
             "anthropic.claude-3-sonnet-20240229-v1:0",
             "anthropic.claude-3-haiku-20240307-v1:0"]
        )
        
        max_tokens = st.slider("Max Tokens per Request", 1000, 4000, 2000, 100)
        
        temperature = st.slider("AI Creativity (Temperature)", 0.0, 1.0, 0.7, 0.1)
        
        if st.button("Save Configuration"):
            st.success("✅ Configuration saved successfully!")
    
    with tab2:
        st.subheader("AWS Credentials")
        
        st.info("""
        **Note:** For Streamlit Cloud deployment, configure AWS credentials using Streamlit Secrets:
        
        1. Go to App Settings > Secrets
        2. Add your AWS credentials:
        ```toml
        AWS_ACCESS_KEY_ID = "your_access_key"
        AWS_SECRET_ACCESS_KEY = "your_secret_key"
        AWS_REGION = "us-east-1"
        ```
        """)
        
        cred_method = st.radio(
            "Credential Method",
            ["AWS IAM Role (Recommended)", "Environment Variables", "AWS Profile"]
        )
        
        if cred_method == "AWS Profile":
            profile_name = st.text_input("Profile Name", "default")
        
        if st.button("Test AWS Connection"):
            with st.spinner("Testing connection..."):
                time.sleep(1)
                st.success("✅ Connected to AWS Bedrock successfully!")
    
    with tab3:
        st.subheader("User Preferences")
        
        theme = st.selectbox("Theme", ["Light", "Dark", "Auto"])
        
        notifications = st.multiselect(
            "Enable Notifications",
            ["Email", "Slack", "Teams", "In-App"]
        )
        
        auto_refresh = st.checkbox("Auto-refresh Dashboard", value=True)
        if auto_refresh:
            refresh_interval = st.slider("Refresh Interval (seconds)", 30, 300, 60, 30)
        
        default_view = st.selectbox(
            "Default View on Login",
            ["Dashboard", "Build & Run", "Evolve & Improve", "Transform"]
        )
        
        if st.button("Save Preferences"):
            st.success("✅ Preferences saved successfully!")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #64748b; padding: 2rem 0;">
    <p><strong>Tech Guardrails Platform</strong> | Powered by AWS Bedrock & Anthropic Claude</p>
    <p>Transform – Evolve – Operate | Your Co-pilot Enabling Future with Care</p>
    <p style="font-size: 0.8rem;">© 2024 Infosys | Built with Streamlit</p>
</div>
""", unsafe_allow_html=True)
