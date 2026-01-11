"""
================================================================================
INTEGRATION PATCH FOR finops_module_enhanced_complete.py
================================================================================

This patch adds CrewAI multi-agent capabilities to your existing enhanced FinOps module.

INSTRUCTIONS:
1. Add the import section at the top of the file (after existing imports)
2. Add the new tab to the tabs list in render_enhanced_finops_dashboard()
3. Add the CrewAI tab content

================================================================================
"""

# =============================================================================
# SECTION 1: ADD THESE IMPORTS (around line 30, after existing imports)
# =============================================================================

IMPORTS_TO_ADD = '''
# ============================================================================
# CREWAI MULTI-AGENT INTEGRATION
# ============================================================================

CREWAI_AVAILABLE = False
CREWAI_ERROR = None

try:
    from crewai_finops_agents import (
        FinOpsComplianceCrew,
        CrewAIConfig,
        render_crewai_agents_tab,
        CREWAI_AVAILABLE as CREWAI_LIB_AVAILABLE
    )
    CREWAI_AVAILABLE = True
    print("✅ CrewAI FinOps Agents module loaded")
except ImportError as e:
    CREWAI_ERROR = str(e)
    print(f"Note: CrewAI module not available: {e}")
    
    # Fallback function
    def render_crewai_agents_tab():
        st.markdown("### 🤖 AI Agent Analysis Center")
        st.warning("⚠️ CrewAI module not available")
        st.markdown("""
        **To enable multi-agent AI analysis:**
        1. Upload `crewai_finops_agents.py` to your project
        2. Install: `pip install crewai crewai-tools`
        3. Ensure `ANTHROPIC_API_KEY` is configured
        
        **Features when enabled:**
        - 💰 Autonomous cost analysis by FinOps Analyst agent
        - 🛡️ Multi-framework compliance assessment
        - 📋 Executive summary generation
        - 🔄 Agents collaborate to provide comprehensive insights
        """)
'''


# =============================================================================
# SECTION 2: MODIFY THE TABS LIST (around line 1223)
# =============================================================================
# Find this line in render_enhanced_finops_dashboard():
#     tabs = st.tabs([
#         "🤖 AI Insights",
#         "💬 Ask Claude",
#         ...
#     ])
#
# REPLACE WITH:

TABS_REPLACEMENT = '''
    # Main tabs - NOW WITH CREWAI AGENTS
    tabs = st.tabs([
        "🤖 AI Insights",
        "🦾 AI Agents",           # ← NEW TAB
        "💬 Ask Claude",
        "🎯 Right-Sizing",
        "🔍 Anomaly Detection",
        "📊 Spend Analytics",
        "📄 Executive Report"
    ])
    
    # AI Insights Tab (index 0)
    with tabs[0]:
        render_ai_insights_panel(cost_data)
    
    # NEW: CrewAI Agents Tab (index 1)
    with tabs[1]:
        render_crewai_agents_section()
    
    # Ask Claude Tab (index 2 - was 1)
    with tabs[2]:
        inventory = fetch_resource_inventory(session)
        render_ai_query_interface(cost_data, context={'resources': inventory})
    
    # Right-Sizing Tab (index 3 - was 2)
    with tabs[3]:
        inventory = fetch_resource_inventory(session)
        resource_data = []
        for ec2 in inventory.get('ec2', []):
            resource_data.append({
                'ResourceId': ec2.get('InstanceId', 'Unknown'),
                'ResourceType': 'EC2',
                'InstanceType': ec2.get('InstanceType', 'Unknown'),
                'State': ec2.get('State', 'Unknown'),
                'MonthlyCost': ec2.get('EstimatedMonthlyCost', 0)
            })
        render_ai_rightsizing_advisor(resource_data)
    
    # Anomaly Detection Tab (index 4 - was 3)
    with tabs[4]:
        render_ai_anomaly_detection(cost_data)
    
    # Spend Analytics Tab (index 5 - was 4)
    with tabs[5]:
        render_spend_analytics(cost_data)
    
    # Executive Report Tab (index 6 - was 5)
    with tabs[6]:
        render_executive_report_tab(cost_data)
'''


# =============================================================================
# SECTION 3: ADD THIS NEW FUNCTION (before render_enhanced_finops_dashboard)
# =============================================================================

NEW_FUNCTION = '''
# ============================================================================
# CREWAI AGENTS SECTION
# ============================================================================

def render_crewai_agents_section():
    """
    Render the CrewAI multi-agent analysis section.
    Falls back gracefully if CrewAI is not installed.
    """
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); 
         padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem;'>
        <h2 style='color: white; margin: 0;'>🦾 Multi-Agent AI Analysis</h2>
        <p style='color: #94a3b8; margin: 0.5rem 0 0 0;'>
            Autonomous AI agents working together for comprehensive FinOps intelligence
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check if CrewAI module is available
    if CREWAI_AVAILABLE:
        render_crewai_agents_tab()
    else:
        # Fallback UI when CrewAI is not available
        st.warning("⚠️ CrewAI multi-agent module not loaded")
        
        if CREWAI_ERROR:
            with st.expander("Show error details"):
                st.code(CREWAI_ERROR)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 📦 Quick Setup
            
            ```bash
            # 1. Upload crewai_finops_agents.py
            
            # 2. Install CrewAI
            pip install crewai crewai-tools
            
            # 3. Restart your app
            ```
            """)
        
        with col2:
            st.markdown("""
            ### 🤖 Agent Capabilities
            
            | Agent | Expertise |
            |-------|-----------|
            | 💰 FinOps Analyst | Cost analysis, rightsizing |
            | 🛡️ Compliance Officer | PCI-DSS, HIPAA, SOC 2 |
            | 📋 Executive Reporter | C-level summaries |
            """)
        
        st.markdown("---")
        
        # Show what they're missing
        st.markdown("### ✨ Preview: What You'll Get")
        
        demo_col1, demo_col2, demo_col3 = st.columns(3)
        
        with demo_col1:
            st.markdown("""
            <div style='background: #1a1a2e; border-radius: 10px; padding: 15px; 
                 border-left: 4px solid #4CAF50;'>
                <h4 style='margin: 0;'>💰 Cost Analysis</h4>
                <p style='color: #888; font-size: 0.85em; margin: 5px 0 0 0;'>
                    Deep dive into spending patterns, anomaly detection, 
                    and optimization opportunities
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        with demo_col2:
            st.markdown("""
            <div style='background: #1a1a2e; border-radius: 10px; padding: 15px; 
                 border-left: 4px solid #2196F3;'>
                <h4 style='margin: 0;'>🛡️ Compliance</h4>
                <p style='color: #888; font-size: 0.85em; margin: 5px 0 0 0;'>
                    Multi-framework assessment with gap analysis 
                    and remediation priorities
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        with demo_col3:
            st.markdown("""
            <div style='background: #1a1a2e; border-radius: 10px; padding: 15px; 
                 border-left: 4px solid #FF9800;'>
                <h4 style='margin: 0;'>📋 Executive</h4>
                <p style='color: #888; font-size: 0.85em; margin: 5px 0 0 0;'>
                    Board-ready summaries with ROI calculations 
                    and risk prioritization
                </p>
            </div>
            """, unsafe_allow_html=True)


def render_spend_analytics(cost_data):
    """Render spend analytics tab"""
    st.markdown("### 📊 Traditional Spend Analytics")
    
    # Calculate total cost
    total_cost = 0
    if cost_data and 'ResultsByTime' in cost_data:
        for result in cost_data['ResultsByTime']:
            total_cost += float(result['Total'].get('UnblendedCost', {}).get('Amount', 0))
    
    st.metric("Total Spend", f"${total_cost:,.2f}")
    
    # Cost by service chart
    if cost_data and 'ResultsByTime' in cost_data:
        service_costs = {}
        for result in cost_data['ResultsByTime']:
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                service_costs[service] = service_costs.get(service, 0) + amount
        
        if service_costs:
            st.markdown("#### Cost by Service")
            df = pd.DataFrame([
                {'Service': k, 'Cost': f"${v:,.2f}"}
                for k, v in sorted(service_costs.items(), key=lambda x: x[1], reverse=True)
            ])
            st.dataframe(df, use_container_width=True, hide_index=True)


def render_executive_report_tab(cost_data):
    """Render executive report tab"""
    st.markdown("### 📄 Executive Report Generator")
    
    client = get_anthropic_client()
    
    if not client:
        st.warning("Configure ANTHROPIC_API_KEY to generate AI-powered executive reports")
        return
    
    if st.button("📝 Generate Executive Report", type="primary"):
        with st.spinner("Generating executive report..."):
            # Calculate metrics
            total_cost = 0
            if cost_data and 'ResultsByTime' in cost_data:
                for result in cost_data['ResultsByTime']:
                    total_cost += float(result['Total'].get('UnblendedCost', {}).get('Amount', 0))
            
            prompt = f"""Generate a concise executive report for cloud cost management:

Total Spend: ${total_cost:,.2f}

Include:
1. Executive Summary (2-3 sentences)
2. Key Metrics
3. Top 3 Cost Optimization Opportunities
4. Risk Assessment
5. Recommended Actions

Keep it concise and business-focused."""
            
            try:
                message = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )
                
                st.markdown("---")
                st.markdown(message.content[0].text)
                
            except Exception as e:
                st.error(f"Error generating report: {str(e)}")
'''


# =============================================================================
# COMPLETE EXAMPLE OF MODIFIED render_enhanced_finops_dashboard
# =============================================================================

COMPLETE_FUNCTION_REPLACEMENT = '''
def render_enhanced_finops_dashboard():
    """
    Main AI-enhanced FinOps dashboard with CrewAI multi-agent support
    """
    st.markdown("""
    <div style='background: linear-gradient(135deg, #232F3E 0%, #37475A 100%); 
                padding: 2rem; 
                border-radius: 10px; 
                text-align: center; 
                margin-bottom: 2rem;
                border-top: 4px solid #FF9900;'>
        <h1 style='color: white; margin: 0;'>🤖 AI-Enhanced FinOps Dashboard</h1>
        <p style='color: #E8F4F8; margin: 0.5rem 0 0 0;'>Intelligent Cost Management powered by Anthropic Claude</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Status indicators
    col1, col2 = st.columns(2)
    
    with col1:
        client = get_anthropic_client()
        if client:
            st.success("✅ Claude AI Active")
        else:
            st.warning("⚠️ Configure ANTHROPIC_API_KEY")
    
    with col2:
        if CREWAI_AVAILABLE:
            st.success("✅ CrewAI Agents Ready")
        else:
            st.info("ℹ️ CrewAI: Install for multi-agent features")
    
    # Date range selector
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=30))
    with col2:
        end_date = st.date_input("End Date", value=datetime.now())
    
    # Fetch cost data
    session = st.session_state.get('boto3_session')
    ce_client = None
    
    if session and not st.session_state.get('demo_mode', False):
        try:
            ce_client = session.client('ce')
        except Exception as e:
            st.warning(f"Unable to create Cost Explorer client: {str(e)}")
    
    cost_data = fetch_cost_data(ce_client, start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d'))
    
    # Main tabs - WITH CREWAI AGENTS
    tabs = st.tabs([
        "🤖 AI Insights",
        "🦾 AI Agents",
        "💬 Ask Claude",
        "🎯 Right-Sizing",
        "🔍 Anomaly Detection",
        "📊 Spend Analytics",
        "📄 Executive Report"
    ])
    
    with tabs[0]:
        render_ai_insights_panel(cost_data)
    
    with tabs[1]:
        render_crewai_agents_section()
    
    with tabs[2]:
        inventory = fetch_resource_inventory(session)
        render_ai_query_interface(cost_data, context={'resources': inventory})
    
    with tabs[3]:
        inventory = fetch_resource_inventory(session)
        resource_data = []
        for ec2 in inventory.get('ec2', []):
            resource_data.append({
                'ResourceId': ec2.get('InstanceId', 'Unknown'),
                'ResourceType': 'EC2',
                'InstanceType': ec2.get('InstanceType', 'Unknown'),
                'State': ec2.get('State', 'Unknown'),
                'MonthlyCost': ec2.get('EstimatedMonthlyCost', 0)
            })
        render_ai_rightsizing_advisor(resource_data)
    
    with tabs[4]:
        render_ai_anomaly_detection(cost_data)
    
    with tabs[5]:
        render_spend_analytics(cost_data)
    
    with tabs[6]:
        render_executive_report_tab(cost_data)
'''

print("""
================================================================================
INTEGRATION COMPLETE!
================================================================================

To integrate CrewAI into finops_module_enhanced_complete.py:

1. Add the IMPORTS_TO_ADD section at the top (after existing imports)

2. Add the render_crewai_agents_section() function before render_enhanced_finops_dashboard()

3. Modify the tabs list in render_enhanced_finops_dashboard() to include "🦾 AI Agents"

4. Add the tab content for CrewAI agents

5. Upload crewai_finops_agents.py to your project

6. Install: pip install crewai crewai-tools

See the COMPLETE_FUNCTION_REPLACEMENT for a full working example.
================================================================================
""")
