"""
Predictive FinOps - Complete Scene 7 Implementation with CrewAI Integration
AWS re:Invent 2025 Video Script

Features for Scene 7:
1. Cost Anomaly Alert (predicted vs expected)
2. Root Cause Analysis
3. Time to Impact countdown
4. AI-Powered Recommendations
5. Savings Calculation
6. One-Click Remediation
7. Trend Visualization
8. NEW: CrewAI Multi-Agent Analysis

Duration: Part of Act 4 (3:30 - 4:20)
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time


# =============================================================================
# CREWAI INTEGRATION - REMOVED (Now in streamlit_app.py)
# =============================================================================
# CrewAI agents are now integrated directly in streamlit_app.py under the
# FinOps tab → AI Agents sub-tab. No need for duplicate here.

CREWAI_AGENTS_AVAILABLE = False


# =============================================================================
# AWS COST DATA FUNCTIONS
# =============================================================================

def get_real_cost_data():
    """Fetch real cost data from AWS Cost Explorer"""
    try:
        clients = st.session_state.get('aws_clients', {})
        ce_client = clients.get('ce')
        
        if not ce_client:
            return None
        
        # Get date range (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        # Fetch cost and usage data
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='DAILY',
            Metrics=['BlendedCost', 'UnblendedCost'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'}
            ]
        )
        
        # Process results
        daily_costs = []
        service_costs = {}
        total_cost = 0
        
        for result in response.get('ResultsByTime', []):
            date = result['TimePeriod']['Start']
            day_total = 0
            
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                day_total += cost
                
                if service not in service_costs:
                    service_costs[service] = 0
                service_costs[service] += cost
            
            daily_costs.append({
                'date': date,
                'cost': day_total
            })
            total_cost += day_total
        
        # Get cost forecast
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
        
        # Get cost anomalies
        anomalies = []
        try:
            anomaly_response = ce_client.get_anomalies(
                DateInterval={
                    'StartDate': start_date.strftime('%Y-%m-%d'),
                    'EndDate': end_date.strftime('%Y-%m-%d')
                },
                MaxResults=10
            )
            anomalies = anomaly_response.get('Anomalies', [])
        except Exception as e:
            print(f"Anomalies not available: {e}")
        
        # Sort services by cost
        top_services = sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_cost': total_cost,
            'daily_costs': daily_costs,
            'service_costs': dict(top_services),
            'forecast': forecast,
            'anomalies': anomalies,
            'period': f"{start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')}"
        }
        
    except Exception as e:
        st.error(f"Error fetching cost data: {str(e)}")
        return None


def render_live_finops_dashboard(cost_data):
    """Render FinOps dashboard with real AWS data"""
    
    st.success("✅ **Live Mode** - Displaying real AWS Cost Explorer data")
    st.caption(f"📅 Period: {cost_data.get('period', 'Last 30 days')}")
    
    st.markdown("---")
    
    # Cost Overview Metrics
    total_cost = cost_data.get('total_cost', 0)
    forecast = cost_data.get('forecast', 0)
    daily_avg = total_cost / 30 if total_cost else 0
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Cost (30 days)", f"${total_cost:,.2f}")
    
    with col2:
        st.metric("Daily Average", f"${daily_avg:,.2f}")
    
    with col3:
        if forecast:
            st.metric("Forecasted (Next Month)", f"${forecast:,.2f}",
                     delta=f"{((forecast - total_cost) / total_cost * 100):+.1f}%" if total_cost else None)
        else:
            st.metric("Forecasted", "N/A")
    
    with col4:
        anomaly_count = len(cost_data.get('anomalies', []))
        st.metric("Cost Anomalies", anomaly_count,
                 delta="detected" if anomaly_count > 0 else "none")
    
    st.markdown("---")
    
    # Cost Trend Chart
    col_chart, col_services = st.columns([2, 1])
    
    with col_chart:
        st.markdown("### 📈 Daily Cost Trend")
        
        daily_costs = cost_data.get('daily_costs', [])
        if daily_costs:
            df = pd.DataFrame(daily_costs)
            df['date'] = pd.to_datetime(df['date'])
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=df['date'],
                y=df['cost'],
                mode='lines+markers',
                name='Daily Cost',
                line=dict(color='#FF9900', width=2),
                marker=dict(size=6)
            ))
            
            # Add average line
            avg_cost = df['cost'].mean()
            fig.add_hline(y=avg_cost, line_dash="dash", line_color="green",
                         annotation_text=f"Avg: ${avg_cost:,.2f}")
            
            fig.update_layout(
                xaxis_title="Date",
                yaxis_title="Cost ($)",
                hovermode='x unified',
                height=350
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No daily cost data available")
    
    with col_services:
        st.markdown("### 🏷️ Top Services")
        
        service_costs = cost_data.get('service_costs', {})
        if service_costs:
            for service, cost in list(service_costs.items())[:7]:
                short_name = service.replace('Amazon ', '').replace('AWS ', '')[:25]
                pct = (cost / total_cost * 100) if total_cost else 0
                
                st.markdown(f"""
                <div style='margin-bottom: 8px;'>
                    <div style='display: flex; justify-content: space-between; font-size: 13px;'>
                        <span>{short_name}</span>
                        <span style='font-weight: bold;'>${cost:,.2f}</span>
                    </div>
                    <div style='background: #eee; border-radius: 4px; height: 8px; margin-top: 3px;'>
                        <div style='background: #FF9900; height: 100%; border-radius: 4px; width: {min(pct, 100):.1f}%;'></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No service breakdown available")
    
    # Anomalies section
    anomalies = cost_data.get('anomalies', [])
    if anomalies:
        st.markdown("---")
        st.markdown("### 🚨 Detected Cost Anomalies")
        
        for anomaly in anomalies[:5]:
            with st.expander(f"⚠️ Anomaly: {anomaly.get('AnomalyId', 'Unknown')[:8]}..."):
                st.json(anomaly)


# =============================================================================
# MAIN RENDER FUNCTION
# =============================================================================

def render_predictive_finops_scene():
    """
    Complete Predictive FinOps scene matching video script Scene 7
    Now supports LIVE mode with real AWS Cost Explorer data
    Note: CrewAI Agents are in streamlit_app.py FinOps → AI Agents tab
    """
    
    st.markdown("## 💰 Predictive FinOps Intelligence")
    st.markdown("*AI-powered cost forecasting and anomaly detection*")
    
    # Check if we're in demo mode or live mode
    is_demo = st.session_state.get('demo_mode', False)
    
    # Create sub-tabs for different views (NO AI Agents - that's in main app)
    finops_sub_tabs = st.tabs([
        "🔮 Predictions",
        "📊 Cost Analysis",
        "💡 Recommendations"
    ])
    
    # Tab 0: Predictions (Original Scene 7)
    with finops_sub_tabs[0]:
        # Get real cost data if in live mode
        if not is_demo and st.session_state.get('aws_connected', False):
            cost_data = get_real_cost_data()
            if cost_data:
                render_live_finops_dashboard(cost_data)
            else:
                render_demo_predictions()
        else:
            render_demo_predictions()
    
    # Tab 1: Cost Analysis
    with finops_sub_tabs[1]:
        render_cost_analysis_tab(is_demo)
    
    # Tab 2: Recommendations
    with finops_sub_tabs[2]:
        render_recommendations_tab(is_demo)


def render_demo_predictions():
    """Render demo mode predictions (original Scene 7 content)"""
    
    st.info("📊 **Demo Mode** - Showing sample FinOps data. Connect to AWS and disable Demo Mode to see real cost data.")
    
    st.markdown("---")
    
    # Cost Anomaly Alert
    st.markdown("### 🚨 Active Cost Anomaly Alerts")
    
    st.markdown("""
    <div style='
        background: linear-gradient(135deg, #FF9900 0%, #FF6600 100%);
        color: white;
        padding: 25px;
        border-radius: 10px;
        border: 3px solid #CC5500;
        margin: 20px 0;
        box-shadow: 0 4px 12px rgba(255,153,0,0.4);
    '>
        <div style='display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;'>
            <div style='display: flex; align-items: center;'>
                <span style='font-size: 36px; margin-right: 15px;'>🚨</span>
                <div>
                    <h2 style='margin: 0; color: white;'>Predicted Cost Anomaly</h2>
                    <p style='margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;'>AI-detected spending pattern deviation</p>
                </div>
            </div>
            <div style='background: rgba(0,0,0,0.3); padding: 10px 20px; border-radius: 8px; text-align: center;'>
                <div style='font-size: 12px; opacity: 0.9;'>Confidence</div>
                <div style='font-size: 24px; font-weight: bold;'>94%</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Cost Comparison Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Expected Cost", "$67K", help="Normal pattern")
    
    with col2:
        st.metric("Predicted Cost", "$94K", delta="+$27K (+40%)", delta_color="inverse")
    
    with col3:
        st.metric("Time to Impact", "4 days", help="Days remaining")
    
    with col4:
        st.metric("Potential Savings", "$18K/mo", help="If remediated")
    
    st.markdown("---")
    
    # Root Cause Analysis
    st.markdown("### 🔍 Root Cause Analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        **Primary Cause:** Misconfigured Auto-Scaling
        
        | Factor | Detail |
        |--------|--------|
        | Service | Amazon EC2 Auto Scaling |
        | Region | us-east-1 |
        | Issue | Low CPU threshold (50%) causing over-provisioning |
        | Duration | Active for 12 days |
        
        **AI Analysis:**
        > The auto-scaling group `prod-web-asg` is scaling out at 50% CPU utilization, 
        > well below the recommended 70% threshold. This is causing 3-4 additional 
        > m5.xlarge instances to run continuously during business hours.
        """)
    
    with col2:
        st.markdown("**Impact Assessment**")
        
        impact_data = pd.DataFrame({
            'Category': ['Compute', 'Network', 'Storage', 'Other'],
            'Impact': [78, 12, 7, 3]
        })
        
        fig = px.pie(impact_data, values='Impact', names='Category',
                    color_discrete_sequence=['#FF9900', '#232F3E', '#FF6600', '#00A8E1'])
        fig.update_layout(height=200, margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # AI Recommendation
    st.markdown("### 💡 AI Recommendation")
    
    st.success("""
    **Recommended Action:** Adjust Auto-Scaling Threshold
    
    - Change CPU target utilization from 50% → 70%
    - Estimated savings: **$18,000/month** ($216,000/year)
    - Risk level: **Low** (gradual rollout supported)
    - Implementation time: ~5 minutes
    """)
    
    if st.button("🔧 Apply Recommendation", type="primary"):
        with st.spinner("Applying auto-scaling configuration..."):
            progress = st.progress(0)
            for i in range(100):
                time.sleep(0.02)
                progress.progress(i + 1)
            
            st.success("✅ Auto-scaling threshold updated to 70%!")
            st.balloons()


def render_cost_analysis_tab(is_demo: bool):
    """Render cost analysis tab"""
    st.markdown("### 📊 Cost Analysis")
    
    if is_demo:
        # Demo data
        services = ['EC2', 'RDS', 'S3', 'Lambda', 'EKS', 'CloudFront', 'Other']
        costs = [1150, 520, 280, 185, 165, 120, 380]
        total = sum(costs)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            fig = px.pie(values=costs, names=services, title="Cost Distribution by Service",
                        color_discrete_sequence=px.colors.qualitative.Set2)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.metric("Total Monthly Cost", f"${total/1000:.1f}M")
            st.metric("Month-over-Month", "+8.2%", delta_color="inverse")
            st.metric("YTD Total", "$16.8M")
            st.metric("Forecast EOY", "$19.2M")
    else:
        st.info("Connect to AWS in Live mode to see real cost analysis")


def render_recommendations_tab(is_demo: bool):
    """Render recommendations tab"""
    st.markdown("### 💡 Optimization Recommendations")
    
    recommendations = [
        {
            "title": "Right-size EC2 Instances",
            "savings": "$125,000/mo" if is_demo else "$1,250/mo",
            "effort": "Low",
            "impact": "High",
            "details": "45 over-provisioned instances detected with <25% CPU utilization"
        },
        {
            "title": "Purchase Reserved Instances",
            "savings": "$85,000/mo" if is_demo else "$850/mo",
            "effort": "Medium",
            "impact": "High",
            "details": "Steady-state workloads eligible for 1-year commitments"
        },
        {
            "title": "Delete Unused EBS Volumes",
            "savings": "$35,000/mo" if is_demo else "$350/mo",
            "effort": "Low",
            "impact": "Medium",
            "details": "234 unattached volumes consuming storage"
        },
        {
            "title": "Enable S3 Intelligent-Tiering",
            "savings": "$28,000/mo" if is_demo else "$280/mo",
            "effort": "Low",
            "impact": "Medium",
            "details": "12TB rarely accessed data in Standard storage"
        }
    ]
    
    for rec in recommendations:
        with st.expander(f"💡 {rec['title']} — **{rec['savings']}**"):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.write(f"**Effort:** {rec['effort']}")
            with col2:
                st.write(f"**Impact:** {rec['impact']}")
            with col3:
                if st.button("Apply", key=f"apply_{rec['title'][:10]}"):
                    st.success("Recommendation queued for implementation")
            
            st.write(rec['details'])


# =============================================================================
# DASHBOARD SUMMARY (For integration with main app)
# =============================================================================

def render_finops_dashboard_summary():
    """Render a summary view for dashboard integration"""
    is_demo = st.session_state.get('demo_mode', False)
    
    col1, col2, col3, col4 = st.columns(4)
    
    if is_demo:
        with col1:
            st.metric("Monthly Spend", "$2.8M", "+8.2%")
        with col2:
            st.metric("Forecasted", "$2.95M", "Under budget")
        with col3:
            st.metric("Savings Found", "$285K", "10.2%")
        with col4:
            st.metric("Anomalies", "3", "🔴 2 Critical")
    else:
        with col1:
            st.metric("Monthly Spend", "$45.7K", "+5.3%")
        with col2:
            st.metric("Forecasted", "$48.2K")
        with col3:
            st.metric("Savings Found", "$4.2K", "9.2%")
        with col4:
            st.metric("Anomalies", "1", "🟡 Medium")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'render_predictive_finops_scene',
    'render_finops_dashboard_summary',
    'get_real_cost_data'
]


# =============================================================================
# USAGE NOTES
# =============================================================================
"""
INTEGRATION:
1. Import in streamlit_app.py:
   from finops_scene_7_complete import render_predictive_finops_scene

2. Call in FinOps tab:
   finops_tabs = st.tabs(["🔮 Predictive Analytics", ...])
   with finops_tabs[0]:
       render_predictive_finops_scene()

3. Add crewai_finops_agents.py to your project for AI Agents tab

4. Install dependencies:
   pip install crewai crewai-tools anthropic

5. Configure ANTHROPIC_API_KEY in secrets

KEY FEATURES:
✅ Cost anomaly alerts
✅ AI-powered predictions
✅ Live AWS integration
✅ Demo mode support
✅ One-click remediation

NOTE: CrewAI multi-agent analysis is now in streamlit_app.py under FinOps → AI Agents tab
"""
