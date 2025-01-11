'''
Page Navigation url : app/attack-analyse
Page Description : Analyse Halberd attack executions.
'''

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
from datetime import timedelta
from dash import dcc, html
from core.Constants import APP_LOG_FILE

def create_df_from_attack_logs():
    # Read log file
    with open(APP_LOG_FILE, 'r') as file:
        log_data = file.read()
    
    events = []
    for line in log_data.split('\n'):
        if line.strip():
            try:
                parts = line.split(' - INFO - Technique Execution ', 1)
                if len(parts) != 2:
                    continue
                    
                timestamp = parts[0].split(' - ')[0]  # Get timestamp from first part
                action = "Technique Execution"
                data = parts[1]
                
                event = json.loads(data)
                event['timestamp'] = pd.to_datetime(timestamp)
                events.append(event)
            except Exception as e:
                continue
    return pd.DataFrame(events)

def process_attack_data(df, start_date=None, end_date=None):
    """
    Process attack data with optional date filtering
    """
    if start_date and end_date:
        df = df[(df['timestamp'] >= start_date) & (df['timestamp'] <= end_date)]
    
    # Get completed attacks only
    completed_attacks = df[df['status'] == 'completed']
    
    # Return empty data if no attacks in range
    if len(completed_attacks) == 0:
        return {
            'status_counts': pd.Series(dtype='int64'),
            'surface_counts': pd.Series(dtype='int64'),
            'tactic_counts': pd.Series(dtype='int64'),
            'technique_counts': pd.Series(dtype='int64'),
            'source_counts': pd.Series(dtype='int64'),
            'testing_period': {
                'start': start_date,
                'end': end_date,
                'duration': end_date - start_date if start_date and end_date else timedelta(0)
            },
            'tactic_success': pd.DataFrame(),
            'timeline_data': pd.Series(dtype='int64'),
            'total_executions': 0,
            'unique_techniques': 0
        }

    # Calculate metrics
    status_counts = completed_attacks['result'].value_counts()
    surface_counts = completed_attacks['technique'].apply(lambda x: 'AWS' if x.startswith('AWS') else 
                                                        'Azure' if x.startswith('Azure') else
                                                        'Entra' if x.startswith('Entra') else
                                                        'M365' if x.startswith('M365') else 'Other').value_counts()
    tactic_counts = completed_attacks['tactic'].value_counts()
    technique_counts = completed_attacks['technique'].value_counts().head(10)
    source_counts = completed_attacks['source'].value_counts()
    
    # Tactic success rate
    tactic_success = pd.crosstab(completed_attacks['tactic'], completed_attacks['result'])
    tactic_success['success_rate'] = (tactic_success['success'] / (tactic_success['success'] + tactic_success.get('failed', 0)) * 100).round(2)
    
    # Timeline data
    timeline_data = completed_attacks.set_index('timestamp').resample('1h').size()
    
    # Calculate time between attacks
    sorted_attacks = completed_attacks.sort_values('timestamp')
    attack_intervals = sorted_attacks['timestamp'].diff().dropna()
    median_interval = attack_intervals.median()

    return {
        'status_counts': status_counts,
        'surface_counts': surface_counts,
        'tactic_counts': tactic_counts,
        'technique_counts': technique_counts,
        'source_counts': source_counts,
        'testing_period': {
            'start': df['timestamp'].min(),
            'end': df['timestamp'].max(),
            'duration': df['timestamp'].max() - df['timestamp'].min()
        },
        'tactic_success': tactic_success,
        'timeline_data': timeline_data,
        'median_interval': median_interval,
        'total_executions': len(completed_attacks),
        'unique_techniques': len(completed_attacks['technique'].unique())
    }

THEME = {
    'background': '#1a1a1a',  # Main background
    'paper': '#2d2d2d',      # Card background
    'text': '#e0e0e0',       # Primary text
    'secondary_text': '#a0a0a0', # Secondary text
    'accent': '#dc3545',     # Halberd's accent red
    'border': '#404040',     # Border color
    'plot_colors': ['#00ff9d', '#00bcd4', '#7c4dff', '#ff4081', '#ffc107'], # Chart colors
    'success': '#00ff9d',    # Success color
    'danger': '#ff4081',     # Error/danger color
    'warning': '#ffc107',    # Warning color
    'info': '#00bcd4'        # Info color
}

def create_dark_theme_template():
    return {
        'layout': {
            'paper_bgcolor': "#1a1a1a",
            'plot_bgcolor': "#1a1a1a",
            'font': {'color': THEME['text']},
            'xaxis': {
                'gridcolor': THEME['border'],
                'linecolor': THEME['border'],
                'zerolinecolor': THEME['border']
            },
            'yaxis': {
                'gridcolor': THEME['border'],
                'linecolor': THEME['border'],
                'zerolinecolor': THEME['border']
            }
        }
    }

# Update the graph creation functions to use dark theme
def create_timeline_graph(data):
    fig = go.Figure(data=[
        go.Scatter(
            x=data['timeline_data'].index,
            y=data['timeline_data'].values,
            fill='tozeroy',
            fillcolor=f'rgba(0, 255, 157, 0.1)',  # Halberd green with opacity
            line={'color': THEME['accent']},
            name='Attacks'
        )
    ])
    
    fig.update_layout(
        template=create_dark_theme_template(),
        title='Attack Execution Timeline',
        xaxis_title='Time',
        yaxis_title='Number of Attacks',
        height=300
    )
    return fig

def create_pie_chart(values, names, title):
    fig = px.pie(
        values=values,
        names=names,
        title=title,
        hole=0.3,
        color_discrete_sequence=THEME['plot_colors']
    )
    
    fig.update_layout(
        template=create_dark_theme_template(),
        height=350
    )
    return fig

def create_bar_chart(x, y, title, orientation='v', color=THEME['accent']):
    fig = go.Figure([go.Bar(
        x=x,
        y=y,
        marker_color=color,
        orientation=orientation
    )])
    
    fig.update_layout(
        template=create_dark_theme_template(),
        title=title,
        xaxis_tickangle=-45 if orientation == 'v' else 0,
        height=400
    )
    return fig

def create_metric_card(title, value, icon, color):
    return html.Div([
        html.Div([
            html.I(className=f"fas {icon}", style={'fontSize': '24px', 'color': color}),
            html.H4(title, style={'marginLeft': '10px', 'color': THEME['text']})
        ], style={'display': 'flex', 'alignItems': 'center'}),
        html.H2(value, style={'marginTop': '10px', 'color': color})
    ], 
    style={
        'padding': '20px',
        'borderRadius': '10px',
    },
    className="halberd-depth-card")

def create_error_layout(error_message: str) -> html.Div:
    """Creates an error layout with the provided message"""
    return html.Div([
        html.Div([
            html.I(className="fas fa-exclamation-triangle", 
                   style={'fontSize': '48px', 'color': THEME['warning'], 'marginBottom': '20px'}),
            html.H1('Dashboard Error', 
                    style={'color': THEME['text'], 'marginBottom': '20px'}),
            html.P(error_message,
                   style={'color': THEME['secondary_text'], 'fontSize': '18px', 'marginBottom': '20px'}),
            html.P('Please ensure that:', 
                   style={'color': THEME['secondary_text'], 'fontSize': '16px', 'marginBottom': '10px'}),
            html.Ul([
                html.Li('The app.log file exists in the current directory',
                        style={'color': THEME['secondary_text'], 'marginBottom': '5px'}),
                html.Li('The file contains valid Halberd execution logs',
                        style={'color': THEME['secondary_text'], 'marginBottom': '5px'}),
                html.Li('You have read permissions for the file',
                        style={'color': THEME['secondary_text'], 'marginBottom': '5px'})
            ], style={'listStyleType': 'disc', 'marginLeft': '20px'}),
        ], style={
            'textAlign': 'center',
            'padding': '40px',
            'backgroundColor': THEME['paper'],
            'borderRadius': '10px',
            'boxShadow': f'0 2px 4px {THEME["border"]}',
            'border': f'1px solid {THEME["border"]}',
            'maxWidth': '600px',
            'margin': '100px auto'
        })
    ], style={
        'backgroundColor': THEME['background'],
        'minHeight': '100vh',
        'padding': '20px'
    })

def create_welcome_layout() -> html.Div:
    """Creates a welcome layout with getting started instructions"""
    return html.Div([
        html.Div([
            # Logo/Icon Section
            html.Div([
                html.I(className="fas fa-shield-alt", 
                      style={
                          'fontSize': '64px', 
                          'color': THEME['accent'],
                          'marginBottom': '30px'
                      }),
                html.H1('Welcome to Halberd Dashboard', 
                       style={
                           'color': THEME['text'],
                           'marginBottom': '20px',
                           'fontSize': '32px'
                       }),
                html.P('No attack execution data found. Let\'s get started!', 
                      style={
                          'color': THEME['secondary_text'],
                          'fontSize': '18px',
                          'marginBottom': '40px'
                      })
            ], style={'textAlign': 'center'}),

            # Steps Section
            html.Div([
                html.H2('Getting Started', 
                       style={
                           'color': THEME['accent'],
                           'marginBottom': '20px',
                           'fontSize': '24px'
                       }),
                
                # Step 1
                html.Div([
                    html.Div([
                        html.Span('1', style={
                            'backgroundColor': THEME['accent'],
                            'color': THEME['background'],
                            'borderRadius': '50%',
                            'width': '30px',
                            'height': '30px',
                            'display': 'inline-flex',
                            'alignItems': 'center',
                            'justifyContent': 'center',
                            'marginRight': '15px'
                        }),
                        html.H3('Start Testing in Attack Page', 
                               style={'color': THEME['text'], 'display': 'inline'})
                    ], style={'marginBottom': '10px'}),
                    html.P('Navigate to Halberd Attack page', 
                          style={'color': THEME['secondary_text'], 'marginLeft': '45px'}),
                ], style={'marginBottom': '30px'}),
                
                # Step 2
                html.Div([
                    html.Div([
                        html.Span('2', style={
                            'backgroundColor': THEME['accent'],
                            'color': THEME['background'],
                            'borderRadius': '50%',
                            'width': '30px',
                            'height': '30px',
                            'display': 'inline-flex',
                            'alignItems': 'center',
                            'justifyContent': 'center',
                            'marginRight': '15px'
                        }),
                        html.H3('Execute Attack Techniques', 
                               style={'color': THEME['text'], 'display': 'inline'})
                    ], style={'marginBottom': '10px'}),
                    html.P('Run various attack techniques using Halberd', 
                          style={'color': THEME['secondary_text'], 'marginLeft': '45px'}),
                ], style={'marginBottom': '30px'}),
                
                # Step 3
                html.Div([
                    html.Div([
                        html.Span('3', style={
                            'backgroundColor': THEME['accent'],
                            'color': THEME['background'],
                            'borderRadius': '50%',
                            'width': '30px',
                            'height': '30px',
                            'display': 'inline-flex',
                            'alignItems': 'center',
                            'justifyContent': 'center',
                            'marginRight': '15px'
                        }),
                        html.H3('View Results', 
                               style={'color': THEME['text'], 'display': 'inline'})
                    ], style={'marginBottom': '10px'}),
                    html.P('Return to this dashboard to analyze your attack execution results.', 
                          style={'color': THEME['secondary_text'], 'marginLeft': '45px'}),
                ])
            ], style={
                'backgroundColor': THEME['paper'],
                'padding': '30px',
                'borderRadius': '10px',
                'boxShadow': f'0 2px 4px {THEME["border"]}',
                'border': f'1px solid {THEME["border"]}',
                'maxWidth': '800px',
                'margin': '0 auto'
            }),

            # Additional Resources Section
            html.Div([
                html.H3('Additional Resources', 
                       style={
                           'color': THEME['text'],
                           'marginBottom': '15px',
                           'marginTop': '30px'
                       }),
                html.Div([
                    html.A(
                        html.Div([
                            html.I(className="fab fa-github", style={'marginRight': '10px'}),
                            'GitHub Repository'
                        ], style={'display': 'flex', 'alignItems': 'center'}),
                        href="https://github.com/vectra-ai-research/halberd",
                        style={
                            'color': THEME['accent'],
                            'textDecoration': 'none',
                            'marginRight': '20px'
                        }
                    ),
                    html.A(
                        html.Div([
                            html.I(className="fas fa-book", style={'marginRight': '10px'}),
                            'Documentation'
                        ], style={'display': 'flex', 'alignItems': 'center'}),
                        href="https://github.com/vectra-ai-research/halberd/wiki",
                        style={
                            'color': THEME['accent'],
                            'textDecoration': 'none'
                        }
                    )
                ], style={'display': 'flex', 'justifyContent': 'center'})
            ], style={'textAlign': 'center'})
        ])
    ], style={
        'backgroundColor': THEME['background'],
        'minHeight': '100vh',
        'padding': '40px 20px'
    })

def create_layout():
    try:
        df = create_df_from_attack_logs()
        # Handle empty log file
        if len(df)==0:
            return create_welcome_layout()
        min_date = df['timestamp'].min()
        max_date = df['timestamp'].max()
    except Exception as e:
        # Handle unexpected errors
        error_message = "An unexpected error occurred while loading the dashboard"
        return create_error_layout(error_message)
    
    return html.Div([
        # Header with Date Range Picker
        html.Div([
            html.Div([
                html.Div([
                    html.Label('Select Date Range:', 
                                style={'marginRight': '10px', 'color': THEME['text']}),
                    dcc.DatePickerRange(
                        id='date-picker-range',
                        min_date_allowed=min_date,
                        max_date_allowed=max_date,
                        start_date=min_date,
                        end_date=max_date,
                        style={'color': THEME['text']}
                    ),
                ], style={'display': 'inline-block', 'marginRight': '20px'}),
                dbc.Button(
                    [
                        DashIconify(
                            icon="mdi:file-report-outline",
                            width=20,
                            className="me-1"
                        ),
                        "Export Report"
                    ],
                    className="ms-2 halberd-button-secondary",
                    id="download-halberd-report-button",
                    n_clicks=0,
                ),
                dcc.Download(id="download-report")
            ])
        ], 
        style={'textAlign': 'center', 'marginBottom': '30px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}, className="bg-halberd-dark"),
        # Key Metrics Row
        html.Div([
            html.Div([
                html.Div(id='metric-cards', style={'display': 'flex'})
            ])
        ], style={'marginBottom': '20px'}),
        
        # Graphs Container - will be updated by callbacks
        html.Div(id='graphs-container'),
        
        # Footer with execution statistics
        html.Div(id='footer-stats')
    ], style={'padding': '20px', 'minHeight': '100vh'}, className="bg-halberd-dark")