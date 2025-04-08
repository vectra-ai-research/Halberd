import dash
from dash import html, dcc, Input, Output, State, callback, register_page
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
from dataclasses import dataclass, field
import time
from typing import List, Dict, Any
from agent.attack_agent import AttackAgent

# Session state to maintain conversation history
@dataclass
class SessionState:
    messages: List[Dict[str, Any]] = field(default_factory=list)

# Default welcome message
welcome_message = {
    "sender": "bot", 
    "message": "Hello! I'm Halberd Attack Agent. How can I assist you with cloud security testing today?",
}

# Initialize the session state
session_state = SessionState()
session_state.messages = [
        {"role": "assistant", "content": [{"type": "text", "text": welcome_message["message"]}]}
    ]

chatbot_agent = AttackAgent(session_state)

# Register page to app       
register_page(__name__, path='/attack-agent', name='Agent')

# Function to create security technique suggestions
def create_suggestion_chips():
    suggestions = [
        "List GCP techniques", 
        "Explain S3 bucket enumeration",
        "Execute Entra app enumeration",
        "Create Azure enumeration playbook"
    ]
    
    return html.Div([
        html.Div([
            html.Span(suggestion, className="suggestion-chip", id=f"suggestion-{i}")
            for i, suggestion in enumerate(suggestions)
        ], className="mt-3 mb-2 halberd-text")
    ])

# Typing indicator component
typing_indicator = html.Div([
    html.Div(className="bot-message-header", children=[
        DashIconify(icon="mdi:robot", width=16, className="me-2"),
        "Halberd Agent is thinking"
    ]),
    html.Div([
        html.Div(className="typing-dot"),
        html.Div(className="typing-dot"),
        html.Div(className="typing-dot")
    ], className="d-flex")
], className="typing-indicator", id="typing-indicator", style={"display": "none"})

default_welcome_display = [
    dbc.Row([
        dbc.Col(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        DashIconify(icon="mdi:robot", width=16, className="me-2"),
                        "Halberd Agent"
                    ], className="bot-message-header"),
                    html.Div(
                        dcc.Markdown(welcome_message["message"], className="m-0"),
                    )
                ])
            ], className="bot-message chat-message halberd-depth-card"),
            width=9
        )
    ], className="mb-2")
]

# App layout
layout = html.Div([
    dbc.Container([
        # Main chat interface
        dbc.Row([
            dbc.Col([
                # Chat display area
                dbc.Card([
                    # Chat header
                    dbc.CardHeader([
                        dbc.Row([
                            dbc.Col([
                                html.Div([
                                    DashIconify(icon="mdi:robot", className="me-2", width=20),
                                    html.Span("Halberd Attack Agent", className="fw-bold halberd-brand")
                                ], className="d-flex align-items-center halberd-text"),
                            ], width=8
                            ),
                            dbc.Col([
                                html.Div([
                                    dbc.Button([
                                        DashIconify(icon="mdi:content-save", width=18, className="me-2"),
                                        "Save Chat"
                                    ], id="save-chat-btn", className="me-2 halberd-button-secondary"),
                                    dbc.Button([
                                        DashIconify(icon="mdi:refresh", width=18, className="me-1"),
                                        "New Conversation"
                                    ], id="new-conversation-btn", className="halberd-button-secondary")
                                ], className="d-flex justify-content-end")
                            ], width=4
                            )
                        ]),
                    ], className="halberd-toolbar halberd-text"),
                    
                    # Chat messages area
                    dbc.CardBody([
                        html.Div(
                            id="chat-display", 
                            children=default_welcome_display,
                            style={
                                'height': '65vh',
                                'overflowY': 'auto',
                                'padding': '16px',
                                'scrollBehavior': 'smooth'
                            },
                            className="chat-container"
                        ),
                        typing_indicator
                    ], className="p-0"),
                    
                    # Input area
                    dbc.CardFooter([
                        # Quick suggestion chips
                        create_suggestion_chips(),
                        
                        # Input group
                        dbc.InputGroup([
                            dbc.Input(
                                id="user-input",
                                placeholder="Type your message here...",
                                type="text",
                                className="bg-halberd-dark halberd-text halberd-input border-end-0"
                            ),
                            dbc.InputGroupText([
                                DashIconify(
                                    icon="mdi:file-upload-outline",
                                    width=20,
                                    className="me-2",
                                    style={"cursor": "pointer"}
                                ),
                            ], style={"background": "rgba(30, 30, 30, 0.7)", "border": "1px solid #333", "borderLeft": "none"}),
                            dbc.Button([
                                DashIconify(icon="mdi:send", width=18)
                            ], id="send-button", n_clicks=0, color="danger", className="halberd-button send-button-hover")
                        ]),
                        html.Small(
                            "Ask me about cloud security testing, attack paths, technique suggestions or to execute techniques.",
                            className="text-muted mt-2 d-block"
                        )
                    ], className="bg-halberd-dark halberd-text", style={"background": "rgba(25, 25, 25, 0.7)", "borderTop": "1px solid #333"})
                ], className=" mb-3 halberd-depth-card"
                ),
            ], width=12),
        ]),
        
        # Hidden div to store chat history as JSON
        dcc.Store(id="chat-history", data=[welcome_message]),
        
        # Store for controlling typing indicator
        dcc.Store(id="typing-state", data={"is_typing": False}),
        
        # Hidden div for triggering bot response after user message
        html.Div(id="trigger-bot-response", style={"display": "none"})
    ], fluid=True)
],
className="bg-halberd-dark halberd-text",
style={
    'minHeight': '100vh',
    "padding-right": "20px", 
    "padding-left": "20px"
})

# Callback to update the chat on button click or Enter key press
@callback(
    [Output("chat-display", "children"),
     Output("chat-history", "data"),
     Output("user-input", "value"),
     Output("typing-indicator", "style"),
     Output("trigger-bot-response", "children")],
    [Input("send-button", "n_clicks"),
     Input("user-input", "n_submit")],
    [State("user-input", "value"),
     State("chat-history", "data")],
    prevent_initial_call=True
)
def update_chat(n_clicks, n_submit, user_message, chat_history):
    # If the input is empty, don't update
    if not user_message or user_message.strip() == "":
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update
    
    # Add user message to history
    chat_history.append({"sender": "user", "message": user_message})
    
    # Create chat messages display
    chat_display = create_chat_display(chat_history)
    
    # Show typing indicator and trigger bot response
    return chat_display, chat_history, "", {"display": "block"}, user_message

# Helper function to create chat display from history
def create_chat_display(chat_history):
    chat_display = []
    for message in chat_history:
        if message["sender"] == "user":
            # User message style
            chat_display.append(
                dbc.Row([
                    dbc.Col(
                        html.Div(
                            dcc.Markdown(message["message"], className="m-0"),
                            className="user-message chat-message"
                        ),
                        width={"size": 9, "offset": 3},
                        className="d-flex justify-content-end"
                    )
                ], className="mb-2")
            )
        else:
            # Bot message style
            # Check if the message contains a command output to format differently
            if "```" in message["message"]:
                parts = message["message"].split("```")
                formatted_message = []
                
                for i, part in enumerate(parts):
                    if i % 2 == 0:  # Regular text
                        if part.strip():
                            formatted_message.append(html.Div(dcc.Markdown(part, className="m-0")))
                    else:  # Code block
                        language = ""
                        code_content = part
                        if "\n" in part:
                            first_line, rest = part.split("\n", 1)
                            if first_line.strip():
                                language = first_line.strip()
                                code_content = rest
                        
                        formatted_message.append(
                            html.Div(code_content, className="command-output")
                        )
                
                chat_display.append(
                    dbc.Row([
                        dbc.Col(
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        DashIconify(icon="mdi:robot", width=16, className="me-2"),
                                        "Halberd Agent"
                                    ], className="bot-message-header"),
                                    html.Div(formatted_message)
                                ])
                            ], className="bot-message chat-message halberd-depth-card"
                            ),
                            width=9
                        )
                    ], className="mb-2")
                )
            else:
                chat_display.append(
                    dbc.Row([
                        dbc.Col(
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        DashIconify(icon="mdi:robot", width=16, className="me-2"),
                                        "Halberd Agent"
                                    ], className="bot-message-header"),
                                    html.Div(
                                        dcc.Markdown(message["message"], className="m-0"),
                                    )
                                ])
                            ], className="bot-message chat-message halberd-depth-card"),
                            width=9
                        )
                    ], className="mb-2"),
                )
    return chat_display

# Callback to handle bot response after a short delay
@callback(
    [Output("chat-display", "children", allow_duplicate=True),
     Output("chat-history", "data", allow_duplicate=True),
     Output("typing-indicator", "style", allow_duplicate=True)],
    [Input("trigger-bot-response", "children")],
    [State("chat-history", "data")],
    prevent_initial_call=True
)
def generate_bot_response(user_message, chat_history):
    if not user_message:
        return dash.no_update, dash.no_update, dash.no_update
    
    # Add artificial delay (about 1.5 seconds) to simulate thinking
    time.sleep(1.5)
    
    try:
        # Get bot response using the ChatBot agent
        bot_response = chatbot_agent.process_user_input(user_message)
        
        # Add bot response to history
        chat_history.append({"sender": "bot", "message": bot_response})
        
        # Create chat messages display
        chat_display = create_chat_display(chat_history)
        
        # Hide typing indicator
        return chat_display, chat_history, {"display": "none"}
        
    except Exception as e:
        # Handle errors
        error_message = f"An error occurred: {str(e)}"
        chat_history.append({"sender": "bot", "message": error_message})
        
        # Create chat display with error message
        chat_display = create_chat_display(chat_history)
        
        # Hide typing indicator
        return chat_display, chat_history, {"display": "none"}

# Callback to reset conversation
@callback(
    [Output("chat-display", "children", allow_duplicate=True),
     Output("chat-history", "data", allow_duplicate=True)],
    Input("new-conversation-btn", "n_clicks"),
    prevent_initial_call=True
)
def reset_conversation(n_clicks):
    if not n_clicks:
        return dash.no_update, dash.no_update
    
    # Reset chat history with just the welcome message
    # Reset the session state
    session_state.messages = [
        {"role": "assistant", "content": [{"type": "text", "text": welcome_message["message"]}]}
    ]
    
    # Create new chat display with just the welcome message
    welcome_display = [
        dbc.Row([
            dbc.Col(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            DashIconify(icon="mdi:robot", width=16, className="me-2"),
                            "Halberd Agent"
                        ], className="bot-message-header"),
                        html.Div(
                            dcc.Markdown(welcome_message["message"], className="m-0"),
                        )
                    ])
                ], className="bot-message chat-message halberd-depth-card"),
                width=9
            )
        ], className="mb-2")
    ]
    
    return welcome_display, [welcome_message]

# Callbacks for suggestion chips
for i in range(5):  # We have 5 suggestion chips
    @callback(
        Output("user-input", "value", allow_duplicate=True),
        Input(f"suggestion-{i}", "n_clicks"),
        State(f"suggestion-{i}", "children"),
        prevent_initial_call=True
    )
    def set_suggestion_text(n_clicks, suggestion_text):
        if n_clicks:
            return suggestion_text
        return dash.no_update