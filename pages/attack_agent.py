import dash
from dash import html, dcc, Input, Output, State, callback, register_page, clientside_callback, ALL, callback_context
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
from dataclasses import dataclass, field
import re
import time
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Literal
from agent.attack_agent import AttackAgent

# Register page to app       
register_page(__name__, path='/attack-agent', name='Attack Agent')

# Session state to maintain conversation history
@dataclass
class SessionState:
    messages: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ChatMessage:
    """Represents a single message in the chat history."""
    sender: Literal["user", "bot"]
    message: str
    type: str
    file_content: Optional[str] = None
    
    def __post_init__(self):
        """Validate the message after initialization."""
        if self.sender not in ["user", "bot"]:
            raise ValueError("Sender must be either 'user' or 'bot'")


@dataclass
class ChatHistory:
    """Manages a collection of chat messages."""
    messages: List[ChatMessage] = field(default_factory=list)
    
    def add_user_message(self, message: str, msg_type: str, file_content: Optional[str] = None) -> None:
        """Add a user message to the chat history."""
        user_msg = ChatMessage(
            sender="user", 
            message=message, 
            type=msg_type, 
            file_content=file_content
        )
        self.messages.append(user_msg)
    
    def add_bot_message(self, message: str, msg_type: str = "text") -> None:
        """Add a bot message to the chat history."""
        bot_msg = ChatMessage(
            sender="bot", 
            message=message, 
            type=msg_type
        )
        self.messages.append(bot_msg)
    
    def add_message(self, message: ChatMessage) -> None:
        """Add a pre-constructed ChatMessage to the history."""
        self.messages.append(message)
    
    def remove_message(self, index: int) -> Optional[ChatMessage]:
        """Remove a message by index. Returns the removed message or None if index is invalid."""
        if 0 <= index < len(self.messages):
            return self.messages.pop(index)
        return None
    
    def remove_last_message(self) -> Optional[ChatMessage]:
        """Remove and return the last message in the history."""
        if self.messages:
            return self.messages.pop()
        return None
    
    def remove_messages_by_sender(self, sender: Literal["user", "bot"]) -> List[ChatMessage]:
        """Remove all messages from a specific sender. Returns the removed messages."""
        removed = [msg for msg in self.messages if msg.sender == sender]
        self.messages = [msg for msg in self.messages if msg.sender != sender]
        return removed
    
    def clear_history(self) -> None:
        """Clear all messages from the chat history."""
        self.messages.clear()
    
    def get_messages_by_sender(self, sender: Literal["user", "bot"]) -> List[ChatMessage]:
        """Get all messages from a specific sender."""
        return [msg for msg in self.messages if msg.sender == sender]
    
    def get_last_n_messages(self, n: int) -> List[ChatMessage]:
        """Get the last n messages from the history."""
        return self.messages[-n:] if n > 0 else []
    
    def __len__(self) -> int:
        """Return the number of messages in the history."""
        return len(self.messages)
    
    def __getitem__(self, index: int) -> ChatMessage:
        """Allow indexing to access messages."""
        return self.messages[index]
    
    def __iter__(self):
        """Allow iteration over messages."""
        return iter(self.messages)
    
    def to_dict_list(self) -> List[dict]:
        """Convert all messages to a list of dictionaries."""
        result = []
        for msg in self.messages:
            msg_dict = {
                "sender": msg.sender,
                "message": msg.message,
                "type": msg.type
            }
            if msg.file_content is not None:
                msg_dict["file_content"] = msg.file_content
            result.append(msg_dict)
        return result

@dataclass
class UserPromptTracker:
    """
    A data class to track and manage a list of user prompts.
    
    Supports three prompt formats:
    1. Document: {"type": "document", "source": {"type": "base64", "media_type": str, "data": str}}
    2. Image: {"type": "image", "source": {"type": "base64", "media_type": str, "data": str}}
    3. Text: {"type": "text", "text": str}
    """
    
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_prompt(self, prompt: Dict[str, Any]) -> None:
        """Add a prompt to the list."""
        self.prompts.append(prompt)
    
    def add_text_prompt(self, text: str) -> None:
        """Add a text prompt to the list."""
        prompt = {
            "type": "text",
            "text": text
        }
        self.add_prompt(prompt)
    
    def add_document_prompt(self, media_type: str, data: str) -> None:
        """Add a document prompt to the list."""
        prompt = {
            "type": "document",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": data
            }
        }
        self.add_prompt(prompt)
    
    def add_image_prompt(self, media_type: str, data: str) -> None:
        """Add an image prompt to the list."""
        prompt = {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": data
            }
        }
        self.add_prompt(prompt)
    
    def remove_prompt(self, index: int) -> Optional[Dict[str, Any]]:
        """Remove a prompt by index. Returns the removed prompt or None if index is invalid."""
        if 0 <= index < len(self.prompts):
            return self.prompts.pop(index)
        return None
    
    def remove_prompt_by_content(self, prompt: Dict[str, Any]) -> bool:
        """Remove the first matching prompt. Returns True if found and removed, False otherwise."""
        try:
            self.prompts.remove(prompt)
            return True
        except ValueError:
            return False
    
    def clear_prompts(self) -> None:
        """Clear all prompts from the list."""
        self.prompts.clear()
    
    def get_prompts(self) -> List[Dict[str, Any]]:
        """Get a copy of all prompts."""
        return self.prompts.copy()
    
    def get_prompt_count(self) -> int:
        """Get the number of prompts in the list."""
        return len(self.prompts)
    
    def get_prompts_by_type(self, prompt_type: str) -> List[Dict[str, Any]]:
        """Get all prompts of a specific type (text, document, or image)."""
        return [prompt for prompt in self.prompts if prompt.get("type") == prompt_type]
    
    def __len__(self) -> int:
        """Return the number of prompts."""
        return len(self.prompts)
    
    def __getitem__(self, index: int) -> Dict[str, Any]:
        """Get a prompt by index."""
        return self.prompts[index]
    
    def __repr__(self) -> str:
        return f"UserPromptTracker({len(self.prompts)} prompts)"

@dataclass
class Attachment:
    """Represents a single attachment with metadata."""
    
    content: str  # base64 encoded content
    type: str     # file type (e.g., "application/pdf", "image/jpeg")
    file_name: str
    file_content: str  # decoded/readable content if applicable
    
    def to_dict(self) -> Dict[str, str]:
        """Convert attachment to dictionary format."""
        return {
            "content": self.content,
            "type": self.type,
            "file_name": self.file_name,
            "file_content": self.file_content
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'Attachment':
        """Create attachment from dictionary."""
        return cls(
            content=data["content"],
            type=data["type"],
            file_name=data["file_name"],
            file_content=data["file_content"]
        )


@dataclass
class AttachmentTracker:
    """A data class to track and manage a list of attachments."""
    
    attachments: List[Attachment] = field(default_factory=list)
    
    def add_attachment(self, content: str, file_type: str, file_name: str, file_content: str) -> bool:
        """
        Add an attachment to the list.
        
        Args:
            content: Base64 encoded file content
            file_type: MIME type of the file
            file_name: Name of the file
            file_content: Decoded/readable content
            
        Returns:
            True if added successfully, False if file with same name already exists
        """
        if not self.has_attachment_by_name(file_name):
            attachment = Attachment(content, file_type, file_name, file_content)
            self.attachments.append(attachment)
            return True
        return False
    
    def add_attachment_object(self, attachment: Attachment) -> bool:
        """
        Add an attachment object to the list.
        
        Args:
            attachment: Attachment object to add
            
        Returns:
            True if added successfully, False if file with same name already exists
        """
        if not self.has_attachment_by_name(attachment.file_name):
            self.attachments.append(attachment)
            return True
        return False
    
    def remove_attachment_by_name(self, file_name: str) -> bool:
        """
        Remove an attachment by file name.
        
        Args:
            file_name: Name of the file to remove
            
        Returns:
            True if removed successfully, False if not found
        """
        for i, attachment in enumerate(self.attachments):
            if attachment.file_name == file_name:
                self.attachments.pop(i)
                return True
        return False
    
    def remove_attachment_by_index(self, index: int) -> bool:
        """
        Remove an attachment by index.
        
        Args:
            index: Index of the attachment to remove
            
        Returns:
            True if removed successfully, False if index out of range
        """
        try:
            self.attachments.pop(index)
            return True
        except IndexError:
            return False
    
    def has_attachment_by_name(self, file_name: str) -> bool:
        """Check if an attachment with the given file name exists."""
        return any(att.file_name == file_name for att in self.attachments)
    
    def get_attachment_by_name(self, file_name: str) -> Optional[Attachment]:
        """Get an attachment by file name."""
        for attachment in self.attachments:
            if attachment.file_name == file_name:
                return attachment
        return None
    
    def get_attachment_by_index(self, index: int) -> Optional[Attachment]:
        """Get an attachment by index."""
        try:
            return self.attachments[index]
        except IndexError:
            return None
    
    def update_attachment_content(self, file_name: str, new_content: str, new_file_content: str = None) -> bool:
        """
        Update the content of an existing attachment.
        
        Args:
            file_name: Name of the file to update
            new_content: New base64 content
            new_file_content: New decoded content (optional)
            
        Returns:
            True if updated successfully, False if file not found
        """
        attachment = self.get_attachment_by_name(file_name)
        if attachment:
            attachment.content = new_content
            if new_file_content is not None:
                attachment.file_content = new_file_content
            return True
        return False
    
    def clear_attachments(self) -> None:
        """Remove all attachments from the list."""
        self.attachments.clear()
    
    def get_attachment_count(self) -> int:
        """Get the number of attachments."""
        return len(self.attachments)
    
    def get_attachments(self) -> List[Attachment]:
        """Get a copy of the attachments list."""
        return self.attachments.copy()
    
    def get_attachment_names(self) -> List[str]:
        """Get a list of all attachment file names."""
        return [att.file_name for att in self.attachments]
    
    def get_attachments_by_type(self, file_type: str) -> List[Attachment]:
        """Get all attachments of a specific type."""
        return [att for att in self.attachments if att.type == file_type]
    
    def to_dict_list(self) -> List[Dict[str, str]]:
        """Convert all attachments to a list of dictionaries."""
        return [att.to_dict() for att in self.attachments]
    
    def __str__(self) -> str:
        return f"AttachmentTracker({len(self.attachments)} attachments)"
    
    def __repr__(self) -> str:
        file_names = [att.file_name for att in self.attachments]
        return f"AttachmentTracker(files={file_names})"

# Initialize file attachment tracker, user prompt tracker and chat history tracker
attachment_tracker = AttachmentTracker()
user_prompt_tracker = UserPromptTracker()
chat_history_tracker = ChatHistory()

# Default welcome message
welcome_message = {
    "sender": "bot", 
    "message": "Hi, how can I assist you with cloud security testing today?",
}

# Add welcome message to chat history
chat_history_tracker.add_bot_message(message = welcome_message["message"], msg_type="text")

# Initialize the session state
session_state = SessionState()
session_state.messages = [
        {"role": "assistant", "content": [{"type": "text", "text": welcome_message["message"]}]}
    ]

# Initialize halberd agent
chatbot_agent = AttackAgent(session_state)

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

# Page layout
layout = html.Div([
    dbc.Container([
        # dcc.Location to track URL changes
        dcc.Location(id="url-location", refresh=False),
        dcc.Store(id="current-page-path", data="/attack-agent"),  # Store current page
        # Main chat interface
        dbc.Row([
            dbc.Col([
                # Chat display area
                dbc.Card([
                    # Chat messages area
                    dbc.CardBody([
                        html.Div(
                            id="chat-display", 
                            children=default_welcome_display,
                            style={
                                'height': '75vh',
                                'overflowY': 'auto',
                                'padding': '16px',
                                'scrollBehavior': 'smooth'
                            },
                            className="chat-container"
                        ),
                        typing_indicator,
                        # trigger for automatic scroll in chat window
                        html.Div(id="scroll-trigger", style={'display': 'none'})
                    ], className="p-0"),
                    
                    # Input area
                    dbc.CardFooter([
                        # Display for uploaded files waiting to be sent
                        html.Div(id="upload-display", className="mb-2"),

                        dbc.Col([
                            dbc.Row(
                                dcc.Textarea(
                                    id="user-input",
                                    placeholder="Reply to Halberd Agent...",
                                    rows=1,
                                    className="bg-halberd-dark halberd-text halberd-input",
                                    style={'border': 'none', 'boxShadow': 'none'}
                                ),
                                class_name="mb-2"
                            ),

                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        # Button - Upload file
                                        dcc.Upload(
                                            id="upload-to-agent-chat",
                                            children=dbc.Button([
                                                DashIconify(icon="mdi:attachment", width=18, className="me-2")
                                            ],
                                            title="Upload a file", id="upload-to-agent-chat-button", n_clicks=0, size="sm", className="me-2"),
                                        ),
                                        # Button - Reset chat
                                        dbc.Button([
                                            DashIconify(icon="mdi:chat-plus-outline", width=18, className="me-1"),
                                        ], title = "New chat", id="new-conversation-btn", n_clicks=0, size="sm", className="halberd-button-secondary")
                                    ], className="d-flex")
                                ], width=4),
                                dbc.Col([
                                    # Button - Send message
                                    dbc.Button([
                                        DashIconify(icon="mdi:arrow-up")
                                    ], id="send-button", n_clicks=0, size="sm", className="halberd-button send-button-hover float-end")
                                ])
                            ])
                        ])
                    ], className="bg-halberd-dark halberd-text halberd-depth-card", style={"width": "50%", "margin": "0 auto"})
                ], className="mb-3", style={"border":0}),
            ], width=12),
        ]),
        
        # Store for controlling typing indicator
        dcc.Store(id="typing-state", data={"is_typing": False}),
        
        # Hidden div for triggering bot response after user message
        html.Div(id="trigger-bot-response", style={"display": "none"}),
    ], fluid=True)
],
className="bg-halberd-dark halberd-text",
style={
    'minHeight': '92vh',
    "padding-right": "20px", 
    "padding-left": "20px"
})

# Callback to update the chat on button click or Enter key press
@callback(
    Output("user-input", "value"),
    Output("chat-display", "children"),
    Output("typing-indicator", "style"),
    Output("trigger-bot-response", "children"),
    Output("upload-display", "children", allow_duplicate=True),
    Input("send-button", "n_clicks"),
    State("user-input", "value"),
    prevent_initial_call=True
)
def update_chat(n_clicks, user_message):
    if not n_clicks:
        raise PreventUpdate
    
    # If the input is empty, don't update
    if not user_message or user_message.strip() == "":
        raise PreventUpdate

    if attachment_tracker.get_attachment_count() > 0:
        # Add attachments to history & prompt
        for attachment in attachment_tracker.get_attachments():
            chat_history_tracker.add_user_message(message=attachment.content, msg_type=attachment.type, file_content=attachment.file_content)

            if "image" in attachment.type:
                user_prompt_tracker.add_image_prompt(
                    attachment.type,
                    attachment.content
                )
            
            elif "pdf" in attachment.type:
                user_prompt_tracker.add_document_prompt(
                    attachment.type,
                    attachment.content
                )

            else:
                # File type not supported
                pass

    # Clear attachment tracker
    attachment_tracker.clear_attachments()

    # Add user message to history & prompt
    chat_history_tracker.add_user_message(message=user_message, msg_type= "text")

    user_prompt_tracker.add_text_prompt(user_message)
    
    # Create chat messages display
    chat_display = create_chat_display(chat_history_tracker.to_dict_list())
    
    # Show typing indicator, trigger bot response and clear the attachment store
    return "", chat_display, {"display": "block"}, 1, []

# Helper function to create chat display from history
def create_chat_display(chat_history):
    chat_display = []
    for message in chat_history:
        if message["sender"] == "user":
            message_display_content = None
            if message["type"] == "text":
                message_display_content = dcc.Markdown(children= message["message"], className="m-0")
            elif 'image' in message["type"]:
                message_display_content = html.Img(src=message["file_content"], style={'height': '100%', 'max-height': '500px', 'width': 'auto'})
            elif 'pdf' in message["type"]:
                message_display_content = DashIconify(icon="mdi:file-pdf", className="m-0", style={'height': '100%', 'max-height': '500px', 'width': 'auto'})
                
            
            # User message style
            chat_display.append(
                dbc.Row([
                    dbc.Col(
                        html.Div(
                            message_display_content,
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
    Output("chat-display", "children", allow_duplicate=True),
    Output("typing-indicator", "style", allow_duplicate=True),
    Input("trigger-bot-response", "children"),
    prevent_initial_call=True
)
def generate_bot_response(response_trigger):
    if not response_trigger:
        return dash.no_update, dash.no_update
    
    # Add artificial delay (about 1.5 seconds) to simulate thinking
    time.sleep(1.5)

    # Check if anthropic key is available to use API client
    if chatbot_agent.is_anthropic_ready():
        try:
            # Get bot response using the ChatBot agent
            bot_response = chatbot_agent.process_user_input(user_prompt_tracker.get_prompts())
            
            # Clear all prompts from prompts tracker
            user_prompt_tracker.clear_prompts()
            
            # Add bot response to history
            chat_history_tracker.add_bot_message(message = bot_response, msg_type = "text")
            
            # Create chat messages display
            chat_display = create_chat_display(chat_history_tracker.to_dict_list())
            
            # Hide typing indicator
            return chat_display, {"display": "none"}
            
        except Exception as e:
            # Handle errors
            error_message = f"An error occurred: {str(e)}"
            chat_history_tracker.add_bot_message(message = error_message, msg_type = "text")
            
            # Create chat display with error message
            chat_display = create_chat_display(chat_history_tracker.to_dict_list())
            
            # Hide typing indicator
            return chat_display, {"display": "none"}
    else:
        chat_history_tracker.add_bot_message(message = "API Key Not Found : Add Anthropic API key to use Halberd Attack Agent", msg_type = "text")
            
        # Create chat display with error message
        chat_display = create_chat_display(chat_history_tracker.to_dict_list())
        
        # Hide typing indicator
        return chat_display, {"display": "none"}

# Callback to start new chat
@callback(
    [Output("chat-display", "children", allow_duplicate=True),
     Output("upload-display", "children", allow_duplicate=True)],
    Input("new-conversation-btn", "n_clicks"),
    prevent_initial_call=True
)
def reset_conversation(n_clicks):
    if not n_clicks:
        return dash.no_update, dash.no_update
    
    # If no message from user then no need to start new chat
    if not any(chat_history_tracker.get_messages_by_sender("user")):
        return dash.no_update, dash.no_update
    
    # Save chat
    # Generate current date-time string (file-system friendly format)
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"{current_time}.txt"

    file_path = f"./local/chats/{file_name}"

    # Create and save the file
    with open(file_path, 'w') as f:
        json.dump(chat_history_tracker.to_dict_list(), f, indent=4)
    
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

    # Clear attachment, chat history and user prompt tracker as part of reset
    attachment_tracker.clear_attachments()
    user_prompt_tracker.clear_prompts()
    chat_history_tracker.clear_history()
    chat_history_tracker.add_bot_message(message = welcome_message, msg_type = "text")
    
    return welcome_display, []
    
'''Callback to attach file to agent chat'''
@callback(
    Output("upload-display", "children"),
    Input(component_id = 'upload-to-agent-chat-button', component_property = 'n_clicks'), 
    Input(component_id = 'upload-to-agent-chat', component_property = 'contents'),
    Input(component_id = 'upload-to-agent-chat', component_property = 'filename'),
    prevent_initial_call=True
)
def upload_attachment_callback(n_clicks, ex_file_content, ex_file_name):
    if n_clicks == 0:
        raise PreventUpdate
    if ex_file_content:
        # Extract file content and file type
        pattern = r'^data:([^;]+);base64,(.+)$'
        match = re.match(pattern, ex_file_content)
        if match:
            ex_file_type = match.group(1)
            ex_file_base64_content = match.group(2)
        
        try:
            # Add file info and content to attachment memory store
            attachment_tracker.add_attachment(
                content= ex_file_base64_content,
                file_type= ex_file_type, 
                file_name= ex_file_name,
                file_content= ex_file_content
            )

            # Determine the file type for display
            file_display_items = []
            for file in attachment_tracker.get_attachments():
                if 'image' in file.type:
                    display_icon = "mdi:image"
                elif 'pdf' in file.type:
                    display_icon = "mdi:file-pdf"
                elif 'officedocument' in file.type:
                    display_icon = "mdi:file-document"
                else:
                    display_icon = "mdi:file"

                file_display_items.append(
                    html.Div([
                        DashIconify(icon=display_icon, width=16, className="me-2"),
                        html.Span(file.file_name, className="me-2"),
                        # Button to remove any attached file
                        dbc.Button(
                            DashIconify(icon="mdi:close", width=14, style={"cursor": "pointer"}),
                            id={"type": "remove-chat-attachment-btn", "index": file.file_name}
                        ),
                    ], className="d-flex align-items-center p-2 mb-2 border rounded file-preview-item")
                )

            # Return the div to display
            return html.Div(file_display_items, className="halberd-text")
        except Exception as e:
            raise PreventUpdate
    else:
        raise PreventUpdate
    
'''Callback to remove a file from agent chat'''
@callback(
    Output("upload-display", "children", allow_duplicate=True),
    Input({"type": "remove-chat-attachment-btn", "index": ALL}, "n_clicks"), 
    prevent_initial_call=True
)
def upload_attachment_callback(n_clicks):
    if any(n_clicks):

        ctx = callback_context
        if not ctx.triggered:
            return dash.no_update
        
        button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
        file_name = eval(button_id)['index']

        attachment_tracker.remove_attachment_by_name(file_name)
        # Determine the file type for display
        file_display_items = []
        for file in attachment_tracker.get_attachments():
            if 'image' in file.type:
                display_icon = "mdi:image"
            elif 'pdf' in file.type:
                display_icon = "mdi:file-pdf"
            elif 'officedocument' in file.type:
                display_icon = "mdi:file-document"
            else:
                display_icon = "mdi:file"
            file_display_items.append(
                html.Div([
                    DashIconify(icon=display_icon, width=16, className="me-2"),
                    html.Span(file.file_name, className="me-2"),
                    html.Span(
                        DashIconify(icon="mdi:close", width=14, id={"type": "remove-chat-attachment-btn", "index": file.file_name}, style={"cursor": "pointer"}),
                        className="ms-2"
                    ),
                ], className="d-flex align-items-center p-2 mb-2 border rounded")
            )
        file_display = html.Div(file_display_items, className="halberd-text")
        
        return file_display
    else:
        raise PreventUpdate

# Callback to detect page changes and clear chat
@callback(
    Output("current-page-path", "data"),
    Input("url-location", "pathname"),
    prevent_initial_call=False
)
def handle_page_navigation(current_pathname):
    """Clear chat when navigating to/from this page"""
    
    # Check if we're on the attack-agent page
    if current_pathname == "/attack-agent":
        # If this is a fresh visit to the page (either from another page or refresh)
        # Clear all trackers
        chat_history_tracker.clear_history()
        attachment_tracker.clear_attachments()
        user_prompt_tracker.clear_prompts()
        
        # Reset session state
        session_state.messages = [
            {"role": "assistant", "content": [{"type": "text", "text": welcome_message["message"]}]}
        ]
        
        # Add welcome message back
        chat_history_tracker.add_bot_message(message=welcome_message["message"], msg_type="text")
        
        return current_pathname
    
    # If not on attack-agent page or no change needed
    return current_pathname

# Client-side callback to auto-adjust the height of the textarea
clientside_callback(
    """
    function(value) {
        // Short delay to ensure input has rendered
        setTimeout(function() {
            const textarea = document.getElementById("user-input");
            if (textarea) {
                // Reset height to default first
                textarea.style.height = "38px";
                
                // Expand if content present
                if (value && value.length > 0) {
                    // Set height to scroll height to expand vertically
                    textarea.style.height = textarea.scrollHeight + "px";
                }
                // If no content, keep height at default 38px
            }
        }, 10);
        
        return window.dash_clientside.no_update;
    }
    """,
    Output("user-input", "style"),
    Input("user-input", "value")
)

# Clientside callback for scrolling to new item in chat window
clientside_callback(
    """
    function(children) {
        if (children && children.length > 0) {
            setTimeout(function() {
                var chatDisplay = document.getElementById('chat-display');
                if (chatDisplay) {
                    // Get the last child element (newly added)
                    var lastChild = chatDisplay.lastElementChild;
                    if (lastChild && lastChild.scrollIntoView) {
                        lastChild.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                }
            }, 100);
        }
        return '';
    }
    """,
    Output('scroll-trigger', 'children'),
    Input('chat-display', 'children')
)