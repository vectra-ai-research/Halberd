from anthropic import Anthropic
from .tools import *
from dotenv import load_dotenv
import json
import tiktoken
import time
import random

load_dotenv()

IDENTITY = """You are Halberd Attack Agent, a helpful and knowledgeable AI assistant for Halberd Attack Tool. 
Your role is to assist Halberd tool users, provide information related to tool capabilities, help plan cloud security testing and execute Halberd attack techniques. 
Generate all your responses properly formatted for markdown rendering. 

STEPS TO EXECUTE A TECHNIQUE: 
1. Get appropriate technique
2. Check technique's input requirements
3. Based on technique inputs, configure technique with appropriate inputs. Ask user for input if required.
4. CONFIRM WITH THE USER THE FINAL TECHNIQUE CONFIGURATION
5. Execute technique
6. Return technique execution response in the following structure: 
<technique-response-format>
# Technique Name
Result : {Success(green checkmark)/ Failed(Red X)}

Event ID : {event-id}

## Output Analysis
- Brief analysis of the technique output in bullet points. 
If the output is too large, display a short note to check the full output in [attack-history](/attack-history)

Summary information of the output (if applicable)

## Recommendations
- Table of technique names for next step recommendation if applicable
End response
</technique-response-format>
"""

tool_functions = {
    "execute_technique":execute_technique,
    "list_techniques":list_techniques,
    "list_tactics":list_tactics,
    "get_technique_mitre_info": get_technique_mitre_info,
    "get_technique_aztrm_info": get_technique_aztrm_info,
    "get_technique_inputs": get_technique_inputs,
    "entra_id_get_all_tokens": entra_id_get_all_tokens,
    "entra_id_get_active_token": entra_id_get_active_token,
    "entra_id_get_active_token_pair": entra_id_get_active_token_pair,
    "entra_id_set_active_token": entra_id_set_active_token,
    "entra_id_decode_jwt_token": entra_id_decode_jwt_token,
    "aws_get_all_sessions": aws_get_all_sessions,
    "aws_retrieve_sessions": aws_retrieve_sessions,
    "aws_get_active_session": aws_get_active_session,
    "aws_get_session_details": aws_get_session_details,
    "aws_set_active_session": aws_set_active_session,
    "aws_get_connected_user_details": aws_get_connected_user_details,
    "read_halberd_logs": read_halberd_logs,
    "get_technique_execution_response": get_technique_execution_response
}

# Token limits
MAX_TOTAL_TOKENS = 200000  # Anthropic's total token limit 
MAX_MODEL_TOKENS = 4096  # Claude-3-7-sonnet max tokens
MAX_TOOL_RESPONSE_TOKENS = 15000  # Max size for tool responses

# Rate limiting parameters
RATE_LIMIT_TOKENS_PER_MIN = 20000  # Anthropic's rate limit (tokens per minute)
OUTPUT_RATE_LIMIT_TOKENS_PER_MIN = 8000  # Output tokens rate limit
MIN_DELAY_BETWEEN_CALLS = 3  # Minimum delay in seconds between API calls

class RateLimiter:
    """Tracks API usage and calculates necessary delays to avoid rate limits."""
    
    def __init__(self):
        self.requests_timestamps = []  # Track request timestamps
        self.input_token_usage = []    # Track (timestamp, input_token_count)
        self.output_token_usage = []   # Track (timestamp, output_token_count)
        
    def _clean_old_records(self, current_time):
        """Remove records older than 60 seconds from all tracking lists."""
        minute_ago = current_time - 60
        
        # Clean request timestamps
        self.requests_timestamps = [t for t in self.requests_timestamps if t > minute_ago]
        
        # Clean token usage records
        self.input_token_usage = [(t, count) for t, count in self.input_token_usage if t > minute_ago]
        self.output_token_usage = [(t, count) for t, count in self.output_token_usage if t > minute_ago]
    
    def _calculate_request_delay(self, current_time):
        """Calculate delay needed to stay under request rate limit."""
        # If we haven't hit the request limit, no delay needed
        if len(self.requests_timestamps) < 50:
            return 0
            
        # Calculate when the oldest request will expire from the window
        oldest_timestamp = min(self.requests_timestamps)
        time_until_slot_available = (oldest_timestamp + 60) - current_time
        
        return max(0, time_until_slot_available)
    
    def _calculate_token_delay(self, new_tokens, usage_records, limit, current_time):
        """Calculate delay needed to stay under token rate limit."""
        # Sum current usage in the rolling window
        current_usage = sum(count for _, count in usage_records)
        
        # If adding new tokens doesn't exceed limit, no delay needed
        if current_usage + new_tokens <= limit:
            return 0
            
        # Calculate tokens that need to expire before we can proceed
        tokens_to_expire = (current_usage + new_tokens) - limit
        
        # Sort usage records by timestamp (oldest first)
        sorted_records = sorted(usage_records, key=lambda x: x[0])
        
        # Find wait time for enough tokens to expire
        tokens_expired = 0
        for timestamp, count in sorted_records:
            tokens_expired += count
            if tokens_expired >= tokens_to_expire:
                return max(0, (timestamp + 60) - current_time)
                
        # If we can't expire enough tokens within the window, use maximum delay
        return 60  # Maximum possible delay
    
    def get_required_delay(self, input_tokens, est_output_tokens):
        """Calculate the delay required to satisfy all rate limits."""
        current_time = time.time()
        
        # Remove records older than 60 seconds
        self._clean_old_records(current_time)
        
        # Calculate delays for each constraint
        request_delay = self._calculate_request_delay(current_time)
        input_token_delay = self._calculate_token_delay(
            input_tokens, self.input_token_usage, RATE_LIMIT_TOKENS_PER_MIN, current_time)
        output_token_delay = self._calculate_token_delay(
            est_output_tokens, self.output_token_usage, OUTPUT_RATE_LIMIT_TOKENS_PER_MIN, current_time)
        
        # Get maximum delay required
        max_delay = max(request_delay, input_token_delay, output_token_delay)
        
        if max_delay > 0:
            reason = "requests"
            if input_token_delay == max_delay:
                reason = "input tokens"
            elif output_token_delay == max_delay:
                reason = "output tokens"
            print(f"Rate limiting: Delay of {max_delay:.2f}s required due to {reason} limit")
            
        return max_delay
    
    def record_usage(self, input_tokens, output_tokens, timestamp=None):
        """Record actual usage after an API call."""
        if timestamp is None:
            timestamp = time.time()
            
        self.requests_timestamps.append(timestamp)
        self.input_token_usage.append((timestamp, input_tokens))
        self.output_token_usage.append((timestamp, output_tokens))

class AttackAgent:
    def __init__(self, session_state):
        self.anthropic = Anthropic()
        self.session_state = session_state
        self.encoder = tiktoken.get_encoding("cl100k_base")
        self.last_api_call_time = 0  # Track last API call time for rate limiting
        
        # Add token tracking variables
        self.current_conversation_input_tokens = 0
        self.current_conversation_output_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def count_tokens(self, text):
        """Count the number of tokens in a text string."""
        if isinstance(text, str):
            return len(self.encoder.encode(text))
        elif isinstance(text, dict):
            # For message dictionaries
            return self.count_tokens(json.dumps(text))
        elif isinstance(text, list):
            # For lists of messages
            return sum(self.count_tokens(message) for message in text)
        return 0

    def truncate_messages_history(self, messages, max_tokens):
        """Truncate message history to fit within token limits."""
        # Always keep the system message and the latest user message
        if len(messages) <= 2:
            return messages
            
        # Start with the most recent messages (keeping the system message at index 0)
        system_message = messages[0]
        recent_messages = [messages[-1]]  # Latest user message
        token_count = self.count_tokens(system_message) + self.count_tokens(recent_messages[0])
        
        # Add messages from newest to oldest until we approach the limit
        for message in reversed(messages[1:-1]):
            message_tokens = self.count_tokens(message)
            if token_count + message_tokens < max_tokens:
                recent_messages.insert(0, message)
                token_count += message_tokens
            else:
                break
                
        # Reconstruct the messages with system message first
        return [system_message] + recent_messages

    def generate_message(self, messages, max_tokens):
        """Generate a message using Anthropic API. Implements rate limiting."""
        # Initialize rate limiter if it doesn't exist
        if not hasattr(self, 'rate_limiter'):
            self.rate_limiter = RateLimiter()
        
        # Check if the total context exceeds limits
        total_tokens = self.count_tokens(messages)
        
        # Track input tokens for this call
        input_tokens = total_tokens
        self.current_conversation_input_tokens += input_tokens
        self.total_input_tokens += input_tokens
        
        if total_tokens > MAX_TOTAL_TOKENS - max_tokens:
            # Truncate history to fit within limits
            messages = self.truncate_messages_history(messages, MAX_TOTAL_TOKENS - max_tokens)
            # Recalculate tokens after truncation
            new_total_tokens = self.count_tokens(messages)
            
            # Adjust token counts
            token_reduction = total_tokens - new_total_tokens
            self.current_conversation_input_tokens -= token_reduction
            self.total_input_tokens -= token_reduction
            
            total_tokens = new_total_tokens
        
        # Estimate output tokens (about 75% of their max_tokens allocation)
        # More conservative estimate = safer rate limiting
        estimated_output_tokens = int(max_tokens * 0.75)
        
        # Get required delay from rate limiter
        required_delay = self.rate_limiter.get_required_delay(total_tokens, estimated_output_tokens)
        
        # Apply delay if needed (either from rate limits or minimum delay)
        if required_delay > 0:
            time.sleep(required_delay)
        else:
            # Ensure minimum delay between consecutive calls
            time_since_last_call = time.time() - self.last_api_call_time
            if time_since_last_call < MIN_DELAY_BETWEEN_CALLS and self.last_api_call_time > 0:
                minimum_delay = MIN_DELAY_BETWEEN_CALLS - time_since_last_call
                time.sleep(minimum_delay)
                print(f"Enforcing minimum delay: {minimum_delay:.2f}s between API calls")

        # Update last API call time before making the call
        self.last_api_call_time = time.time()
        
        # Retry parameters
        max_retries = 5
        base_delay = 2  # Base delay in seconds
        
        for attempt in range(max_retries):
            try:
                call_start_time = time.time()
                
                # Make the API call
                response = self.anthropic.messages.create(
                    model="claude-3-7-sonnet-20250219",
                    system=[
                        {
                            "type": "text",
                            "text": IDENTITY,
                            "cache_control": {"type": "ephemeral"}
                        }
                    ],
                    max_tokens=max_tokens,
                    messages=messages,
                    tools=tools,
                )
                
                # Count tokens in the actual response
                actual_output_tokens = self.count_tokens_in_response(response)
                
                # Track output tokens for this call
                self.current_conversation_output_tokens += actual_output_tokens
                self.total_output_tokens += actual_output_tokens
                
                # Record usage for rate limiting
                self.rate_limiter.record_usage(total_tokens, actual_output_tokens, call_start_time)
                
                return response
                
            except Exception as e:
                error_str = str(e)
                
                # Check if it's a rate limit error
                if "rate_limit_error" in error_str or "429" in error_str:
                    # If this is the last retry, fail
                    if attempt == max_retries - 1:
                        return {"error": f"Rate limit exceeded after {max_retries} attempts. Please try again later."}
                    
                    # Calculate backoff delay with jitter (randomness)
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                    print(f"Rate limit hit. Retrying in {delay:.2f} seconds (attempt {attempt+1}/{max_retries})...")
                    time.sleep(delay)
                    
                    # After a rate limit, update our internal tracking to be more cautious
                    if hasattr(self, 'rate_limiter'):
                        # Record a more moderate artificial usage to ensure we back off appropriately
                        # Use portion of the actual request
                        now = time.time()
                        cautious_input_tokens = int(total_tokens * 0.5)  # 50% of the actual input tokens
                        cautious_output_tokens = int(estimated_output_tokens * 0.5)  # 50% of estimated output
                        self.rate_limiter.record_usage(
                            cautious_input_tokens,
                            cautious_output_tokens,
                            now - 1  # Very recent timestamp
                        )
                else:
                    # For non-rate-limit errors, don't retry
                    return {"error": error_str}
    
    def process_user_input(self, user_input):
        """
        Process user input, manage tool calls, and maintain a valid conversation structure.
        """        
        # Create main user message
        self.session_state.messages.append({"role": "user", "content": user_input})
        
        try:
            # Initial model response
            response_message = self.generate_message(
                messages=self.session_state.messages,
                max_tokens=MAX_MODEL_TOKENS,
            )
            
            if "error" in response_message:
                return f"An error occurred: {response_message['error']}"
            
            # Keep processing tool calls until there are none left
            current_message = response_message
            
            while any(content.type == "tool_use" for content in current_message.content):
                # Get all tool calls in this message
                tool_calls = [content for content in current_message.content if content.type == "tool_use"]
                print(f"Tool call: {tool_calls}")
                text_content = [content for content in current_message.content if content.type == "text"]
                
                # Convert message content to serializable format before adding to history
                serializable_content = []
                for content_block in current_message.content:
                    if content_block.type == "text":
                        serializable_content.append({"type": "text", "text": content_block.text})
                    elif content_block.type == "tool_use":
                        serializable_content.append({
                            "type": "tool_use", 
                            "id": content_block.id,
                            "name": content_block.name,
                            "input": content_block.input
                        })
                
                # Add the serialized message to the conversation history
                self.session_state.messages.append(
                    {"role": "assistant", "content": serializable_content}
                )
                
                # Process each tool call
                tool_results = []
                for tool_use in tool_calls:
                    func_name = tool_use.name
                    func_params = tool_use.input
                    tool_use_id = tool_use.id
                    
                    # Return result, even if the tool execution fails
                    result = self.handle_tool_use(func_name, func_params)
                    
                    # Check if tool response is too large
                    result_tokens = self.count_tokens(str(result))
                    if result_tokens > MAX_TOOL_RESPONSE_TOKENS:
                        # Truncate or provide a summary message
                        result_content = f"Tool response exceeded token limit ({result_tokens} tokens). The complete results can be viewed externally but cannot be fully processed by the Attack Agent. Here's a summary or partial result: {str(result)[:500]}..."
                    else:
                        result_content = str(result)
                    
                    # Add tool_result for each tool_use, even if execution failed
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result_content,
                    })
                
                # Add tool results to the conversation
                self.session_state.messages.append({
                    "role": "user",
                    "content": tool_results,
                })
                
                try:
                    # Get the next response from the model
                    current_message = self.generate_message(
                        messages=self.session_state.messages,
                        max_tokens=MAX_MODEL_TOKENS,
                    )
                    
                    if "error" in current_message:
                        return f"An error occurred: {current_message['error']}"
                except Exception as e:
                    # If there's an error getting the next message, add error message
                    # to ensure the conversation state remains valid
                    error_message = f"Error generating response: {str(e)}"
                    self.session_state.messages.append({
                        "role": "assistant", 
                        "content": [{"type": "text", "text": error_message}]
                    })
                    return error_message
            
            # If message with no tool calls
            # Extract response text
            response_text = ''.join([content.text for content in current_message.content if content.type == "text"])
            
            # Convert final message content to serializable format
            serializable_content = []
            for content_block in current_message.content:
                if content_block.type == "text":
                    serializable_content.append({"type": "text", "text": content_block.text})
                elif content_block.type == "tool_use":
                    serializable_content.append({
                        "type": "tool_use", 
                        "id": content_block.id,
                        "name": content_block.name,
                        "input": content_block.input
                    })
            
            # Add the serialized message to the conversation history
            self.session_state.messages.append(
                {"role": "assistant", "content": serializable_content}
            )
            
            return response_text
            
        except Exception as e:
            # Catch any unexpected errors during processing
            error_message = f"An unexpected error occurred: {str(e)}"
            # Add the error as an assistant message to ensure conversation validity
            self.session_state.messages.append({
                "role": "assistant", 
                "content": [{"type": "text", "text": error_message}]
            })
            return error_message
   
    def handle_tool_use(self, tool_name, tool_input):
        """
        Execute a tool call and handle any exceptions.
        Returns a result string even if the tool execution fails.
        """
        try:
            if tool_name in tool_functions:
                return tool_functions[tool_name](**tool_input)
            else:
                return f"Error: Tool '{tool_name}' not found"
        except Exception as e:
            # Return a structured error message
            return f"Error executing tool '{tool_name}': {str(e)}"
    
    def count_tokens_in_response(self, response):
        """Count tokens in the API response content."""
        total_tokens = 0
        for content_block in response.content:
            if content_block.type == "text":
                total_tokens += self.count_tokens(content_block.text)
            elif content_block.type == "tool_use":
                # Count tokens in the tool use block
                total_tokens += self.count_tokens(json.dumps(content_block.input))
        return total_tokens