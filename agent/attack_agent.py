from anthropic import Anthropic
from .tools import *
from dotenv import load_dotenv
import json
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
    "get_technique_execution_response": get_technique_execution_response,
    "get_app_info": get_app_info
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
        self.session_state = session_state
        self.last_api_call_time = 0  # Track last API call time for rate limiting
        
        # Add token tracking variables
        self.current_conversation_input_tokens = 0
        self.current_conversation_output_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0

        # Client & api key variables
        self._anthropic_client = None
        self._last_api_key = None

    @property
    def anthropic(self):
        """Lazy initialization of Anthropic client that updates when API key changes"""
        load_dotenv()
        current_api_key = os.environ.get('ANTHROPIC_API_KEY')
        
        # If no client yet or the API key has changed -> create a new one
        if (self._anthropic_client is None or 
            current_api_key != self._last_api_key):
            
            if current_api_key:
                try:
                    self._anthropic_client = Anthropic()
                    self._last_api_key = current_api_key
                except Exception as e:
                    print(f"Failed to initialize Anthropic client: {e}")
                    self._anthropic_client = None
            else:
                self._anthropic_client = None
                
        return self._anthropic_client
    
    def is_anthropic_ready(self):
        """Check if Anthropic client is ready to use"""
        return self.anthropic is not None

    def count_tokens_for_messages(self, messages, include_system=True):
        """
        Count tokens for a complete message array using Anthropic's native counting.
        This includes both conversation messages and system message if specified.
        """
        if not self.is_anthropic_ready():
            # Fallback estimation if client not ready
            return self._estimate_tokens_fallback(messages, include_system)
        
        try:
            # Prepare messages for token counting
            messages_for_counting = []
            
            # Add conversation messages
            for msg in messages:
                if isinstance(msg, dict) and "role" in msg and "content" in msg:
                    messages_for_counting.append(msg)
                else:
                    # Convert non-standard message format
                    messages_for_counting.append({
                        "role": "user", 
                        "content": json.dumps(msg) if not isinstance(msg, str) else str(msg)
                    })
            
            # Count tokens using Anthropic's native method
            if include_system:
                # Include system message in counting
                count_result = self.anthropic.messages.count_tokens(
                    model="claude-3-7-sonnet-20250219",
                    messages=messages_for_counting,
                    system=IDENTITY
                )
            else:
                # Count only conversation messages
                count_result = self.anthropic.messages.count_tokens(
                    model="claude-3-7-sonnet-20250219",
                    messages=messages_for_counting
                )
            
            return count_result.input_tokens
            
        except Exception as e:
            print(f"Token counting error: {e}")
            return self._estimate_tokens_fallback(messages, include_system)

    def count_tokens_for_content(self, content):
        """
        Count tokens for arbitrary content by converting to message format.
        Used for tool responses, strings, etc.
        """
        if not self.is_anthropic_ready():
            # Fallback estimation
            if isinstance(content, str):
                return len(content) // 4
            else:
                return len(str(content)) // 4
        
        try:
            # Convert content to message format
            if isinstance(content, str):
                messages = [{"role": "user", "content": content}]
            else:
                messages = [{"role": "user", "content": str(content)}]
            
            # Count tokens without system message (since this is just content)
            count_result = self.anthropic.messages.count_tokens(
                model="claude-3-7-sonnet-20250219",
                messages=messages
            )
            
            return count_result.input_tokens
            
        except Exception as e:
            print(f"Content token counting error: {e}")
            # Fallback estimation
            if isinstance(content, str):
                return len(content) // 4
            else:
                return len(str(content)) // 4

    def _estimate_tokens_fallback(self, content, include_system=False):
        """Fallback token estimation when native counting is unavailable."""
        total_chars = 0
        
        if include_system:
            total_chars += len(IDENTITY)
        
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    total_chars += len(json.dumps(item))
                else:
                    total_chars += len(str(item))
        elif isinstance(content, dict):
            total_chars += len(json.dumps(content))
        else:
            total_chars += len(str(content))
        
        # Rough estimation: ~4 characters per token
        return total_chars // 4

    def truncate_messages_history(self, messages, max_tokens):
        """Truncate message history to fit within token limits."""
        # Always keep at least the latest user message
        if len(messages) <= 1:
            return messages
        
        # Start with the most recent message
        recent_messages = [messages[-1]]
        
        # Calculate initial token count (including system message)
        token_count = self.count_tokens_for_messages(recent_messages, include_system=True)
        
        # Add messages from newest to oldest until we approach the limit
        for message in reversed(messages[:-1]):
            # Calculate tokens for this message
            temp_messages = [message] + recent_messages
            temp_token_count = self.count_tokens_for_messages(temp_messages, include_system=True)
            
            if temp_token_count < max_tokens:
                recent_messages.insert(0, message)
                token_count = temp_token_count
            else:
                break
        
        return recent_messages

    def generate_message(self, messages, max_tokens):
        """Generate a message using Anthropic API. Implements rate limiting."""
        # Initialize rate limiter if it doesn't exist
        if not hasattr(self, 'rate_limiter'):
            self.rate_limiter = RateLimiter()
        
        # Count total tokens including system message
        total_tokens = self.count_tokens_for_messages(messages, include_system=True)
        
        # Track input tokens for this call
        input_tokens = total_tokens
        self.current_conversation_input_tokens += input_tokens
        self.total_input_tokens += input_tokens
        
        if total_tokens > MAX_TOTAL_TOKENS - max_tokens:
            # Truncate history to fit within limits
            messages = self.truncate_messages_history(messages, MAX_TOTAL_TOKENS - max_tokens)
            # Recalculate tokens after truncation
            new_total_tokens = self.count_tokens_for_messages(messages, include_system=True)
            
            # Adjust token counts
            token_reduction = total_tokens - new_total_tokens
            self.current_conversation_input_tokens -= token_reduction
            self.total_input_tokens -= token_reduction
            
            total_tokens = new_total_tokens
        
        # Estimate output tokens (about 75% of their max_tokens allocation)
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
                        now = time.time()
                        cautious_input_tokens = int(total_tokens * 0.5)
                        cautious_output_tokens = int(estimated_output_tokens * 0.5)
                        self.rate_limiter.record_usage(
                            cautious_input_tokens,
                            cautious_output_tokens,
                            now - 1
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
                    
                    # Execute tool and get result
                    result = self.handle_tool_use(func_name, func_params)
                    
                    # Check if tool response is too large using content token counting
                    result_tokens = self.count_tokens_for_content(str(result))
                    if result_tokens > MAX_TOOL_RESPONSE_TOKENS:
                        # Truncate response with clear explanation
                        result_content = f"Tool response exceeded token limit ({result_tokens} tokens). The complete results can be viewed externally but cannot be fully processed by the Attack Agent. Here's a summary or partial result: {str(result)[:500]}..."
                    else:
                        result_content = str(result)
                    
                    # Add tool_result for each tool_use
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
                    error_message = f"Error generating response: {str(e)}"
                    self.session_state.messages.append({
                        "role": "assistant", 
                        "content": [{"type": "text", "text": error_message}]
                    })
                    return error_message
            
            # Extract response text from final message
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
            
            # Add the final message to conversation history
            self.session_state.messages.append(
                {"role": "assistant", "content": serializable_content}
            )
            
            return response_text
            
        except Exception as e:
            # Catch any unexpected errors during processing
            error_message = f"An unexpected error occurred: {str(e)}"
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
        try:
            # Extract all text content from response
            content_parts = []
            for content_block in response.content:
                if content_block.type == "text":
                    content_parts.append(content_block.text)
                elif content_block.type == "tool_use":
                    # Include tool use information in token count
                    content_parts.append(json.dumps({
                        "name": content_block.name,
                        "input": content_block.input
                    }))
            
            # Combine all content and count tokens
            combined_content = "\n".join(content_parts)
            return self.count_tokens_for_content(combined_content)
            
        except Exception as e:
            print(f"Error counting response tokens: {e}")
            # Fallback estimation
            total_chars = 0
            for content_block in response.content:
                if content_block.type == "text":
                    total_chars += len(content_block.text)
                elif content_block.type == "tool_use":
                    total_chars += len(json.dumps(content_block.input))
            return total_chars // 4