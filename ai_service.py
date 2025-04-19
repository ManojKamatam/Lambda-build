import anthropic
import boto3
import json
import time
import os
import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger()

class AIService:
    def __init__(self, anthropic_api_key=None):
        self.anthropic_api_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.client = anthropic.Anthropic(api_key=self.anthropic_api_key)
        self.bedrock = boto3.client('bedrock-runtime')
        self.model_id = os.environ.get("BEDROCK_MODEL_ID", "amazon.titan-embed-text-v1")
    
    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Get embeddings from Amazon Bedrock"""
        embeddings = []
        
        for text in texts:
            try:
                # Limit text length for token limits
                if len(text) > 8000:
                    text = text[:8000]
                    
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "inputText": text
                    })
                )
                
                # Handle response based on type
                if hasattr(response['body'], 'read'):
                    body = json.loads(response['body'].read().decode())
                else:
                    body = json.loads(response['body']) if isinstance(response['body'], str) else response['body']
                    
                # Validate we got an embedding
                if 'embedding' not in body:
                    logger.error("No embedding in Bedrock response")
                    embeddings.append([0.0] * 1536)  # Default embedding size
                    continue
                    
                embedding = body['embedding']
                embeddings.append(embedding)
            except Exception as e:
                logger.error(f"Error getting embedding: {str(e)}")
                # Return zeros as fallback
                embeddings.append([0.0] * 1536)  # Default embedding size
        
        return embeddings
    
    def analyze_problem(self, problem_info: Dict[str, Any], files: Dict[str, str], 
                        max_retries: int = 3, retry_delay: int = 2) -> Dict[str, Any]:
        """
        Analyze a problem using Claude Opus and decide on next steps
        """
        system_prompt = """
        You are a senior DevOps engineer tasked with analyzing and responding to system alerts.
        Based on the problem information and code files provided, determine the appropriate action:
        
        1. If this is a clear code issue that can be fixed directly, respond with ACTION: fix_code
        2. If this requires a new feature or complex change, respond with ACTION: create_ticket
        3. If you need more information to proceed, respond with ACTION: needs_more_info
        
        For fix_code actions, include:
        - A brief explanation of the issue
        - The specific files that need changes
        - What those changes should be
        
        For create_ticket actions, include:
        - A suggested ticket title
        - A detailed description of the issue
        - Recommended priority (High/Medium/Low)
        - Any suggested labels or components
        
        For needs_more_info actions, specify exactly what additional information you need.
        
        Present your final decision in a JSON format at the end of your response, like:
        ```json
        {
          "action": "fix_code|create_ticket|needs_more_info", 
          "explanation": "Brief explanation of decision",
          "details": {...action-specific details...}
        }
        ```
        """
        
        # Create a comprehensive prompt with all relevant information
        files_content = "\n\n".join([f"--- {filename} ---\n{content}" for filename, content in files.items()])
        
        problem_text = self._create_problem_text(problem_info, files)
        
        # Use Claude Opus for analysis
        for attempt in range(max_retries):
            try:
                message = self.client.messages.create(
                    model="claude-3-opus-20240229",
                    system=system_prompt,
                    max_tokens=4000,
                    messages=[
                        {"role": "user", "content": problem_text}
                    ]
                )
                
                response_text = message.content[0].text
                
                # Extract JSON from the response
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    decision = json.loads(json_match.group(1))
                    return decision
                else:
                    # If no JSON found, try to parse the whole response
                    try:
                        # Look for a JSON-like structure in the text
                        json_like = re.search(r'({.*})', response_text.replace('\n', ' '), re.DOTALL)
                        if json_like:
                            return json.loads(json_like.group(1))
                        else:
                            # Create a basic structure based on keywords
                            if "ACTION: fix_code" in response_text:
                                return {"action": "fix_code", "explanation": response_text}
                            elif "ACTION: create_ticket" in response_text:
                                return {"action": "create_ticket", "explanation": response_text}
                            else:
                                return {"action": "needs_more_info", "explanation": response_text}
                    except json.JSONDecodeError:
                        # Last resort: infer from text
                        if "fix" in response_text.lower() and "code" in response_text.lower():
                            return {"action": "fix_code", "explanation": response_text}
                        elif "ticket" in response_text.lower() or "issue" in response_text.lower():
                            return {"action": "create_ticket", "explanation": response_text}
                        else:
                            return {"action": "needs_more_info", "explanation": response_text}
                
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise e
        
        return {"action": "needs_more_info", "explanation": "Failed to analyze the problem after multiple attempts."}
    
    def _create_problem_text(self, problem_info, files):
        """Create a formatted problem text for AI analysis"""
        files_content = "\n\n".join([f"--- {filename} ---\n{content}" for filename, content in files.items()])
        
        # Use plain_description if available
        description = problem_info.get('plain_description', problem_info.get('description', 'N/A'))
        
        # Include components if available
        components_text = ""
        if 'components' in problem_info and problem_info['components']:
            components_text = f"\nCOMPONENTS:\n{', '.join(problem_info['components'])}"
        
        return f"""
        PROBLEM INFORMATION:
        Title: {problem_info.get('title', 'N/A')}
        Severity: {problem_info.get('severity', 'N/A')}
        Impact: {problem_info.get('impact', 'N/A')}
        Description: {description}
        
        IMPACTED SERVICES:
        {', '.join(problem_info.get('service_names', ['Unknown']))}{components_text}
        
        SOURCE CODE FILES:
        {files_content}
        """
    
    def analyze_problem_with_tools(self, problem_info: Dict[str, Any], files: Dict[str, str], 
                              apm_service=None, max_retries: int = 3, 
                              retry_delay: int = 2) -> Dict[str, Any]:
        """
        Analyze a problem using Claude with tool support for APM data
        """
        # Tools for AI to use for getting more info if needed
        tools = [
            {
                "name": "get_additional_logs",
                "description": "Get additional logs from the APM system",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "service_name": {
                            "type": "string",
                            "description": "Service name to get logs for"
                        },
                        "time_range": {
                            "type": "string",
                            "description": "Time range for logs (e.g., '1h', '24h')"
                        },
                        "log_level": {
                            "type": "string",
                            "enum": ["DEBUG", "INFO", "WARN", "ERROR"],
                            "default": "ERROR"
                        }
                    },
                    "required": ["service_name"]
                }
            },
            {
                "name": "get_service_metrics",
                "description": "Get performance metrics for a service",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "service_name": {
                            "type": "string",
                            "description": "Service name to get metrics for"
                        },
                        "metric_type": {
                            "type": "string",
                            "enum": ["cpu", "memory", "latency", "error_rate", "throughput"],
                            "description": "Type of metric to retrieve"
                        },
                        "time_range": {
                            "type": "string",
                            "description": "Time period for metrics (e.g., '1h', '24h')"
                        }
                    },
                    "required": ["service_name", "metric_type"]
                }
            }
        ]
        
        # Enhanced system prompt to strongly encourage tool usage
        system_prompt = """
        You are a senior DevOps engineer tasked with analyzing and responding to system alerts.

        IMPORTANT INSTRUCTIONS:
        1. For Flask application errors, ALWAYS use the available tools to get more information:
          - Use get_additional_logs with the impacted service name to get error logs
          - Use get_service_metrics with metric_type="error_rate" to get error metrics

        2. Only after using these tools should you decide on an action:
          - For clear code issues with a simple fix: ACTION: fix_code
          - For complex changes or new features: ACTION: create_ticket
          - Only if tools don't provide enough context: ACTION: needs_more_info

        Bare exception blocks, insecure configs, and inefficient SQL queries are common issues
        that should be fixed directly when possible.

        Your response must include a JSON decision at the end with your action and explanation.
        
        Present your final decision in a JSON format at the end of your response, like:
        ```json
        {
          "action": "fix_code|create_ticket|needs_more_info", 
          "explanation": "Brief explanation of decision",
          "details": {...action-specific details...}
        }
        ```
        """
        
        # Create problem text
        problem_text = self._create_problem_text(problem_info, files)
        
        # Use Claude with tools enabled
        for attempt in range(max_retries):
            try:
                message = self.client.messages.create(
                    model="claude-3-opus-20240229",
                    system=system_prompt,
                    max_tokens=4000,
                    tools=tools,
                    messages=[
                        {"role": "user", "content": problem_text}
                    ]
                )
                
                # Extract tool calls
                tool_calls = []
                for content in message.content:
                    if content.type == 'tool_use':
                        tool_calls.append({
                            'name': content.name,  # Changed from content.tool_use.name
                            'parameters': content.input,  # Changed from content.tool_use.input
                            'tool_use_id': content.id  # Changed from content.tool_use.id
                        })
                
                # Log tool call information
                if tool_calls:
                    logger.info(f"AI requested {len(tool_calls)} tools during initial analysis")
                    for call in tool_calls:
                        logger.info(f"Tool requested: {call['name']} for service: {call['parameters'].get('service_name')}")
                
                # If no tool calls but the response indicates needs_more_info, add tool_calls property
                response_text = message.content[0].text if message.content and message.content[0].type == 'text' else ""
                
                if not tool_calls and ("needs_more_info" in response_text.lower() or "need more information" in response_text.lower()):
                    logger.info("AI indicated it needs more info but didn't use tools - may need to force tool usage")
                
                # Extract decision from response
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    decision = json.loads(json_match.group(1))
                    # Include tool_calls in the response for the Lambda handler
                    if tool_calls:
                        decision['tool_calls'] = tool_calls
                    return decision
                else:
                    # Parse response as in analyze_problem
                    result = self._parse_response(response_text)
                    if tool_calls:
                        result['tool_calls'] = tool_calls
                    return result
                
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Error in analyze_problem_with_tools: {str(e)}")
                    return {"action": "needs_more_info", "explanation": f"Error during analysis: {str(e)}"}
        
        return {"action": "needs_more_info", "explanation": "Failed to analyze the problem after multiple attempts."}

    def analyze_with_tool_results(self, problem_info, files, tool_results):
        """
        Analyze the problem with tool results using a proper follow-up message
        structure that avoids the "Unexpected role" error.
        """
        try:
            # Format tool results as user-friendly text
            tool_results_text = ""
            for result in tool_results:
                tool_name = result.get('tool_name', 'unknown')
                params = result.get('parameters', {})
                result_data = result.get('result', 'No data')
                
                # Format the data nicely
                tool_results_text += f"\n\n--- {tool_name.upper()} RESULTS ---\n"
                tool_results_text += f"Parameters: {json.dumps(params)}\n\n"
                
                # Format result data based on type
                if isinstance(result_data, (dict, list)):
                    try:
                        formatted_data = json.dumps(result_data, indent=2)
                        # Truncate if too long
                        if len(formatted_data) > 1000:
                            formatted_data = formatted_data[:1000] + "...[truncated]"
                        tool_results_text += formatted_data
                    except:
                        tool_results_text += str(result_data)[:1000]
                else:
                    tool_results_text += str(result_data)[:1000]
            
            # Create updated problem text with the tool results included
            files_content = "\n\n".join([f"--- {filename} ---\n{content}" for filename, content in files.items()])
            
            # Create a new prompt with all information
            updated_prompt = f"""
            PROBLEM INFORMATION:
            Title: {problem_info.get('title', 'N/A')}
            Severity: {problem_info.get('severity', 'N/A')}
            Impact: {problem_info.get('impact', 'N/A')}
            Description: {problem_info.get('plain_description', problem_info.get('description', 'N/A'))}
            
            IMPACTED SERVICES:
            {', '.join(problem_info.get('service_names', ['Unknown']))}
            
            TOOL RESULTS FROM APM SYSTEM:
            {tool_results_text}
            
            SOURCE CODE FILES:
            {files_content}
            
            Based on ALL this information (problem details, APM data, and code files), 
            please provide your final analysis and recommendation.
            """
            
            # System prompt for final analysis
            system_prompt = """
            You are a senior DevOps engineer analyzing system alerts with additional APM data.
            
            Based on ALL the information (problem details, code files, and APM data), determine the appropriate action:
            
            1. If this is a clear code issue that can be fixed directly, respond with ACTION: fix_code
            2. If this requires a new feature or complex change, respond with ACTION: create_ticket
            3. If you still need more information, respond with ACTION: needs_more_info
            
            Present your final decision in a JSON format at the end of your response, like:
            ```json
            {
              "action": "fix_code|create_ticket|needs_more_info", 
              "explanation": "Brief explanation of decision",
              "details": {...action-specific details...}
            }
            ```
            """
            
            # Make the API call
            message = self.client.messages.create(
                model="claude-3-opus-20240229",
                system=system_prompt,
                max_tokens=4000,
                messages=[
                    {"role": "user", "content": updated_prompt}
                ]
            )
            
            response_text = message.content[0].text
            
            # Extract JSON using same logic as analyze_problem
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(1))
                # Add tool results to decision for later use
                decision['tool_results'] = tool_results
                return decision
            else:
                # Use parse_response helper
                result = self._parse_response(response_text)
                result['tool_results'] = tool_results
                return result
                
        except Exception as e:
            logger.error(f"Error in follow-up analysis: {str(e)}")
            return {
                "action": "needs_more_info", 
                "explanation": f"Error during analysis with APM data: {str(e)}",
                "tool_results": tool_results
            }
    
    def _parse_response(self, response_text):
        """Parse Claude's response to extract decision"""
        try:
            # Look for a JSON-like structure in the text
            json_like = re.search(r'({.*})', response_text.replace('\n', ' '), re.DOTALL)
            if json_like:
                return json.loads(json_like.group(1))
            else:
                # Infer from text
                if "ACTION: fix_code" in response_text or ("fix" in response_text.lower() and "code" in response_text.lower()):
                    return {"action": "fix_code", "explanation": response_text}
                elif "ACTION: create_ticket" in response_text or ("ticket" in response_text.lower() and "create" in response_text.lower()):
                    return {"action": "create_ticket", "explanation": response_text}
                else:
                    return {"action": "needs_more_info", "explanation": response_text}
        except json.JSONDecodeError:
            # Last resort: infer from keywords
            if "fix" in response_text.lower() and "code" in response_text.lower():
                return {"action": "fix_code", "explanation": response_text}
            elif "ticket" in response_text.lower() or "issue" in response_text.lower():
                return {"action": "create_ticket", "explanation": response_text}
            else:
                return {"action": "needs_more_info", "explanation": response_text}
    
    def process_tool_calls(self, tool_calls, apm_service, problem_info, files=None):
        """Process tool calls and get APM data"""
        if not tool_calls or not apm_service:
            return None
            
        logger.info(f"Processing {len(tool_calls)} tool calls")
        tool_results = []
        
        for tool_call in tool_calls:
            try:
                # Extract tool information with safer access
                tool_name = tool_call.get('name', '')
                parameters = tool_call.get('parameters', {})
                
                # Handle string parameters (convert to dict if needed)
                if isinstance(parameters, str):
                    try:
                        parameters = json.loads(parameters)
                    except:
                        logger.error(f"Failed to parse parameters string: {parameters}")
                        parameters = {}
                        
                # Get service name directly (no .get on parameters if it's a string)
                service_name = parameters.get('service_name') if isinstance(parameters, dict) else ''
                
                logger.info(f"Processing tool: {tool_name} for service: {service_name}")
                
                # Execute the appropriate tool with explicit parameter extraction
                result = None
                if tool_name == 'get_additional_logs':
                    # Extract parameters safely
                    time_range = parameters.get('time_range', '1h') if isinstance(parameters, dict) else '1h'
                    log_level = parameters.get('log_level', 'ERROR') if isinstance(parameters, dict) else 'ERROR'
                    
                    # Call with explicit parameters rather than passing parameters dict
                    result = apm_service.get_logs(
                        service_name=service_name,
                        time_range=time_range,
                        log_level=log_level
                    )
                    
                elif tool_name == 'get_service_metrics':
                    # Extract parameters safely
                    metric_type = parameters.get('metric_type', 'error_rate') if isinstance(parameters, dict) else 'error_rate'
                    time_range = parameters.get('time_range', '1h') if isinstance(parameters, dict) else '1h'
                    
                    # Call with explicit parameters
                    result = apm_service.get_metrics(
                        service_name=service_name,
                        metric_type=metric_type,
                        time_range=time_range
                    )
                    
                # Record the result
                tool_results.append({
                    "tool_name": tool_name,
                    "result": result,
                    "parameters": parameters
                })
                    
            except Exception as e:
                logger.error(f"Tool execution error: {str(e)}")
                # Continue with next tool if one fails
        
        # Process the results
        if tool_results:
            return self.analyze_with_tool_results(problem_info, files or {}, tool_results)
        
        return None
    
    def generate_code_fix(self, problem_info: Dict[str, Any], files: Dict[str, str], 
                          analysis: Dict[str, Any], max_retries: int = 3, 
                          retry_delay: int = 2) -> Dict[str, str]:
        """
        Generate code fixes using Claude Sonnet
        """
        system_prompt = """
        You are a senior software engineer tasked with fixing code issues. 
        Your response should focus ONLY on the specific code changes needed to fix the problem.
        
        For each file that needs changes:
        1. Include the ENTIRE updated file content, not just the changes
        2. Keep all unchanged parts exactly the same
        3. Maintain consistent formatting, indentation, and style with the original code
        
        Format your response as follows for each modified file:
        
        FILENAME: [full path of file]
        ```
        [entire updated file content]
        ```
        
        If you update multiple files, separate them clearly.
        Do not include explanations unless absolutely necessary. Focus on providing clean, working code.
        """
        
        # Create a comprehensive prompt with all relevant information
        files_content = "\n\n".join([f"--- {filename} ---\n{content}" for filename, content in files.items()])
        
        problem_text = f"""
        PROBLEM INFORMATION:
        Title: {problem_info.get('title', 'N/A')}
        Description: {problem_info.get('description', 'N/A')}
        
        ANALYSIS:
        {analysis.get('explanation', 'No explanation provided')}
        
        SOURCE CODE FILES:
        {files_content}
        
        Please provide the updated file content for all files that need modifications to fix this issue.
        """
        
        # Use Claude Sonnet for code generation
        for attempt in range(max_retries):
            try:
                message = self.client.messages.create(
                    model="claude-3-sonnet-20240229",
                    system=system_prompt,
                    max_tokens=4000,
                    messages=[
                        {"role": "user", "content": problem_text}
                    ]
                )
                
                response_text = message.content[0].text
                
                # Extract updated files
                updated_files = {}
                
                # Match patterns like "FILENAME: path/to/file.py\n```\ncontent\n```"
                file_pattern = r'FILENAME:\s*([^\n]+)\s*```(?:[\w]*\n)?(.+?)```'
                matches = re.finditer(file_pattern, response_text, re.DOTALL)
                
                for match in matches:
                    filename = match.group(1).strip()
                    content = match.group(2).strip()
                    updated_files[filename] = content
                
                # If no matches found, try a different pattern (just code blocks with filenames before)
                if not updated_files:
                    alt_pattern = r'(?:^|\n)([^\n]+?)\s*```(?:[\w]*\n)?(.+?)```'
                    matches = re.finditer(alt_pattern, response_text, re.DOTALL)
                    
                    for match in matches:
                        potential_filename = match.group(1).strip()
                        # Check if this looks like a filename (contains certain characters)
                        if '.' in potential_filename and '/' in potential_filename:
                            content = match.group(2).strip()
                            updated_files[potential_filename] = content
                
                return updated_files
                
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise e
        
        return {}
    
    def create_ticket_details(self, problem_info: Dict[str, Any], analysis: Dict[str, Any],
                              max_retries: int = 3, retry_delay: int = 2) -> Dict[str, Any]:
        """
        Generate detailed ticket information using Claude Sonnet
        """
        system_prompt = """
        You are a technical support specialist creating detailed tickets for engineering issues.
        Based on the problem information and analysis, create a well-structured ticket with:

        1. A clear, concise title that summarizes the core issue
        2. A detailed description that includes:
           - Problem summary
           - Technical details
           - Impact on systems/users
           - Any known workarounds
           - Suggested investigation approach
        3. Appropriate priority level (Critical, High, Medium, Low)
        4. Recommended labels/tags for categorization
        5. Suggested assignee type (Frontend, Backend, DevOps, etc.)

        Return this information in JSON format like:
        ```json
        {
          "title": "Clear ticket title",
          "description": "Detailed description",
          "priority": "High/Medium/Low",
          "tags": ["tag1", "tag2"],
          "assignee_type": "DevOps"
        }
        ```
        """
        
        problem_text = f"""
        PROBLEM INFORMATION:
        Title: {problem_info.get('title', 'N/A')}
        Severity: {problem_info.get('severity', 'N/A')}
        Impact: {problem_info.get('impact', 'N/A')}
        Description: {problem_info.get('description', 'N/A')}
        
        ANALYSIS:
        {analysis.get('explanation', 'No explanation provided')}
        
        Please create a detailed ticket for this issue.
        """
        
        # Use Claude Sonnet for ticket creation
        for attempt in range(max_retries):
            try:
                message = self.client.messages.create(
                    model="claude-3-sonnet-20240229",
                    system=system_prompt,
                    max_tokens=2000,
                    messages=[
                        {"role": "user", "content": problem_text}
                    ]
                )
                
                response_text = message.content[0].text
                
                # Extract JSON from the response
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    ticket_info = json.loads(json_match.group(1))
                    return ticket_info
                else:
                    # If no JSON found, try to parse the whole response
                    try:
                        json_like = re.search(r'({.*})', response_text.replace('\n', ' '), re.DOTALL)
                        if json_like:
                            return json.loads(json_like.group(1))
                        else:
                            # Create a basic structure based on text
                            lines = response_text.split('\n')
                            title = next((line for line in lines if line.strip()), "Issue from alert")
                            return {
                                "title": title[:80],
                                "description": response_text,
                                "priority": "Medium",
                                "tags": ["auto-generated"]
                            }
                    except json.JSONDecodeError:
                        # Create a simple structure
                        return {
                            "title": problem_info.get('title', 'Issue from alert')[:80],
                            "description": response_text,
                            "priority": "Medium",
                            "tags": ["auto-generated"]
                        }
                
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise e
        
        return {
            "title": problem_info.get('title', 'Issue from alert'),
            "description": "Failed to generate detailed ticket information.",
            "priority": "Medium",
            "tags": ["auto-generated", "error"]
        }
