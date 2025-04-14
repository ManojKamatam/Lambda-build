import anthropic
import boto3
import json
import time
import os
import re
from typing import Dict, List, Any, Optional

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
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "inputText": text
                    })
                )
                
                response_body = json.loads(response['body'].read().decode())
                embedding = response_body['embedding']
                embeddings.append(embedding)
            except Exception as e:
                print(f"Error getting embedding: {str(e)}")
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
        
        problem_text = f"""
        PROBLEM INFORMATION:
        Title: {problem_info.get('title', 'N/A')}
        Severity: {problem_info.get('severity', 'N/A')}
        Impact: {problem_info.get('impact', 'N/A')}
        Description: {problem_info.get('description', 'N/A')}
        
        SOURCE CODE FILES:
        {files_content}
        """
        
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
    
    def analyze_problem_with_tools(self, problem_info: Dict[str, Any], files: Dict[str, str], 
                                  apm_service=None, max_retries: int = 3, 
                                  retry_delay: int = 2) -> Dict[str, Any]:
        """
        Analyze a problem using Claude with tool support for APM data
        """
        # Define tools for AI to use for getting more info if needed
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
        
        system_prompt = """
        You are a senior DevOps engineer tasked with analyzing and responding to system alerts.
        Based on the problem information and code files provided, determine the appropriate action:
        
        1. If this is a clear code issue that can be fixed directly, respond with ACTION: fix_code
        2. If this requires a new feature or complex change, respond with ACTION: create_ticket
        3. If you need more information to proceed, respond with ACTION: needs_more_info
        
        You have access to tools that can help you gather more information if needed.
        Use these tools to get additional logs or metrics ONLY if it would significantly help your analysis.
        
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
        
        problem_text = f"""
        PROBLEM INFORMATION:
        Title: {problem_info.get('title', 'N/A')}
        Severity: {problem_info.get('severity', 'N/A')}
        Impact: {problem_info.get('impact', 'N/A')}
        Description: {problem_info.get('description', 'N/A')}
        
        SOURCE CODE FILES:
        {files_content}
        """
        
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
                
                # Process tool calls if any
                tool_calls = []
                for content in message.content:
                    if content.type == 'tool_use':
                        tool_calls.append({
                            'name': content.tool_use.name,
                            'parameters': content.tool_use.input
                        })
                
                # Handle tool calls if needed
                if tool_calls and apm_service:
                    tool_responses = []
                    
                    for tool_call in tool_calls:
                        tool_name = tool_call['name']
                        params = tool_call['parameters']
                        
                        if tool_name == 'get_additional_logs':
                            logs = apm_service.get_logs(
                                service_name=params.get('service_name'),
                                time_range=params.get('time_range'),
                                log_level=params.get('log_level', 'ERROR')
                            )
                            tool_responses.append({
                                'role': 'tool',
                                'tool_use_id': tool_call['name'],
                                'content': json.dumps(logs)
                            })
                            
                        elif tool_name == 'get_service_metrics':
                            metrics = apm_service.get_metrics(
                                service_name=params.get('service_name'),
                                metric_type=params.get('metric_type'),
                                time_range=params.get('time_range')
                            )
                            tool_responses.append({
                                'role': 'tool',
                                'tool_use_id': tool_call['name'],
                                'content': json.dumps(metrics)
                            })
                    
                    # Continue the conversation with tool responses
                    if tool_responses:
                        follow_up = self.client.messages.create(
                            model="claude-3-opus-20240229",
                            system=system_prompt,
                            max_tokens=4000,
                            tools=tools,
                            messages=[
                                {"role": "user", "content": problem_text},
                                *tool_responses,
                                {"role": "user", "content": "Now that you have the additional information, please provide your final analysis and recommendation."}
                            ]
                        )
                        
                        response_text = follow_up.content[0].text
                    else:
                        response_text = message.content[0].text
                else:
                    response_text = message.content[0].text
                
                # Extract JSON from the response
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    decision = json.loads(json_match.group(1))
                    return decision
                else:
                    # If no JSON found, try to parse the whole response (same as regular analyze_problem)
                    try:
                        json_like = re.search(r'({.*})', response_text.replace('\n', ' '), re.DOTALL)
                        if json_like:
                            return json.loads(json_like.group(1))
                        else:
                            if "ACTION: fix_code" in response_text:
                                return {"action": "fix_code", "explanation": response_text}
                            elif "ACTION: create_ticket" in response_text:
                                return {"action": "create_ticket", "explanation": response_text}
                            else:
                                return {"action": "needs_more_info", "explanation": response_text}
                    except json.JSONDecodeError:
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