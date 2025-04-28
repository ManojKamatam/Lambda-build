import json
import os
import logging
import boto3
import datetime
import numpy as np
import re
from opensearch_service import OpenSearchService
from vcs_service import VCSService
from apm_service import APMService
from ai_service import AIService
from ticket_service import TicketService

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secrets = {}
try:
    # Get the secret name from environment variable
    secret_name = os.environ.get('SECRET_NAME')
    
    if secret_name:
        # Initialize AWS Secrets Manager client
        region_name = os.environ.get('AWS_REGION', 'us-east-1')
        secrets_client = boto3.client('secretsmanager', region_name=region_name)
        
        # Get the secret value
        logger.info(f"Loading secrets from {secret_name}")
        secret_response = secrets_client.get_secret_value(SecretId=secret_name)
        
        # Parse the secret value
        if 'SecretString' in secret_response:
            secret_string = secret_response['SecretString']
            
            # Check if the secret is a JSON string
            try:
                secrets = json.loads(secret_string)
                logger.info("Successfully loaded secrets from AWS Secrets Manager")
            except json.JSONDecodeError:
                # If not JSON, treat it as a single secret value
                logger.warning("Secret is not valid JSON, treating as a single secret value")
                secrets = {"SECRET_VALUE": secret_string}
        else:
            logger.warning("No SecretString found in the secrets response")
    else:
        logger.info("No SECRET_NAME environment variable found, using environment variables only")
except Exception as e:
    logger.error(f"Error loading secrets from AWS Secrets Manager: {str(e)}")
    logger.info("Proceeding with environment variables only")

def get_secret_param(param_name, default=None):
    """Get a parameter from secrets or environment with proper error handling"""
    try:
        # Try to get from secrets first
        if param_name in secrets:
            value = secrets.get(param_name)
            logger.info(f"Loaded {param_name} from Secrets Manager")
            return value
        # Fall back to environment variable
        elif param_name in os.environ:
            value = os.environ.get(param_name)
            logger.info(f"Loaded {param_name} from environment variables")
            return value
        else:
            logger.info(f"{param_name} not found in Secrets Manager or environment, using default")
            return default
    except Exception as e:
        logger.error(f"Error loading {param_name}: {str(e)}")
        return default

# Environment configuration - using get_secret_param for consistent loading
ANTHROPIC_API_KEY = get_secret_param("ANTHROPIC_API_KEY")
VCS_TYPE = get_secret_param("VCS_TYPE", os.environ.get("VCS_TYPE"))
VCS_TOKEN = get_secret_param("VCS_TOKEN")

# Safely load VCS_EXTRA_PARAMS
VCS_EXTRA_PARAMS = {}
try:
    vcs_extra_raw = get_secret_param("VCS_EXTRA_PARAMS")
    if vcs_extra_raw:
        if isinstance(vcs_extra_raw, dict):
            VCS_EXTRA_PARAMS = vcs_extra_raw
            logger.info("Loaded VCS_EXTRA_PARAMS as dictionary")
        else:
            # Try parsing as JSON string
            VCS_EXTRA_PARAMS = json.loads(vcs_extra_raw)
            logger.info("Loaded VCS_EXTRA_PARAMS as JSON string")
    elif "VCS_EXTRA_PARAMS" in os.environ:
        VCS_EXTRA_PARAMS = json.loads(os.environ.get("VCS_EXTRA_PARAMS", "{}"))
        logger.info("Loaded VCS_EXTRA_PARAMS from environment")
except Exception as e:
    logger.error(f"Error parsing VCS_EXTRA_PARAMS: {str(e)}, using empty dict")
    VCS_EXTRA_PARAMS = {}

OPENSEARCH_ENDPOINT = get_secret_param("OPENSEARCH_ENDPOINT")
ENABLE_APM_TOOLS = get_secret_param("ENABLE_APM_TOOLS", "true").lower() == "true"
APM_TYPE = get_secret_param("APM_TYPE")
APM_API_KEY = get_secret_param("APM_API_KEY")

# Safely load APM_EXTRA_PARAMS
APM_EXTRA_PARAMS = {}
try:
    apm_extra_raw = get_secret_param("APM_EXTRA_PARAMS")
    if apm_extra_raw:
        if isinstance(apm_extra_raw, dict):
            APM_EXTRA_PARAMS = apm_extra_raw
            logger.info("Loaded APM_EXTRA_PARAMS as dictionary")
        else:
            # Try parsing as JSON string
            APM_EXTRA_PARAMS = json.loads(apm_extra_raw)
            logger.info("Loaded APM_EXTRA_PARAMS as JSON string")
    elif "APM_EXTRA_PARAMS" in os.environ:
        APM_EXTRA_PARAMS = json.loads(os.environ.get("APM_EXTRA_PARAMS", "{}"))
        logger.info("Loaded APM_EXTRA_PARAMS from environment")
except Exception as e:
    logger.error(f"Error parsing APM_EXTRA_PARAMS: {str(e)}, using empty dict")
    APM_EXTRA_PARAMS = {}

TICKET_TYPE = get_secret_param("TICKET_TYPE")

# Safely load TICKET_PARAMS
TICKET_PARAMS = {}
try:
    ticket_params_raw = get_secret_param("TICKET_PARAMS")
    if ticket_params_raw:
        if isinstance(ticket_params_raw, dict):
            TICKET_PARAMS = ticket_params_raw
            logger.info("Loaded TICKET_PARAMS as dictionary")
        else:
            # Try parsing as JSON string
            TICKET_PARAMS = json.loads(ticket_params_raw)
            logger.info("Loaded TICKET_PARAMS as JSON string")
    elif "TICKET_PARAMS" in os.environ:
        TICKET_PARAMS = json.loads(os.environ.get("TICKET_PARAMS", "{}"))
        logger.info("Loaded TICKET_PARAMS from environment")
except Exception as e:
    logger.error(f"Error parsing TICKET_PARAMS: {str(e)}, using empty dict")
    TICKET_PARAMS = {}

NOTIFICATION_WEBHOOK = get_secret_param("NOTIFICATION_WEBHOOK")

def lambda_handler(event, context):
    """Main Lambda handler"""
    start_time = datetime.datetime.now()
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Initialize services
        logger.info("Initializing services")
        vcs_service = VCSService(
        vcs_type=VCS_TYPE, 
        token=VCS_TOKEN, 
        **VCS_EXTRA_PARAMS
        )
        ai_service = AIService(ANTHROPIC_API_KEY)
        opensearch_service = OpenSearchService(OPENSEARCH_ENDPOINT) if OPENSEARCH_ENDPOINT else None
        apm_service = APMService(
            apm_type=APM_TYPE, 
            api_key=APM_API_KEY, 
            **APM_EXTRA_PARAMS
        ) if ENABLE_APM_TOOLS else None
        
        logger.info(f"APM service initialized: {apm_service is not None}")
        
        ticket_service = TicketService(
            ticket_type=TICKET_TYPE,
            **TICKET_PARAMS
        )
        
        # Extract problem information with enhanced component extraction
        problem_info = extract_problem_info(event)
        logger.info(f"Extracted problem info: {json.dumps(problem_info)}")
        
        # Extract repo info
        repo_info = extract_repo_info(event)
        logger.info(f"Repository info: {json.dumps(repo_info)}")
        
        if not repo_info or not all([repo_info.get('owner'), repo_info.get('repo')]):
            return {
                'statusCode': 400,
                'body': json.dumps('Missing repository information')
            }
        
        # Detailed GitHub repository debugging
        repo = f"{repo_info['owner']}/{repo_info['repo']}"
        if vcs_service.vcs_type == "github":
            logger.info("--- Starting GitHub Repository Debug ---")
            
            # Check token permissions
            permissions = vcs_service.check_token_permissions()
            logger.info(f"Token permissions: {json.dumps(permissions)}")
            
            # Check rate limits
            rate_limit = vcs_service.check_rate_limit()
            logger.info(f"GitHub API rate limit status: {json.dumps(rate_limit)}")
            
            # Check if repository exists and is accessible
            logger.info(f"Verifying repository access for: {repo}")
            repo_exists = vcs_service.verify_repository_access(repo)
            logger.info(f"Repository exists and is accessible: {repo_exists}")
            
            if not repo_exists:
                return {
                    'statusCode': 404,
                    'body': json.dumps(f'Repository {repo} not found or not accessible')
                }
                
            # Get the default branch
            default_branch = vcs_service.get_default_branch(repo)
            logger.info(f"Repository default branch: {default_branch}")
            
            # Make sure we're using the correct branch
            branch_to_use = repo_info.get('default_branch', default_branch)
            logger.info(f"Using branch: {branch_to_use}")
            
            # Check if repository has content
            has_content = vcs_service.check_repository_content(repo, branch_to_use)
            logger.info(f"Repository has content: {has_content}")
            
            if not has_content:
                return {
                    'statusCode': 200,
                    'body': json.dumps(f'Repository {repo} exists but has no content')
                }
        
        # Get a list of repository files
        logger.info(f"Attempting to get files from repository: {repo}")

        # ADD THIS BLOCK HERE - right after the log statement above
        # IMPORTANT: For Bitbucket, modify the repository reference format
        if vcs_service.vcs_type == "bitbucket":
            # For Bitbucket, only use the repo name without owner
            repo = repo_info['repo']  # Just use the repo name alone
            logger.info(f"Modified for Bitbucket: using repo name only: {repo}")
        else:
            # For other providers like GitHub, use owner/repo format
            repo = f"{repo_info['owner']}/{repo_info['repo']}"
        # END OF NEW BLOCK
        
        file_list = vcs_service.get_repository_files(repo)
        logger.info(f"Retrieved {len(file_list)} files from {vcs_service.vcs_type} repository")
        
        # Log a sample of files if available
        if file_list:
            logger.info(f"Sample files: {', '.join(file_list[:5])}")
        else:
            logger.warning("No files found in repository")
            
        if vcs_service.vcs_type == "github":
            logger.info("--- End GitHub Repository Debug ---")

        # Try component-based file discovery
        component_files = get_component_based_files(vcs_service, repo, problem_info, file_list)
        logger.info(f"Found {len(component_files)} files using component matching")
        
        # If component-based discovery found files, use them
        relevant_files = {}
        if component_files:
            relevant_files = component_files
            logger.info("Using component-matched files for analysis")
        else:
            # Fall back to semantic search
            logger.info("No files found via component matching, falling back to semantic search")
            
            # Filter files by extensions to reduce the search space
            filtered_files = filter_files_by_extensions(file_list)
            logger.info(f"Filtered to {len(filtered_files)} files based on extensions")
            
            # Get content for a subset of files for embedding
            file_contents = {}
            for file_path in filtered_files[:50]:  # Limit to 50 files for embedding
                try:
                    content = vcs_service.get_file_content(repo, file_path)
                    file_contents[file_path] = content
                except Exception as e:
                    logger.debug(f"Failed to get file {file_path}: {str(e)}")
            
            # Create enhanced problem text for embedding
            components_text = ", ".join(problem_info.get('components', []))
            service_names_text = ", ".join(problem_info.get('service_names', []))
            
            problem_text = f"""
            {problem_info.get('title', '')}
            {problem_info.get('plain_description', problem_info.get('description', ''))}
            Services: {service_names_text}
            Components: {components_text}
            """
            
            logger.info(f"Created problem text for embeddings ({len(problem_text)} chars)")
            
            # Get embeddings through OpenSearch service if available
            if opensearch_service and opensearch_service.client:
                logger.info("Using OpenSearch for Bedrock embeddings")
                problem_embedding = opensearch_service.get_bedrock_embeddings([problem_text])[0]
                
                # Calculate embeddings for files
                file_embeddings = []
                file_paths = []
                
                for file_path, content in file_contents.items():
                    # Use a representative sample of the file
                    sample = content[:1000]
                    if len(content) > 2000:
                        # Add end of file if long enough
                        sample += "\n...\n" + content[-500:]
                    
                    file_embedding = opensearch_service.get_bedrock_embeddings([sample])[0]
                    file_embeddings.append(file_embedding)
                    file_paths.append(file_path)
            else:
                logger.info("Using AI service for embeddings")
                # Get vectors from AI service instead
                problem_embedding = ai_service.get_embeddings([problem_text])[0]
                
                # Calculate embeddings for files
                file_embeddings = []
                file_paths = []
                
                for file_path, content in file_contents.items():
                    # Use a representative sample of the file
                    sample = content[:1000]
                    if len(content) > 2000:
                        # Add end of file if long enough
                        sample += "\n...\n" + content[-500:]
                    
                    file_embedding = ai_service.get_embeddings([sample])[0]
                    file_embeddings.append(file_embedding)
                    file_paths.append(file_path)
            
            # Calculate similarities
            similarities = []
            for file_embedding in file_embeddings:
                # Cosine similarity using numpy
                similarity = np.dot(problem_embedding, file_embedding) / (
                    np.linalg.norm(problem_embedding) * np.linalg.norm(file_embedding)
                )
                similarities.append(float(similarity))
            
            # Get top relevant files with a lower threshold
            if similarities:
                # Include any files with similarity above threshold
                threshold = 0.1
                relevant_indices = [i for i, sim in enumerate(similarities) if sim > threshold]
                
                if relevant_indices:
                    # Sort by similarity and take top 10
                    top_indices = sorted(relevant_indices, key=lambda i: similarities[i], reverse=True)[:10]
                    relevant_file_paths = [file_paths[i] for i in top_indices]
                    
                    # Log the similarity scores for debugging
                    for i, idx in enumerate(top_indices):
                        logger.info(f"File {file_paths[idx]} - similarity: {similarities[idx]:.3f}")
                else:
                    # If nothing above threshold, just take top 5 anyway
                    top_indices = np.argsort(similarities)[::-1][:5]
                    relevant_file_paths = [file_paths[i] for i in top_indices]
                    logger.warning(f"No files above similarity threshold {threshold}, using top 5 anyway")
            else:
                relevant_file_paths = []
            
            logger.info(f"Found {len(relevant_file_paths)} relevant files via semantic search")
            
            # Get content for relevant files
            for file_path in relevant_file_paths:
                if file_path in file_contents:
                    relevant_files[file_path] = file_contents[file_path]
                else:
                    try:
                        content = vcs_service.get_file_content(repo, file_path)
                        relevant_files[file_path] = content
                    except Exception as e:
                        logger.warning(f"Failed to get file {file_path}: {str(e)}")
            
            # Store vectors in OpenSearch if available
            if opensearch_service and opensearch_service.client:
                try:
                    # Store problem vector
                    opensearch_service.index_vector(
                        f"problem_{context.aws_request_id}",
                        problem_embedding,
                        {
                            "type": "problem",
                            "title": problem_info.get('title', ''),
                            "severity": problem_info.get('severity', ''),
                            "repository": repo,
                            "timestamp": datetime.datetime.now().isoformat()
                        }
                    )
                    
                    # Store file vectors using bulk API
                    success_count = opensearch_service.store_file_vectors(
                        context.aws_request_id,
                        file_paths,
                        file_embeddings,
                        file_contents,
                        repo
                    )
                    logger.info(f"Stored {success_count} vectors in OpenSearch")
                except Exception as e:
                    logger.warning(f"Failed to store vectors in OpenSearch: {str(e)}")

        # Analyze the problem
        if not relevant_files:
            logger.warning("No relevant files found for analysis")
            send_notification(
                "No Relevant Files Found", 
                f"Could not find any relevant files for issue: {problem_info.get('title')}"
            )
            return {
                'statusCode': 200,
                'body': json.dumps('No relevant files found for analysis')
            }
            
        logger.info(f"Starting analysis with {len(relevant_files)} relevant files")
        
        if ENABLE_APM_TOOLS and apm_service:
            # First analysis with APM tools
            logger.info("Performing analysis with APM tools enabled")
            analysis = ai_service.analyze_problem_with_tools(problem_info, relevant_files, apm_service)
            
            # Extract tool calls
            tool_calls = []
            
            # Try to extract from response object or dictionary
            if hasattr(analysis, 'tool_calls'):
                tool_calls = analysis.tool_calls
            elif isinstance(analysis, dict) and 'tool_calls' in analysis:
                tool_calls = analysis['tool_calls']
            
            # If AI didn't use tools but we have service names, force tool usage
            if not tool_calls and problem_info.get('service_names'):
                logger.info("AI didn't use tools initially. Forcing tool usage...")
                service_name = problem_info['service_names'][0]
                
                # Create a simulated tool call for logs
                forced_tool_calls = [
                    {
                        'name': 'get_additional_logs',
                        'parameters': {
                            'service_name': service_name,
                            'time_range': '1h',
                            'log_level': 'ERROR'
                        },
                        'tool_use_id': 'forced_logs_call'
                    },
                    {
                        'name': 'get_service_metrics',
                        'parameters': {
                            'service_name': service_name,
                            'metric_type': 'error_rate',
                            'time_range': '1h'
                        },
                        'tool_use_id': 'forced_metrics_call'
                    }
                ]
                
                # Process these forced tool calls
                logger.info(f"Forcing APM tool usage for service: {service_name}")
                tool_calls = forced_tool_calls
            
            # Process tool calls if any
            if tool_calls:
                logger.info(f"Processing {len(tool_calls)} APM tool calls")
                updated_analysis = ai_service.process_tool_calls(tool_calls, apm_service, problem_info, relevant_files)
                
                if updated_analysis:
                    analysis = updated_analysis
                    logger.info("Analysis updated with APM data")
                    
                    # Check if we have tool results for additional file discovery
                    if isinstance(analysis, dict) and 'tool_results' in analysis:
                        # Extract error patterns from logs for additional file discovery
                        error_patterns = []
                        
                        # Collect service names mentioned in logs
                        service_names_in_logs = set()
                        
                        for result in analysis.get('tool_results', []):
                            if result.get('tool_name') == 'get_additional_logs':
                                logs = result.get('result', [])
                                for log in logs:
                                    if isinstance(log, dict) and 'content' in log:
                                        # Extract patterns from log content
                                        log_content = log['content']
                                        
                                        # Look for file paths with various patterns
                                        file_patterns = re.findall(r'File "([^"]+)"', log_content)
                                        file_patterns.extend(re.findall(r'at ([a-zA-Z0-9_./$]+)\(', log_content))  # Java stack traces
                                        file_patterns.extend(re.findall(r'at ([a-zA-Z0-9_./$]+):[0-9]+', log_content))  # Node.js stack traces
                                        
                                        # Look for function names
                                        func_patterns = re.findall(r'in ([a-zA-Z0-9_]+)\(', log_content)
                                        func_patterns.extend(re.findall(r'method=([a-zA-Z0-9_]+)', log_content))
                                        
                                        # Look for class names
                                        class_patterns = re.findall(r'class=([a-zA-Z0-9_]+)', log_content)
                                        class_patterns.extend(re.findall(r'([A-Z][a-zA-Z0-9_]+Exception)', log_content))
                                        
                                        # Extract service names
                                        service_pattern = re.findall(r'service=([a-zA-Z0-9_-]+)', log_content)
                                        service_pattern.extend(re.findall(r'([a-zA-Z0-9_-]+Service)', log_content))
                                        service_names_in_logs.update(service_pattern)
                                        
                                        # Extract endpoint patterns
                                        endpoint_patterns = re.findall(r'(GET|POST|PUT|DELETE) /[a-zA-Z0-9_/]+', log_content)
                                        endpoint_patterns = [p.split(' ')[1].strip('/') for p in endpoint_patterns]
                                        
                                        # Collect all patterns
                                        error_patterns.extend(file_patterns + func_patterns + class_patterns + endpoint_patterns)
                        
                        # Add service names from logs to our problem info
                        if service_names_in_logs:
                            problem_info['service_names'] = list(set(problem_info.get('service_names', []) + list(service_names_in_logs)))
                        
                        if error_patterns:
                            logger.info(f"Found error patterns in logs: {error_patterns}")
                            # Add these as components for a second file search
                            if 'components' not in problem_info:
                                problem_info['components'] = []
                            
                            # Filter out very short patterns (likely false positives)
                            filtered_error_patterns = [p for p in error_patterns if len(p) > 3]
                            
                            problem_info['components'] = list(set(problem_info['components'] + filtered_error_patterns))
                            
                            # Do a second component-based file search
                            additional_files = get_component_based_files(vcs_service, repo, problem_info, file_list)
                            
                            # If component search doesn't find enough, try semantic search with updated problem info
                            if len(additional_files) < 3 and opensearch_service and opensearch_service.client:
                                logger.info("Component search after log analysis found few files, trying semantic search with updated context")
                                
                                # Create updated problem text for embedding with log information
                                components_text = ", ".join(problem_info.get('components', []))
                                service_names_text = ", ".join(problem_info.get('service_names', []))
                                
                                # Extract log content to include in search
                                log_excerpts = []
                                for result in analysis.get('tool_results', []):
                                    if result.get('tool_name') == 'get_additional_logs':
                                        logs = result.get('result', [])
                                        for log in logs[:5]:  # Limit to first 5 logs
                                            if isinstance(log, dict) and 'content' in log:
                                                log_excerpts.append(log['content'][:200])  # Truncate long logs
                                
                                log_text = "\n".join(log_excerpts)
                                
                                # Enhanced problem text with log excerpts
                                updated_problem_text = f"""
                                {problem_info.get('title', '')}
                                {problem_info.get('plain_description', problem_info.get('description', ''))}
                                Services: {service_names_text}
                                Components: {components_text}
                                
                                Error logs:
                                {log_text}
                                """
                                
                                # Get updated problem embedding
                                updated_problem_embedding = opensearch_service.get_bedrock_embeddings([updated_problem_text])[0]
                                
                                # Re-run similarity calculation with the new context
                                updated_similarities = []
                                for file_embedding in file_embeddings:
                                    similarity = np.dot(updated_problem_embedding, file_embedding) / (
                                        np.linalg.norm(updated_problem_embedding) * np.linalg.norm(file_embedding)
                                    )
                                    updated_similarities.append(float(similarity))
                                
                                # Get top relevant files with the same threshold
                                if updated_similarities:
                                    threshold = 0.1
                                    relevant_indices = [i for i, sim in enumerate(updated_similarities) if sim > threshold]
                                    
                                    if relevant_indices:
                                        top_indices = sorted(relevant_indices, key=lambda i: updated_similarities[i], reverse=True)[:10]
                                        updated_file_paths = [file_paths[i] for i in top_indices]
                                        
                                        # Get content for any new files
                                        for file_path in updated_file_paths:
                                            if file_path not in relevant_files and file_path not in additional_files:
                                                try:
                                                    content = vcs_service.get_file_content(repo, file_path)
                                                    additional_files[file_path] = content
                                                except Exception as e:
                                                    logger.warning(f"Failed to get file {file_path}: {str(e)}")
                            
                            # Add any new files to relevant_files
                            new_files_count = 0
                            for file_path, content in additional_files.items():
                                if file_path not in relevant_files:
                                    relevant_files[file_path] = content
                                    new_files_count += 1
                            
                            logger.info(f"Added {new_files_count} new files based on log patterns")
                            
                            # Do one final analysis with the complete set of files if we found new ones
                            if new_files_count > 0:
                                logger.info("Performing final analysis with additional files")
                                final_analysis = ai_service.analyze_problem(problem_info, relevant_files)
                                analysis = final_analysis
                else:
                    logger.warning("Failed to get updated analysis with APM data")
        else:
            # Regular analysis without APM tools
            analysis = ai_service.analyze_problem(problem_info, relevant_files)
        
        # Process based on analysis
        action = analysis.get('action', 'needs_more_info')
        logger.info(f"Analysis determined action: {action}")
        
        if action == 'fix_code':
            # Switch to Claude Sonnet for code generation
            logger.info("Switching from Claude Opus to Claude Sonnet for code generation")
            updated_files = ai_service.generate_code_fix(problem_info, relevant_files, analysis)
            
            if not updated_files:
                logger.warning("No file updates generated despite 'fix_code' action")
                send_notification("No File Updates Generated", 
                                 f"AI analysis suggested a code fix but no updates were needed for: {problem_info.get('title')}")
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'action': 'no_changes_needed',
                        'explanation': analysis.get('explanation'),
                        'detail': 'AI suggested changes matched existing code'
                    })
                }
            
            # Create branch, update files, and create PR
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            branch_name = f"ai-fix-{timestamp}"
            
            logger.info(f"Creating branch {branch_name}")
            # Create branch
            vcs_service.create_branch(repo, branch_name, repo_info.get('default_branch', 'main'))
            
            # Update files
            logger.info(f"Updating {len(updated_files)} files")
            # Track whether any actual changes were made
            any_changes_made = False
            for file_path, content in updated_files.items():
                result = vcs_service.update_file(
                    repo,
                    file_path,
                    content,
                    f"AI fix for {problem_info.get('title', 'issue')}",
                    branch_name
                )
                any_changes_made = any_changes_made or result
            
            # Only create PR if actual changes were made
            if not any_changes_made:
                logger.warning("No actual changes were made to files - skipping PR creation")
                send_notification("No File Changes Needed", 
                                f"AI analysis suggested a code fix but all changes matched existing code for: {problem_info.get('title')}")
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'action': 'no_changes_needed',
                        'explanation': analysis.get('explanation'),
                        'detail': 'AI suggested changes matched existing code'
                    })
                }

            # Create PR
            pr_title = f"AI Fix: {problem_info.get('title', 'Fix for detected issue')}"
            pr_body = f"""
            This is an automated fix created by the AI Incident Response system.
            
            Problem: {problem_info.get('title')}
            Severity: {problem_info.get('severity')}
            
            Analysis: {analysis.get('explanation')}
            
            Modified files:
            {', '.join(updated_files.keys())}
            
            Please review the changes and merge if appropriate.
            """
            
            logger.info(f"Creating pull request")
            pr_url = vcs_service.create_pull_request(
                repo,
                pr_title,
                pr_body,
                branch_name,
                repo_info.get('default_branch', 'main')
            )
            
            send_notification(f"AI Fix Created: {problem_info.get('title')}", 
                             f"An automated fix has been created for an incident.\n\nPull Request: {pr_url}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'fix_code',
                    'explanation': analysis.get('explanation'),
                    'analysis_process': {
                        'component_search_files': len(component_files),
                        'semantic_search_used': len(component_files) == 0,
                        'apm_tools_used': len(analysis.get('tool_results', [])) if isinstance(analysis, dict) and 'tool_results' in analysis else 0,
                        'files_analyzed': len(relevant_files)
                    },
                    'pr_url': pr_url,
                    'branch': branch_name,
                    'updated_files': list(updated_files.keys()),
                    'detail': 'Pull request created with automated fix'
                })
            }
            
        elif action == 'create_ticket':
            # Generate ticket details and create ticket
            logger.info("Creating ticket based on analysis")
            ticket_details = ai_service.create_ticket_details(problem_info, analysis)
            
            # Determine if this should go directly to sprint or backlog
            severity = problem_info.get('severity', '').upper()
            priority = ticket_details.get('priority', 'MEDIUM').upper()
            
            # Only critical/high severity issues or explicitly high priority tickets go to sprint
            add_to_sprint = (severity in ['CRITICAL', 'HIGH', 'MAJOR'] or 
                            priority in ['HIGH', 'CRITICAL', 'URGENT'])
            
            sprint_label = "current-sprint" if add_to_sprint else "backlog"
            
            # Create the ticket with appropriate label
            labels = ticket_details.get('tags', ['auto-generated'])
            labels.append(sprint_label)
            
            ticket_id = ticket_service.create_ticket(
                ticket_details.get('title', problem_info.get('title', 'Issue from alert')),
                ticket_details.get('description', 'No description provided'),
                labels=labels
            )
            
            # Explicitly add to board/sprint if needed
            ticket_service.add_to_board(ticket_id, sprint_label)
            
            # Add analysis as a comment
            ticket_service.add_comment(
                ticket_id,
                f"AI Analysis:\n\n{analysis.get('explanation', 'No explanation provided')}"
            )
            
            # Notification includes sprint status
            sprint_status = "added to current sprint" if add_to_sprint else "added to backlog"
            send_notification(f"AI Created Ticket: {ticket_details.get('title')}", 
                            f"A ticket has been created for an incident that requires human attention ({sprint_status}).\n\nTicket ID: {ticket_id}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'ticket_created',
                    'ticket_id': ticket_id,
                    'add_to_sprint': add_to_sprint,
                    'ticket_details': ticket_details
                })
            }
            
        else:  # needs_more_info
            # Determine if this needs investigation ticket or just notification
            severity = problem_info.get('severity', '').upper()
            issue_title = problem_info.get('title', 'Alert')
            
            # Check if this is a low-severity common issue
            is_common_issue = False
            # Look for common patterns in the explanation
            common_phrases = [
                "This is a common occurrence",
                "This appears to be expected behavior",
                "This is likely a false positive",
                "This is a known issue",
                "This is a transient issue"
            ]
            
            if analysis.get('explanation') and any(phrase.lower() in analysis.get('explanation', '').lower() 
                                                  for phrase in common_phrases):
                is_common_issue = True
            
            # For low severity common issues, just send notification without ticket
            if (severity in ['LOW', 'MINOR', 'INFO', 'NORMAL'] and is_common_issue) or (
                severity in ['NORMAL', 'INFO'] and 'false positive' in analysis.get('explanation', '').lower()):
                
                # Just send notification without creating ticket
                send_notification(f"Common Issue Detected: {issue_title}", 
                                 f"A common or expected issue was detected that doesn't require immediate attention.\n\n" +
                                 f"Summary: {analysis.get('explanation', 'No explanation provided')[:200]}...")
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'action': 'notification_only',
                        'explanation': analysis.get('explanation'),
                        'reason': 'Common low-severity issue'
                    })
                }
            
            # Otherwise create investigation ticket with comprehensive details
            logger.info("Creating investigation ticket with comprehensive analysis details")
            
            # Use the function to create a more user-friendly ticket description
            detailed_description = create_investigation_ticket_description(
                problem_info=problem_info,
                analysis=analysis,
                relevant_files=relevant_files,
                tool_results=analysis.get('tool_results', [])
            )
            
            # Always put investigation tickets in backlog, not sprint
            labels = ["investigation-needed", "auto-generated", "ai-response", "backlog"]
            ticket_id = ticket_service.create_ticket(
                f"Investigation Needed: {issue_title}",
                detailed_description,
                labels=labels
            )
            
            # IMPORTANT: Explicitly set this ticket to be in the backlog, not in sprint
            ticket_service.add_to_board(ticket_id, "backlog")
            
            send_notification(f"Investigation Needed: {issue_title}", 
                            f"An alert requires more information for analysis (added to backlog).\n\n" +
                            f"Ticket ID: {ticket_id}\n\nSummary: {len(relevant_files)} files analyzed, " + 
                            f"{len(analysis.get('tool_results', []))} APM tools used.")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'needs_more_info',
                    'ticket_id': ticket_id,
                    'needed_info': analysis.get('details', {}).get('needed_info', 'Additional context is required'),
                    'added_to_sprint': False  # Always false for investigation tickets
                })
            }
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        
        # Send notification about the error
        send_notification("Error in AI Incident Response", f"An error occurred while processing an incident: {str(e)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }
    finally:
        # Log execution time
        end_time = datetime.datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Lambda execution completed in {duration:.2f} seconds")

def detect_technology(description, service_name):
    """Detect application technology stack from alert description and service name"""
    components = []
    tech_detected = False
    
    # Java detection
    if any(pattern in description.lower() for pattern in 
           ['java.lang.', 'springframework', 'java.io.', 
            'tomcat', 'java', 'jakarta', 'hibernate']):
        components.extend(['Java', 'src/main', 'pom.xml', 'build.gradle'])
        tech_detected = True
    
    # .NET detection
    if any(pattern in description.lower() for pattern in 
            ['system.', 'microsoft.', '.net', 'aspnet', 'c#', 'iis']):
        components.extend(['C#', 'Controllers', 'Models', 'web.config'])
        tech_detected = True
    
    # Python detection
    if any(pattern in description.lower() for pattern in 
            ['python', 'flask', 'django', 'werkzeug', 'gunicorn', 'uwsgi']):
        components.extend(['Python', 'app.py', 'routes', 'views.py'])
        tech_detected = True
    
    # JavaScript/Node detection
    if any(pattern in description.lower() for pattern in 
            ['node', 'express', 'javascript', 'npm', 'yarn', 'js']):
        components.extend(['JavaScript', 'index.js', 'routes', 'package.json'])
        tech_detected = True
    
    # Go detection
    if any(pattern in description.lower() for pattern in 
            ['go', 'golang', 'goroutine', 'panic:']):
        components.extend(['Go', 'main.go', 'handlers', 'go.mod'])
        tech_detected = True
    
    # Service name based detection as fallback
    if not tech_detected:
        service_lower = service_name.lower()
        
        # Try to infer technology from service name
        if any(term in service_lower for term in ['java', 'spring', 'tomcat']):
            components.extend(['Java', 'src/main'])
        elif any(term in service_lower for term in ['node', 'js', 'javascript']):
            components.extend(['JavaScript', 'index.js'])
        elif any(term in service_lower for term in ['py', 'flask', 'django']):
            components.extend(['Python', 'app.py'])
        elif any(term in service_lower for term in ['net', 'asp', 'iis']):
            components.extend(['C#', 'Controllers'])
        elif any(term in service_lower for term in ['go']):
            components.extend(['Go', 'main.go'])
        # Generic API components if no specific technology detected
        elif 'api' in service_lower:
            components.extend(['API', 'routes', 'config', 'controllers'])
    
    # Add general component patterns that apply across multiple technologies
    if 'database' in description.lower() or 'sql' in description.lower():
        components.extend(['database', 'db', 'repository', 'dao', 'model'])
    
    if 'memory' in description.lower():
        components.extend(['config', 'settings'])
        
    if 'error' in description.lower() or 'exception' in description.lower():
        components.extend(['error', 'exception', 'handler', 'middleware'])
    
    return components

def get_component_based_files(vcs_service, repo, problem_info, file_list):
    """Find files based on components extracted from problem info"""
    components = problem_info.get('components', [])
    service_names = problem_info.get('service_names', [])
    # Add all components and service names together
    search_terms = components + service_names
    
    # Get description to detect technologies
    description = problem_info.get('plain_description', problem_info.get('description', ''))
    
    # Detect key technology indicators in description
    is_java = any(term in description.lower() for term in ['java', 'spring', 'jvm', 'heap'])
    is_dotnet = any(term in description.lower() for term in ['.net', 'c#', 'iis', 'aspnet'])
    is_python = any(term in description.lower() for term in ['python', 'flask', 'django', 'werkzeug'])
    is_nodejs = any(term in description.lower() for term in ['node', 'javascript', 'npm', 'express'])
    is_go = any(term in description.lower() for term in ['go', 'golang'])
    
    # Add technology-specific search terms
    if is_java:
        search_terms.extend(['java', 'src', 'main', 'controller', 'service', 'repository', 'pom.xml', 'build.gradle'])
    elif is_dotnet:
        search_terms.extend(['controller', 'model', 'service', 'repository', 'startup', 'program', 'web.config'])
    elif is_python:
        search_terms.extend(['exception', 'error', 'sql', 'db', 'database', 'query', 'flask', 'app.py', 'api', 'routes', 'views'])
    elif is_nodejs:
        search_terms.extend(['index.js', 'app.js', 'server.js', 'routes', 'controllers', 'middleware'])
    elif is_go:
        search_terms.extend(['main.go', 'handler', 'router', 'middleware'])
    
    # Common patterns across technologies
    if any(term in description.lower() for term in ['exception', 'error', 'sql', 'query', 'database']):
        search_terms.extend(['exception', 'error', 'sql', 'db', 'database', 'query', 'repository', 'dao'])
    
    # Log what we're looking for
    logger.info(f"Searching for files related to: {search_terms}")
    
    # Score and find files
    scored_files = {}
    
    for file_path in file_list:
        score = 0
        file_lower = file_path.lower()
        
        # Score by file extension (technology specific)
        if is_java and any(file_path.endswith(ext) for ext in ['.java', '.xml', '.properties', '.yml']):
            score += 3
        elif is_dotnet and any(file_path.endswith(ext) for ext in ['.cs', '.cshtml', '.config', '.json']):
            score += 3
        elif is_python and file_path.endswith('.py'):
            score += 3
        elif is_nodejs and any(file_path.endswith(ext) for ext in ['.js', '.ts', '.json']):
            score += 3
        elif is_go and file_path.endswith('.go'):
            score += 3
        elif any(file_path.endswith(ext) for ext in ['.js', '.java', '.go', '.ts', '.py', '.cs']):  # Common code files
            score += 2
        elif any(file_path.endswith(ext) for ext in ['.yml', '.yaml', '.json', '.xml', '.conf']):  # Config files
            score += 1
        
        # Score by component matches in path
        for term in search_terms:
            if term and len(term) > 2 and term.lower() in file_lower:
                score += 4
        
        # Important file patterns by technology
        if is_java and any(pattern in file_lower for pattern in ['application.properties', 'application.yml', 'pom.xml', 'build.gradle']):
            score += 5
        elif is_dotnet and any(pattern in file_lower for pattern in ['startup.cs', 'program.cs', 'web.config', 'appsettings.json']):
            score += 5
        elif is_python and any(pattern in file_lower for pattern in ['app.py', 'main.py', 'config.py', 'settings.py', 'database.py']):
            score += 5
        elif is_nodejs and any(pattern in file_lower for pattern in ['index.js', 'app.js', 'server.js', 'package.json']):
            score += 5
        elif is_go and any(pattern in file_lower for pattern in ['main.go', 'go.mod']):
            score += 5
        
        # Only get content for promising files
        if score >= 3:
            try:
                content = vcs_service.get_file_content(repo, file_path)
                
                # Additional scoring based on content
                content_lower = content.lower()
                for term in search_terms:
                    if term and len(term) > 2 and term.lower() in content_lower:
                        score += 2
                
                # Store files with good scores
                if score >= 5:
                    scored_files[file_path] = {"content": content, "score": score}
            except Exception as e:
                logger.debug(f"Failed to get content for {file_path}: {e}")
    
    # Sort by score and return
    sorted_files = sorted(scored_files.items(), key=lambda x: x[1]["score"], reverse=True)
    logger.info(f"Found {len(sorted_files)} files using component matching")
    
    # Return as dictionary of path -> content (limited to top 10)
    return {path: data["content"] for path, data in sorted_files[:10]}

def extract_problem_info(event):
    """Extract structured problem info from the event"""
    try:
        # Add diagnostic logging
        logger.info(f"Event type: {type(event).__name__}")
        if isinstance(event, dict):
            logger.info(f"Event keys: {list(event.keys())}")
            if 'body' in event:
                body_type = type(event['body']).__name__
                logger.info(f"Body type: {body_type}")
        
        # Check for nested body structure (common in test events)
        if isinstance(event, dict) and 'body' in event and isinstance(event['body'], dict) and 'alert_type' in event['body']:
            # Use the nested body directly
            logger.info("Detected nested Datadog webhook format")
            body = event['body']
            
            # Extract service name from tags if available
            service_name = body.get('hostname', 'unknown-service')
            for tag in body.get('tags', []):
                if tag.startswith('service:'):
                    service_name = tag.split(':', 1)[1]
                    break
            
            # Map severity based on alert type
            severity_mapping = {
                'error': 'CRITICAL',
                'warning': 'MAJOR',
                'info': 'MINOR',
                'success': 'NORMAL'
            }
            severity = severity_mapping.get(body.get('alert_type', ''), 'MAJOR')
            
            # Create detailed description
            description = body.get('message', body.get('body', 'No details available'))
            
            # Format as list items for HTML parsing
            formatted_desc = description + f"\n\n<li>Status: {body.get('status', 'Unknown')}</li>"
            formatted_desc += f"<li>Condition: {body.get('alertCondition', body.get('alert_condition', 'Unknown'))}</li>"
            formatted_desc += f"<li>Metric: {body.get('alertMetric', body.get('metric', 'Unknown'))}</li>"
            
            # Extract components using generic technology detection
            components = detect_technology(description, service_name)
            
            # Also extract components from the message text using regex
            message_text = body.get('message', '')
            service_components = re.findall(r'([A-Za-z][A-Za-z0-9]*(?:Service|API|App|Module))', message_text)
            components.extend(service_components)
            
            # Plain description for better embedding
            plain_description = re.sub(r'<[^>]+>', ' ', formatted_desc)
            plain_description = re.sub(r'\s+', ' ', plain_description).strip()
            # Enhance service name extraction - look for more specific patterns in description
            service_name = extract_service_from_text(description)
            if not service_name:
                service_name = body.get('hostname', 'unknown-service')
            
            problem_info = {
                'title': body.get('title', f"Alert for {service_name}"),
                'severity': severity,
                'impact': service_name,
                'description': formatted_desc,
                'plain_description': plain_description,
                'service_names': [service_name],
                'entity_ids': [str(body.get('id', 'ENTITY-UNKNOWN'))],
                'components': list(set(components))  # Deduplicate components
            }
            
            logger.info(f"Extracted service names: {problem_info['service_names']}")
            logger.info(f"Extracted components: {problem_info['components']}")
            
            return problem_info
        
        # Check if this is an API Gateway event with a body (webhook)
        elif isinstance(event, dict) and 'body' in event and isinstance(event['body'], str):
            # Parse the body if it's a string
            try:
                logger.info("Attempting to parse string body as JSON")
                body = json.loads(event['body'])
                
                # Check if this looks like a Datadog webhook
                if 'alert_type' in body and ('title' in body or 'hostname' in body):
                    logger.info("Detected Datadog webhook in API Gateway format")
                    
                    # Extract service name from tags if available
                    service_name = body.get('hostname', 'unknown-service')
                    for tag in body.get('tags', []):
                        if tag.startswith('service:'):
                            service_name = tag.split(':', 1)[1]
                            break
                    
                    # Process the alert similarly to the nested body format
                    severity_mapping = {
                        'error': 'CRITICAL',
                        'warning': 'MAJOR',
                        'info': 'MINOR',
                        'success': 'NORMAL'
                    }
                    severity = severity_mapping.get(body.get('alert_type', ''), 'MAJOR')
                    
                    description = body.get('message', body.get('body', 'No details available'))
                    components = detect_technology(description, service_name)
                    
                    formatted_desc = description + f"\n\n<li>Status: {body.get('status', 'Unknown')}</li>"
                    formatted_desc += f"<li>Condition: {body.get('alertCondition', body.get('alert_condition', 'Unknown'))}</li>"
                    formatted_desc += f"<li>Metric: {body.get('alertMetric', body.get('metric', 'Unknown'))}</li>"
                    
                    plain_description = re.sub(r'<[^>]+>', ' ', formatted_desc)
                    plain_description = re.sub(r'\s+', ' ', plain_description).strip()
                    
                    return {
                        'title': body.get('title', f"Alert for {service_name}"),
                        'severity': severity,
                        'impact': service_name,
                        'description': formatted_desc,
                        'plain_description': plain_description,
                        'service_names': [service_name],
                        'entity_ids': [str(body.get('id', 'ENTITY-UNKNOWN'))],
                        'components': list(set(components))  # Deduplicate components
                    }
            except Exception as e:
                logger.error(f"Error parsing webhook body: {str(e)}")
                # Continue with other extractors
        
        # For Dynatrace alerts (with technology detection added)
        if 'problemTitle' in event:
            # Extract service names from impacted entities
            service_names = []
            entity_ids = []
            components = []
            
            for entity in event.get('impactedEntities', []):
                if entity.get('type') == 'SERVICE':
                    service_names.append(entity.get('name'))
                    entity_ids.append(entity.get('entity'))
            
            # Extract more detailed description if available
            description = event.get('problemDetails', 'No details available')
            
            # Extract patterns from HTML description
            code_patterns = re.findall(r'<code>([^<]+)</code>', description)
            components.extend(code_patterns)
            
            error_patterns = re.findall(r'<li>([^<]+)</li>', description)
            components.extend(error_patterns)
            
            plain_description = re.sub(r'<[^>]+>', ' ', description)
            plain_description = re.sub(r'\s+', ' ', plain_description).strip()
            
            title_components = re.findall(r'([A-Za-z][A-Za-z0-9]*(?:Service|API|App|Module))', event.get('problemTitle', ''))
            components.extend(title_components)
            
            # Use technology detection instead of hardcoded Flask components
            service_name = service_names[0] if service_names else "unknown-service"
            tech_components = detect_technology(description + " " + event.get('problemTitle', ''), service_name)
            components.extend(tech_components)
            
            return {
                'title': event.get('problemTitle', 'Unknown Issue'),
                'severity': event.get('severity', 'UNKNOWN'),
                'impact': service_names[0] if service_names else "Unknown Service",
                'description': description,
                'plain_description': plain_description,
                'service_names': service_names,
                'entity_ids': entity_ids,
                'components': list(set(components))  # Deduplicate components
            }
        
        # For custom events and fallbacks - with technology detection
        elif 'problem' in event:
            problem = event['problem']
            if 'components' not in problem and 'description' in problem:
                service_name = problem.get('impact', 'unknown-service')
                tech_components = detect_technology(problem['description'], service_name)
                problem['components'] = list(set(problem.get('components', []) + tech_components))
            return problem
        else:
            # Default case - ensure we always have service_names and components
            logger.warning("No specific alert format detected, using fallback format")
            title = event.get('title', 'Unknown Issue')
            description = event.get('description', 'No details available')
            service_name = event.get('service', 'unknown-service')
            
            # Detect technology even in fallback case
            components = detect_technology(description, service_name)
            
            return {
                'title': title,
                'severity': event.get('severity', 'UNKNOWN'),
                'impact': event.get('impact', service_name),
                'description': description,
                'plain_description': description,
                'service_names': [service_name],
                'components': components
            }
    except Exception as e:
        logger.error(f"Error extracting problem info: {e}", exc_info=True)
        return {
            'title': "Unknown Issue",
            'severity': "UNKNOWN", 
            'impact': "Unknown Entity",
            'description': "No details available",
            'service_names': ['unknown-service'],
            'components': []
        }

def extract_service_from_text(text):
    """Extract service name from text using patterns"""
    # Common patterns for service names
    patterns = [
        r'service[:\s]+([a-zA-Z0-9_-]+)',
        r'app[:\s]+([a-zA-Z0-9_-]+)',
        r'application[:\s]+([a-zA-Z0-9_-]+)',
        r'([a-zA-Z0-9_-]+)[\s-]service',
        r'([a-zA-Z0-9_-]+)[\s-]app'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        if matches:
            return matches[0]
    
    return None
    
# Updated environment variables for generic repository configuration
REPO_OWNER = os.environ.get("REPO_OWNER") 
REPO_NAME = os.environ.get("REPO_NAME")
REPO_DEFAULT_BRANCH = os.environ.get("REPO_DEFAULT_BRANCH", "main")

def extract_repo_info(event):
    """Extract repository information from the event or environment variables"""
    if 'repository' in event:
        return event['repository']
    elif 'repo_owner' in event and 'repo_name' in event:
        return {
            'owner': event.get('repo_owner'),
            'repo': event.get('repo_name'),
            'default_branch': event.get('default_branch', REPO_DEFAULT_BRANCH)
        }
    elif REPO_OWNER and REPO_NAME:
        # Use environment variables as the source of truth
        return {
            'owner': REPO_OWNER,
            'repo': REPO_NAME,
            'default_branch': REPO_DEFAULT_BRANCH
        }
    else:
        # Last resort - return empty dict (will be caught as an error)
        logger.error("No repository information available in event or environment variables")
        return {}

def filter_files_by_extensions(file_list):
    """Filter files based on extensions across multiple technologies"""
    # Comprehensive extensions for multiple languages
    extensions_of_interest = [
        # Common programming languages
        '.py', '.js', '.ts', '.java', '.cs', '.go', 
        '.rb', '.php', '.scala', '.kt', '.groovy',
        '.cpp', '.c', '.h', '.hpp', '.swift', '.m',
        
        # Web technologies
        '.jsx', '.tsx', '.vue', '.html', '.css', '.scss',
        
        # Configuration and data
        '.yaml', '.yml', '.json', '.xml', '.ini', '.toml', '.conf',
        '.properties', '.env', '.config', '.tf',
        
        # Scripts
        '.sh', '.bat', '.ps1', '.sql'
    ]
    
    # Important files by name pattern
    important_files = [
        # Container and deployment
        'dockerfile', 'docker-compose', 'kubernetes', 'k8s',
        
        # Build and dependency management
        'makefile', 'pom.xml', 'build.gradle', 'package.json',
        'requirements.txt', 'go.mod', 'gemfile',
        
        # Configuration
        'config', 'settings', '.env', 'web.config', 'appsettings',
        
        # Common entry points
        'app.', 'main.', 'index.', 'server.', 'program.', 'startup.',
        
        # Database related
        'database', 'repository', 'dao', 'model', 'entity',
        
        # API and controllers
        'controller', 'route', 'handler', 'middleware', 'api'
    ]
    
    filtered_files = []
    
    for file_path in file_list:
        file_path_lower = file_path.lower()
        
        # Include files with relevant extensions
        if any(file_path.endswith(ext) for ext in extensions_of_interest):
            filtered_files.append(file_path)
            continue
            
        # Include important files regardless of extension
        if any(important in file_path_lower for important in important_files):
            filtered_files.append(file_path)
            continue
    
    return filtered_files

def create_investigation_ticket_description(problem_info, analysis, relevant_files, tool_results=None):
    """Create a concise, actionable ticket description for 'needs_more_info' cases"""
    
    # Start with essential problem context
    description = f"""
    # Investigation Needed: {problem_info.get('title')}
    
    ## Problem Summary
    - **Service**: {', '.join(problem_info.get('service_names', ['Unknown']))}
    - **Severity**: {problem_info.get('severity', 'Unknown')}
    - **Issue**: {problem_info.get('title')}
    """
    
    # Add specific needed information section - make this prominent
    specific_needs = analysis.get('details', {}).get('needed_info')
    if specific_needs:
        description += f"""
        ## Information Needed ⚠️
        {specific_needs}
        """
    else:
        # If no specific needs were identified, provide guidance
        description += """
        ## Information Needed ⚠️
        The automated analysis couldn't determine the root cause with available data. 
        Please provide additional context about:
        
        - Recent changes to the affected service
        - Patterns or timing of the issue occurrence
        - Related services that might be affected
        """
    
    # Add insight from what we do know (error patterns detected)
    if tool_results:
        error_patterns = []
        error_counts = {}
        
        # Extract meaningful error patterns from logs, not the raw data
        for result in tool_results:
            if result.get('tool_name') == 'get_additional_logs':
                logs = result.get('result', [])
                for log in logs[:5]:  # Limit to first 5 for brevity
                    if isinstance(log, dict) and 'content' in log:
                        content = log.get('content', '')
                        # Extract key error messages, not entire logs
                        if 'error' in content.lower() or 'exception' in content.lower():
                            # Get the error message, not the entire stack trace
                            lines = content.split('\n')
                            error_line = next((line for line in lines if 'error' in line.lower() or 'exception' in line.lower()), '')
                            if error_line and len(error_line) > 10:
                                # Track frequency of this error
                                if error_line in error_counts:
                                    error_counts[error_line] += 1
                                else:
                                    error_counts[error_line] = 1
                                    # Only add unique errors to the patterns list
                                    error_patterns.append(error_line)
        
        if error_patterns:
            description += """
            ## Key Error Patterns Detected
            """
            for pattern in error_patterns[:3]:  # Limit to top 3 errors
                count = error_counts.get(pattern, 1)
                count_text = f"({count} occurrences)" if count > 1 else ""
                description += f"- {pattern} {count_text}\n"
    
    # Include analyzed files section - but keep it brief
    if relevant_files:
        file_list = list(relevant_files.keys())
        description += f"""
        ## Context
        - {len(file_list)} relevant files were analyzed
        """
        
        if len(file_list) <= 5:
            description += "- Files: " + ", ".join(file_list)
        else:
            # Just list a few key files
            description += f"- Key files: {', '.join(file_list[:3])} and {len(file_list)-3} others"
    
    # Add AI analysis summary - keep it concise
    if analysis.get('explanation'):
        explanation = analysis.get('explanation')
        if len(explanation) > 500:
            explanation = explanation[:500] + "..."
            
        description += f"""
        ## Initial Analysis
        {explanation}
        """
    
    return description

def create_analysis_summary(problem_info, component_files, semantic_files, 
                            tool_results, analysis, relevant_files):
    """
    Create a comprehensive summary of the analysis process for debugging/reporting
    """
    summary = {
        "problem_info": {
            "title": problem_info.get('title'),
            "service_name": problem_info.get('service_names', ['unknown'])[0],
            "severity": problem_info.get('severity', 'UNKNOWN'),
            "components_detected": problem_info.get('components', [])
        },
        "file_discovery": {
            "component_search": {
                "files_found": len(component_files),
                "file_paths": list(component_files.keys()) if component_files else []
            },
            "semantic_search": {
                "performed": len(component_files) == 0,
                "files_found": len(semantic_files) if semantic_files else 0, 
                "file_paths": list(semantic_files.keys()) if semantic_files else []
            }
        },
        "apm_tool_usage": {
            "tools_called": [],
            "errors_encountered": []
        },
        "analysis_result": {
            "action": analysis.get('action', 'needs_more_info'),
            "explanation": analysis.get('explanation', 'No explanation provided'),
            "total_files_analyzed": len(relevant_files)
        }
    }
    
    # Add APM tool details if available
    if tool_results:
        for result in tool_results:
            tool_info = {
                "tool": result.get('tool_name'),
                "parameters": result.get('parameters', {}),
                "success": result.get('result') is not None and not isinstance(result.get('result'), str)
            }
            
            # Check for errors in tool execution
            if isinstance(result.get('result'), str) and 'error' in result.get('result', '').lower():
                tool_info["error"] = result.get('result')
                summary["apm_tool_usage"]["errors_encountered"].append({
                    "tool": result.get('tool_name'),
                    "error": result.get('result')
                })
            elif not result.get('result'):
                tool_info["error"] = "No data returned"
                summary["apm_tool_usage"]["errors_encountered"].append({
                    "tool": result.get('tool_name'),
                    "error": "No data returned"
                })
                
            summary["apm_tool_usage"]["tools_called"].append(tool_info)
    
    return summary

def send_notification(title, message):
    """Send a notification to the configured webhook"""
    if not NOTIFICATION_WEBHOOK:
        logger.info(f"Notification not sent (no webhook configured): {title}")
        return
    
    try:
        import requests
        
        # Determine if this is a Teams webhook by URL
        if "office.com" in NOTIFICATION_WEBHOOK or "office365.com" in NOTIFICATION_WEBHOOK:
            # Teams message card format
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "title": title,
                "text": message
            }
        else:
            # Generic webhook format
            payload = {
                "title": title,
                "message": message,
                "timestamp": datetime.datetime.now().isoformat()
            }
        
        requests.post(NOTIFICATION_WEBHOOK, json=payload, timeout=5)
        logger.info(f"Notification sent: {title}")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
