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

# Environment configuration - now using secrets with fallbacks
ANTHROPIC_API_KEY = secrets.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
VCS_TYPE = os.environ.get("VCS_TYPE")
# Modify the environment configuration to explicitly log token source
VCS_TOKEN = None
if "VCS_TOKEN" in secrets:
    VCS_TOKEN = secrets.get("VCS_TOKEN")
    logger.info("Loaded GitHub token from Secrets Manager")
elif "VCS_TOKEN" in os.environ:
    VCS_TOKEN = os.environ.get("VCS_TOKEN")
    logger.info("Loaded GitHub token from environment variables")
else:
    logger.warning("No GitHub token found in Secrets Manager or environment variables")
# Use safer JSON loading for secrets
VCS_EXTRA_PARAMS = {}
try:
    if "VCS_EXTRA_PARAMS" in secrets:
        if isinstance(secrets.get("VCS_EXTRA_PARAMS"), dict):
            VCS_EXTRA_PARAMS = secrets.get("VCS_EXTRA_PARAMS")
            logger.info("Loaded VCS_EXTRA_PARAMS as dictionary from Secrets Manager")
        else:
            # Try parsing as JSON string
            VCS_EXTRA_PARAMS = json.loads(secrets.get("VCS_EXTRA_PARAMS"))
            logger.info("Loaded VCS_EXTRA_PARAMS as JSON string from Secrets Manager")
    elif "VCS_EXTRA_PARAMS" in os.environ:
        VCS_EXTRA_PARAMS = json.loads(os.environ.get("VCS_EXTRA_PARAMS", "{}"))
        logger.info("Loaded VCS_EXTRA_PARAMS from environment")
except Exception as e:
    logger.error(f"Error parsing VCS_EXTRA_PARAMS: {str(e)}, using empty dict")
    VCS_EXTRA_PARAMS = {}
OPENSEARCH_ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT")
ENABLE_APM_TOOLS = os.environ.get("ENABLE_APM_TOOLS", "true").lower() == "true"
APM_TYPE = os.environ.get("APM_TYPE")
APM_API_KEY = secrets.get("APM_API_KEY") or os.environ.get("APM_API_KEY")
APM_EXTRA_PARAMS = json.loads(secrets.get("APM_EXTRA_PARAMS", "{}")) or json.loads(os.environ.get("APM_EXTRA_PARAMS", "{}"))
TICKET_TYPE = os.environ.get("TICKET_TYPE")
TICKET_PARAMS = json.loads(secrets.get("TICKET_PARAMS", "{}")) or json.loads(os.environ.get("TICKET_PARAMS", "{}"))
NOTIFICATION_WEBHOOK = secrets.get("NOTIFICATION_WEBHOOK") or os.environ.get("NOTIFICATION_WEBHOOK")

def lambda_handler(event, context):
    """Main Lambda handler"""
    start_time = datetime.datetime.now()
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Initialize services
        logger.info("Initializing services")
        vcs_service = VCSService()
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
        file_list = vcs_service.get_repository_files(repo)
        logger.info(f"Retrieved {len(file_list)} files from GitHub repository")
        
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
            
            # Get vectors for problem and files
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
            
            # Get top relevant files with a lower threshold (0.1 instead of default)
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
            if opensearch_service:
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
                    
                    # Store file vectors
                    opensearch_service.store_file_vectors(
                        context.aws_request_id,
                        file_paths,
                        file_embeddings,
                        file_contents,
                        repo
                    )
                    logger.info("Stored vectors in OpenSearch")
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
                        for result in analysis.get('tool_results', []):
                            if result.get('tool_name') == 'get_additional_logs':
                                logs = result.get('result', [])
                                for log in logs:
                                    if isinstance(log, dict) and 'content' in log:
                                        # Extract patterns from log content
                                        log_content = log['content']
                                        # Look for file paths and function names
                                        file_patterns = re.findall(r'File "([^"]+)"', log_content)
                                        func_patterns = re.findall(r'in ([a-zA-Z0-9_]+)\(', log_content)
                                        error_patterns.extend(file_patterns + func_patterns)
                        
                        if error_patterns:
                            logger.info(f"Found error patterns in logs: {error_patterns}")
                            # Add these as components for a second file search
                            if 'components' not in problem_info:
                                problem_info['components'] = []
                            problem_info['components'] = list(set(problem_info['components'] + error_patterns))
                            
                            # Do a second component-based file search
                            additional_files = get_component_based_files(vcs_service, repo, problem_info, file_list)
                            
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
            logger.info("Generating code fix")
            updated_files = ai_service.generate_code_fix(problem_info, relevant_files, analysis)
            
            if not updated_files:
                logger.warning("No file updates generated despite 'fix_code' action")
                send_notification("No File Updates Generated", 
                                 f"AI analysis suggested a code fix but no updates were generated for: {problem_info.get('title')}")
                return {
                    'statusCode': 200,
                    'body': json.dumps('No file updates were generated')
                }
            
            # Create branch, update files, and create PR
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            branch_name = f"ai-fix-{timestamp}"
            
            logger.info(f"Creating branch {branch_name}")
            # Create branch
            vcs_service.create_branch(repo, branch_name, repo_info.get('default_branch', 'main'))
            
            # Update files
            logger.info(f"Updating {len(updated_files)} files")
            for file_path, content in updated_files.items():
                vcs_service.update_file(
                    repo,
                    file_path,
                    content,
                    f"AI fix for {problem_info.get('title', 'issue')}",
                    branch_name
                )
            
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
                    'action': 'code_fix',
                    'pr_url': pr_url,
                    'branch': branch_name,
                    'updated_files': list(updated_files.keys())
                })
            }
            
        elif action == 'create_ticket':
            # Generate ticket details and create ticket
            logger.info("Creating ticket based on analysis")
            ticket_details = ai_service.create_ticket_details(problem_info, analysis)
            
            ticket_id = ticket_service.create_ticket(
                ticket_details.get('title', problem_info.get('title', 'Issue from alert')),
                ticket_details.get('description', 'No description provided'),
                labels=ticket_details.get('tags', ['auto-generated'])
            )
            
            # Add analysis as a comment
            ticket_service.add_comment(
                ticket_id,
                f"AI Analysis:\n\n{analysis.get('explanation', 'No explanation provided')}"
            )
            
            send_notification(f"AI Created Ticket: {ticket_details.get('title')}", 
                            f"A ticket has been created for an incident that requires human attention.\n\nTicket ID: {ticket_id}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'ticket_created',
                    'ticket_id': ticket_id,
                    'ticket_details': ticket_details
                })
            }
            
        else:  # needs_more_info
            # Create investigation ticket
            logger.info("Creating investigation ticket for more information")
            ticket_id = ticket_service.create_ticket(
                f"Investigation Needed: {problem_info.get('title', 'Alert')}",
                f"""
                This alert requires more information to determine the appropriate action.
                
                Problem: {problem_info.get('title')}
                Severity: {problem_info.get('severity')}
                
                AI Analysis: {analysis.get('explanation')}
                
                Needed Information: {analysis.get('details', {}).get('needed_info', 'Additional context is required')}
                """,
                labels=["investigation-needed", "auto-generated"]
            )
            
            send_notification(f"Investigation Needed: {problem_info.get('title')}", 
                             f"An alert requires more information for proper analysis.\n\nTicket ID: {ticket_id}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'needs_more_info',
                    'ticket_id': ticket_id,
                    'needed_info': analysis.get('details', {}).get('needed_info', 'Additional context is required')
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

def get_component_based_files(vcs_service, repo, problem_info, file_list):
    """Find files based on components extracted from problem info"""
    components = problem_info.get('components', [])
    service_names = problem_info.get('service_names', [])
    # Add all components and service names together
    search_terms = components + service_names
    
    # Also check for common error types in the description
    description = problem_info.get('plain_description', problem_info.get('description', ''))
    if any(term in description.lower() for term in ['exception', 'error', 'sql', 'query', 'database']):
        search_terms.extend(['exception', 'error', 'sql', 'db', 'database', 'query'])
    
    if any(term in description.lower() for term in ['flask', 'api', 'endpoint']):
        search_terms.extend(['flask', 'app.py', 'api', 'routes', 'views'])
    
    # Log what we're looking for
    logger.info(f"Searching for files related to: {search_terms}")
    
    # Score and find files
    scored_files = {}
    
    for file_path in file_list:
        score = 0
        file_lower = file_path.lower()
        
        # Score by file extension
        if file_path.endswith('.py'):  # Python files get higher score for Flask issues
            score += 3
        elif any(file_path.endswith(ext) for ext in ['.js', '.java', '.go', '.ts']):
            score += 2
        elif any(file_path.endswith(ext) for ext in ['.yml', '.yaml', '.json', '.xml', '.conf']):
            score += 1
        
        # Score by component matches in path
        for term in search_terms:
            if term and len(term) > 2 and term.lower() in file_lower:
                score += 4
        
        # Important file patterns get extra points
        if any(pattern in file_lower for pattern in ['app.py', 'main.py', 'config.py', 'settings.py', 'database.py']):
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
        # Check if this is an API Gateway event with a body (webhook)
        if isinstance(event, dict) and 'body' in event:
            # Parse the body if it's a string
            try:
                body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
                
                # Check if this looks like a Datadog webhook
                if 'alert_type' in body and ('title' in body or 'hostname' in body):
                    logger.info("Detected Datadog webhook format")
                    
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
                    
                    # Extract components from the message
                    components = []
                    message_text = body.get('message', '')
                    components = re.findall(r'([A-Za-z][A-Za-z0-9]*(?:Service|API|App|Module))', message_text)
                    
                    # Plain description for better embedding
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
            import re
            
            # Extract code patterns (paths, functions) from <code> tags
            code_patterns = re.findall(r'<code>([^<]+)</code>', description)
            components.extend(code_patterns)
            
            # Extract error patterns from list items
            error_patterns = re.findall(r'<li>([^<]+)</li>', description)
            components.extend(error_patterns)
            
            # Extract plain text from HTML for better embedding
            plain_description = re.sub(r'<[^>]+>', ' ', description)
            plain_description = re.sub(r'\s+', ' ', plain_description).strip()
            
            # Extract potential keywords from title
            title_components = re.findall(r'([A-Za-z][A-Za-z0-9]*(?:Service|API|App|Module))', event.get('problemTitle', ''))
            components.extend(title_components)
            
            if "Flask" in description or "Flask" in event.get('problemTitle', ''):
                components.append("Flask")
                components.append("app.py")
                components.append("routes")
            
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
        
        # For custom events and fallbacks
        elif 'problem' in event:
            return event['problem']
        else:
            return {
                'title': event.get('title', 'Unknown Issue'),
                'severity': event.get('severity', 'UNKNOWN'),
                'impact': event.get('impact', 'Unknown Entity'),
                'description': event.get('description', 'No details available')
            }
    except Exception as e:
        logger.error(f"Error extracting problem info: {e}")
        return {
            'title': "Unknown Issue",
            'severity': "UNKNOWN", 
            'impact': "Unknown Entity",
            'description': "No details available"
        }

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
    """Filter files based on extensions of interest and problem context"""
    # Original list of extensions - keep this for backward compatibility
    extensions_of_interest = [
        '.py', '.js', '.java', '.go', '.ts', '.yaml', '.yml', 
        '.json', '.xml', '.sh', '.cs', '.cpp', '.h', '.jsx', 
        '.tsx', '.rb', '.php', '.tf', '.conf', '.properties'
    ]
    
    # Add language-agnostic files that are typically important
    important_files = [
        'Dockerfile', 'docker-compose', 'Makefile', 'README', 
        'app.py', 'main.py', 'index.', 'server.', 'config.', 'settings.',
        'requirements.txt', 'package.json', 'build.gradle'
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
