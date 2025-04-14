import json
import os
import logging
import boto3
import datetime
import numpy as np
from opensearch_service import OpenSearchService
from vcs_service import VCSService
from apm_service import APMService
from ai_service import AIService
from ticket_service import TicketService

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add this near the top of lambda_function.py
def get_secrets():
    """Retrieve secrets from AWS Secrets Manager"""
    import boto3
    import json
    
    secret_name = "ai-incident-response-secrets"
    region_name = os.environ.get("AWS_REGION", "us-east-1")
    
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        logger.error(f"Error retrieving secrets: {str(e)}")
        # Return empty dict as fallback
        return {}
    
    # Decrypts secret using the associated KMS key if it exists
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    else:
        logger.error("Secret is in binary format, not supported")
        return {}

# Load secrets on module initialization
try:
    secrets = get_secrets()
except Exception as e:
    logger.warning(f"Could not load secrets, using fallbacks: {str(e)}")
    secrets = {}

# Environment configuration - now using secrets with fallbacks
ANTHROPIC_API_KEY = secrets.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
VCS_TYPE = os.environ.get("VCS_TYPE", "github")
VCS_TOKEN = secrets.get("VCS_TOKEN") or os.environ.get("VCS_TOKEN")
VCS_EXTRA_PARAMS = json.loads(secrets.get("VCS_EXTRA_PARAMS", "{}")) or json.loads(os.environ.get("VCS_EXTRA_PARAMS", "{}"))
OPENSEARCH_ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT")
ENABLE_APM_TOOLS = os.environ.get("ENABLE_APM_TOOLS", "true").lower() == "true"
APM_TYPE = os.environ.get("APM_TYPE", "dynatrace")
APM_API_KEY = secrets.get("APM_API_KEY") or os.environ.get("APM_API_KEY")
APM_EXTRA_PARAMS = json.loads(secrets.get("APM_EXTRA_PARAMS", "{}")) or json.loads(os.environ.get("APM_EXTRA_PARAMS", "{}"))
TICKET_TYPE = os.environ.get("TICKET_TYPE", "jira")
TICKET_PARAMS = json.loads(secrets.get("TICKET_PARAMS", "{}")) or json.loads(os.environ.get("TICKET_PARAMS", "{}"))
NOTIFICATION_WEBHOOK = secrets.get("NOTIFICATION_WEBHOOK") or os.environ.get("NOTIFICATION_WEBHOOK")

def lambda_handler(event, context):
    """Main Lambda handler"""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Initialize services
        vcs_service = VCSService()
        ai_service = AIService(ANTHROPIC_API_KEY)
        opensearch_service = OpenSearchService(OPENSEARCH_ENDPOINT) if OPENSEARCH_ENDPOINT else None
        apm_service = APMService() if ENABLE_APM_TOOLS else None
        ticket_service = TicketService()
        
        # Extract problem information
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
        
        # Get a list of repository files
        repo = f"{repo_info['owner']}/{repo_info['repo']}"
        file_list = vcs_service.get_repository_files(repo)
        
        # Filter files by extensions to reduce the search space
        filtered_files = filter_files_by_extensions(file_list)
        
        # Get content for a subset of files for embedding
        file_contents = {}
        for file_path in filtered_files[:50]:  # Limit to 50 files for embedding
            try:
                content = vcs_service.get_file_content(repo, file_path)
                file_contents[file_path] = content
            except Exception as e:
                logger.debug(f"Failed to get file {file_path}: {str(e)}")
        
        # Create problem text for embedding
        problem_text = f"{problem_info.get('title', '')}\n{problem_info.get('description', '')}"
        
        # Get vectors for problem and files
        problem_embedding = ai_service.get_embeddings([problem_text])[0]
        
        # Calculate embeddings for files
        file_embeddings = []
        file_paths = []
        
        for file_path, content in file_contents.items():
            # Use first 1000 chars as a sample
            file_embedding = ai_service.get_embeddings([content[:1000]])[0]
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
        
        # Get top relevant files
        if similarities:
            top_indices = np.argsort(similarities)[::-1][:10]  # Top 10 files
            relevant_file_paths = [file_paths[i] for i in top_indices]
        else:
            relevant_file_paths = []
        
        logger.info(f"Found {len(relevant_file_paths)} relevant files")
        
        # Get content for relevant files
        relevant_files = {}
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
            except Exception as e:
                logger.warning(f"Failed to store vectors in OpenSearch: {str(e)}")
        
        # Analyze the problem
        if ENABLE_APM_TOOLS and apm_service:
            analysis = ai_service.analyze_problem_with_tools(problem_info, relevant_files, apm_service)
        else:
            analysis = ai_service.analyze_problem(problem_info, relevant_files)
        
        logger.info(f"AI analysis result: {json.dumps(analysis)}")
        
        # Process based on analysis
        action = analysis.get('action', 'needs_more_info')
        
        if action == 'fix_code':
            # Switch to Claude Sonnet for code generation
            updated_files = ai_service.generate_code_fix(problem_info, relevant_files, analysis)
            
            if not updated_files:
                send_notification("No File Updates Generated", 
                                 f"AI analysis suggested a code fix but no updates were generated for: {problem_info.get('title')}")
                return {
                    'statusCode': 200,
                    'body': json.dumps('No file updates were generated')
                }
            
            # Create branch, update files, and create PR
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            branch_name = f"ai-fix-{timestamp}"
            
            # Create branch
            vcs_service.create_branch(repo, branch_name, repo_info.get('default_branch', 'main'))
            
            # Update files
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
            ticket_details = ai_service.create_ticket_details(problem_info, analysis)
            
            ticket_id = ticket_service.create_ticket(
                ticket_details.get('title', problem_info.get('title', 'Issue from alert')),
                ticket_details.get('description', 'No description provided'),
                priority=ticket_details.get('priority', 'Medium'),
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
            ticket_id = ticket_service.create_ticket(
                f"Investigation Needed: {problem_info.get('title', 'Alert')}",
                f"""
                This alert requires more information to determine the appropriate action.
                
                Problem: {problem_info.get('title')}
                Severity: {problem_info.get('severity')}
                
                AI Analysis: {analysis.get('explanation')}
                
                Needed Information: {analysis.get('details', {}).get('needed_info', 'Additional context is required')}
                """,
                priority="Medium",
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

def extract_problem_info(event):
    """Extract problem information from the event"""
    # For Dynatrace alerts
    if 'ProblemTitle' in event:
        return {
            'title': event.get('ProblemTitle', 'Unknown Issue'),
            'severity': event.get('ProblemSeverity', 'UNKNOWN'),
            'impact': event.get('ImpactedEntity', 'Unknown Entity'),
            'description': event.get('ProblemDetails', {}).get('problemDetailsSections', [{}])[0].get('content', 'No details available')
        }
    # For custom events
    elif 'problem' in event:
        return event['problem']
    # Default structure
    else:
        return {
            'title': event.get('title', 'Unknown Issue'),
            'severity': event.get('severity', 'UNKNOWN'),
            'impact': event.get('impact', 'Unknown Entity'),
            'description': event.get('description', 'No details available')
        }

def extract_repo_info(event):
    """Extract repository information from the event"""
    if 'repository' in event:
        return event['repository']
    else:
        return {
            'owner': event.get('repo_owner'),
            'repo': event.get('repo_name'),
            'default_branch': event.get('default_branch', 'main')
        }

def filter_files_by_extensions(file_list):
    """Filter files based on extensions of interest"""
    extensions_of_interest = [
        '.py', '.js', '.java', '.go', '.ts', '.yaml', '.yml', 
        '.json', '.xml', '.sh', '.cs', '.cpp', '.h', '.jsx', 
        '.tsx', '.rb', '.php', '.tf', '.conf', '.properties'
    ]
    
    return [f for f in file_list if any(f.endswith(ext) for ext in extensions_of_interest)]

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
