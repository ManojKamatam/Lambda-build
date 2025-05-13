import os
import json
import requests
import base64
import logging
from typing import Dict, List, Any, Optional

# Set up logging
logger = logging.getLogger(__name__)

class TicketService:
    def __init__(self, ticket_type=None, **kwargs):
        """Initialize ticket service with enhanced capabilities for board management"""
        self.ticket_type = ticket_type or os.environ.get("TICKET_TYPE", "jira")
        self.extra_params = kwargs or json.loads(os.environ.get("TICKET_PARAMS", "{}"))
        
        if self.ticket_type == "jira":
            self._init_jira()
        elif self.ticket_type == "ado":
            self._init_ado()
        else:
            raise ValueError(f"Unsupported ticket type: {self.ticket_type}")
    
    def _init_jira(self):
        """Initialize Jira client with board/sprint capabilities"""
        self.server = self.extra_params.get("server")
        self.username = self.extra_params.get("username")
        self.api_token = self.extra_params.get("api_token")
        self.project_key = self.extra_params.get("project_key")
        
        # Additional board/sprint parameters
        self.default_board = self.extra_params.get("default_board")
        self.default_sprint = self.extra_params.get("default_sprint")
        self.assign_to_sprint = self.extra_params.get("assign_to_sprint", False)
        
        if not all([self.server, self.username, self.api_token, self.project_key]):
            raise ValueError("Jira requires 'server', 'username', 'api_token', and 'project_key' parameters")
        
        from jira import JIRA
        self.client = JIRA(
            server=self.server,
            basic_auth=(self.username, self.api_token)
        )
        
        # Cache available issue types, priorities, and boards
        self._cache_jira_metadata()
        
        logger.info(f"Initialized Jira client for project {self.project_key}")
        if self.default_board:
            logger.info(f"Default board: {self.default_board}")
        if self.default_sprint:
            logger.info(f"Default sprint: {self.default_sprint}")
    
    def _cache_jira_metadata(self):
        """Cache Jira metadata for faster ticket creation"""
        try:
            # Cache issue types
            self.issue_types = {}
            for issue_type in self.client.issue_types():
                self.issue_types[issue_type.name.lower()] = issue_type.id
            
            # Cache priorities
            self.priorities = {}
            for priority in self.client.priorities():
                self.priorities[priority.name.lower()] = priority.id
            
            # Cache boards if default board is specified
            self.boards = {}
            self.sprints = {}
            
            if self.default_board:
                for board in self.client.boards():
                    self.boards[board.name.lower()] = board.id
                    
                    if board.name.lower() == self.default_board.lower():
                        # Log all sprints for debugging
                        all_sprints = self.client.sprints(board.id)
                        logger.info(f"Found {len(all_sprints)} total sprints for board {board.name}")
                        
                        # Log details of each sprint
                        for sprint in all_sprints:
                            sprint_state = getattr(sprint, 'state', 'UNKNOWN')
                            sprint_name = getattr(sprint, 'name', 'UNNAMED')
                            logger.info(f"Sprint: {sprint_name}, State: {sprint_state}, ID: {getattr(sprint, 'id', 'NONE')}")
                            
                            # Cache ALL sprints, not just active ones
                            self.sprints[sprint_name.lower()] = sprint.id
                
                logger.info(f"Cached {len(self.sprints)} active sprints for board {self.default_board}")
            
            logger.info(f"Cached {len(self.issue_types)} issue types and {len(self.priorities)} priorities")
            
        except Exception as e:
            logger.warning(f"Error caching Jira metadata: {str(e)}")
            # Initialize empty dictionaries if caching fails
            self.issue_types = {}
            self.priorities = {}
            self.boards = {}
            self.sprints = {}
    
    def _init_ado(self):
        """Initialize Azure DevOps client with iteration support"""
        self.organization = self.extra_params.get("organization")
        self.project = self.extra_params.get("project")
        self.token = self.extra_params.get("token")
        
        # Additional parameters for sprint/iteration support
        self.default_iteration = self.extra_params.get("default_iteration")
        self.default_area = self.extra_params.get("default_area")
        
        if not all([self.organization, self.project, self.token]):
            raise ValueError("ADO requires 'organization', 'project', and 'token' parameters")
        
        auth = base64.b64encode(f":{self.token}".encode()).decode()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json-patch+json"
        })
        
        # Cache work item types and iterations
        self._cache_ado_metadata()
        
        logger.info(f"Initialized Azure DevOps client for project {self.project}")
        if self.default_iteration:
            logger.info(f"Default iteration: {self.default_iteration}")
    
    def _cache_ado_metadata(self):
        """Cache Azure DevOps metadata for faster ticket creation"""
        try:
            # Cache work item types
            response = self.session.get(
                f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitemtypes",
                params={"api-version": "6.0"}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.work_item_types = {}
                for item in data.get('value', []):
                    self.work_item_types[item['name'].lower()] = item['referenceName']
                
                logger.info(f"Cached {len(self.work_item_types)} work item types from Azure DevOps")
            
            # Cache iterations if default is specified
            if self.default_iteration:
                response = self.session.get(
                    f"https://dev.azure.com/{self.organization}/{self.project}/_apis/work/teamsettings/iterations",
                    params={"api-version": "6.0"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.iterations = {}
                    for item in data.get('value', []):
                        self.iterations[item['name'].lower()] = item['id']
                    
                    logger.info(f"Cached {len(self.iterations)} iterations from Azure DevOps")
            
        except Exception as e:
            logger.warning(f"Error caching Azure DevOps metadata: {str(e)}")
            # Initialize empty dictionaries if caching fails
            self.work_item_types = {}
            self.iterations = {}
    
    def determine_issue_type(self, title: str, description: str) -> str:
        """Intelligently determine the appropriate issue type based on content"""
        text = (title + " " + description).lower()
        
        # Bug indicators
        if any(term in text for term in ['bug', 'error', 'fix', 'broken', 'crash', 'failure', 'exception',
                                         'not working', 'doesn\'t work', 'issue', 'problem']):
            return 'Bug'
        
        # Feature indicators
        if any(term in text for term in ['new feature', 'add capability', 'implement', 'create new', 
                                        'develop', 'feature', 'new functionality']):
            return 'Story'  # or 'New Feature' depending on your Jira setup
        
        # Improvement indicators
        if any(term in text for term in ['improve', 'enhance', 'upgrade', 'optimize', 'refactor',
                                        'performance', 'better', 'faster']):
            return 'Improvement'
        
        # Epic indicators (large initiatives)
        if any(term in text for term in ['initiative', 'platform', 'system', 'large scale',
                                        'multi-phase', 'strategic', 'epic']):
            return 'Epic'
        
        # Task indicators
        if any(term in text for term in ['task', 'chore', 'update', 'maintenance', 'documentation']):
            return 'Task'
            
        # Default fallback based on ticket system
        if self.ticket_type == 'jira':
            return 'Story'  # Common default for Jira
        else:
            return 'Task'   # Common default for Azure DevOps
    
    def create_ticket(self, title: str, description: str, **kwargs) -> str:
        """Create a ticket in the ticket system with enhanced board support"""
        # Auto-detect issue type if not provided
        if 'issue_type' not in kwargs and 'work_item_type' not in kwargs:
            issue_type = self.determine_issue_type(title, description)
            kwargs['issue_type'] = issue_type
            kwargs['work_item_type'] = issue_type
            logger.info(f"Auto-detected issue type: {issue_type}")
        
        if self.ticket_type == "jira":
            return self._jira_create_ticket(title, description, **kwargs)
        elif self.ticket_type == "ado":
            return self._ado_create_ticket(title, description, **kwargs)
    
    def add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to a ticket"""
        if self.ticket_type == "jira":
            return self._jira_add_comment(ticket_id, comment)
        elif self.ticket_type == "ado":
            return self._ado_add_comment(ticket_id, comment)
    
    def _jira_create_ticket(self, title: str, description: str, **kwargs) -> str:
        """Create a ticket in Jira with board/sprint support"""
        # Prepare issue dictionary
        issue_dict = {
            'project': {'key': self.project_key},
            'summary': title,
            'description': description,
            'issuetype': {'name': kwargs.get('issue_type', 'Bug')}
        }
        
        # Add priority with better error handling
        try:
            if 'priority' in kwargs:
                # First check if specified priority exists
                priorities = self.client.priorities()
                priority_names = [p.name for p in priorities]
                
                if kwargs['priority'] in priority_names:
                    issue_dict['priority'] = {'name': kwargs['priority']}
                else:
                    logger.warning(f"Priority '{kwargs['priority']}' not found in Jira. Available priorities: {priority_names}")
        except Exception as e:
            logger.warning(f"Could not set priority: {e}")
        
        # Add components if provided
        if 'components' in kwargs and kwargs['components']:
            issue_dict['components'] = [{'name': c} for c in kwargs['components']]
        
        # Add labels if provided
        if 'labels' in kwargs and kwargs['labels']:
            issue_dict['labels'] = kwargs['labels']
        
        # Create the issue
        try:
            issue = self.client.create_issue(fields=issue_dict)
            logger.info(f"Created Jira issue {issue.key} - {title}")
            
            # Add to sprint if specified or configured to do so by default
            sprint_name = kwargs.get('sprint', self.default_sprint if self.assign_to_sprint else None)
            
            if sprint_name:
                logger.info(f"Attempting to add ticket to sprint: {sprint_name}")
                self._add_issue_to_sprint(issue.key, sprint_name)
            else:
                logger.info(f"Ticket created in backlog (no sprint specified)")
            
            return issue.key
            
        except Exception as e:
            logger.error(f"Error creating Jira ticket: {e}")
            raise

    def add_to_board(self, ticket_id: str, label: str) -> bool:
        """
        Add a ticket to either the sprint or backlog based on label
        
        Args:
            ticket_id: The ID of the created ticket
            label: The label, typically "current-sprint" or "backlog"
        
        Returns:
            bool: True if the operation was successful
        """
        # For Jira
        if self.ticket_type == "jira":
            # If label is current-sprint, add to active sprint
            if label == "current-sprint":
                # Find the default or first active sprint
                sprint_name = self.default_sprint
                if not sprint_name:
                    active_sprints = self._get_jira_active_sprints()
                    if active_sprints:
                        sprint_name = active_sprints[0]['name']
                
                if sprint_name:
                    return self._add_issue_to_sprint(ticket_id, sprint_name)
                else:
                    logger.warning(f"No active sprint found, ticket {ticket_id} remains in backlog")
                    return False
            else:
                # For backlog, ensure it's removed from any sprints
                result = self._ensure_issue_in_backlog(ticket_id)
                return result
        
        # For Azure DevOps
        elif self.ticket_type == "ado":
            # Similar logic for ADO
            if label == "current-sprint" and self.default_iteration:
                # Implementation would use ADO API to update iteration path
                # This is a simplified placeholder
                return True
            else:
                return True
        
        return False
    
    def _ensure_issue_in_backlog(self, issue_key):
        """Ensure an issue is in the backlog (not in any sprint)"""
        try:
            # Check if the issue is in any active sprints using JQL search instead of sprint_issues
            active_sprints = self._get_jira_active_sprints()
            issue_removed = False
            
            for sprint in active_sprints:
                try:
                    # Get issues in sprint using JQL
                    sprint_issues_jql = f'sprint = {sprint["id"]} AND key = {issue_key}'
                    issues_in_sprint = self.client.search_issues(sprint_issues_jql)
                    
                    # If the issue is in this sprint, remove it
                    if issues_in_sprint.total > 0:
                        self.client.move_to_backlog([issue_key])
                        logger.info(f"Removed issue {issue_key} from sprint {sprint['name']}")
                        issue_removed = True
                        break  # No need to check other sprints once removed
                except Exception as e:
                    logger.warning(f"Error checking sprint {sprint['name']}: {str(e)}")
            
            if not issue_removed:
                logger.info(f"Issue {issue_key} is already in backlog")
            
            return True
        except Exception as e:
            logger.error(f"Error ensuring issue in backlog: {e}")
            return False
    
    def _add_issue_to_sprint(self, issue_key, sprint_name):
        """Add a Jira issue to a sprint using proper API calls"""
        try:
            # If sprint_name is "backlog", use move_to_backlog method
            if sprint_name.lower() == "backlog":
                self.client.move_to_backlog([issue_key])
                logger.info(f"Issue SCRUM-{issue_key} is already in backlog")
                return True
            
            # Find sprint ID
            sprint_id = None
            
            # Check if we have cached sprints
            if hasattr(self, 'sprints') and self.sprints:
                sprint_id = self.sprints.get(sprint_name.lower())
            
            # If not found in cache, look up sprints
            if not sprint_id:
                # First find the board
                board_id = None
                board_name = self.default_board
                
                if board_name:
                    # Try cached boards first
                    if hasattr(self, 'boards') and self.boards:
                        board_id = self.boards.get(board_name.lower())
                    
                    # If not found, query boards
                    if not board_id:
                        boards = self.client.boards()
                        for board in boards:
                            if board.name.lower() == board_name.lower():
                                board_id = board.id
                                break
                
                # If board found, look for the sprint
                if board_id:
                    all_sprints = self.client.sprints(board_id)
                    logger.info(f"Found {len(all_sprints)} total sprints")
                    
                    for sprint in all_sprints:
                        if hasattr(sprint, 'name') and sprint.name.lower() == sprint_name.lower():
                            # Remove the ACTIVE requirement
                            sprint_id = sprint.id
                            sprint_state = getattr(sprint, 'state', 'UNKNOWN')
                            logger.info(f"Found sprint {sprint_name} with state {sprint_state}")
                            break
            
            if sprint_id:
                # Move issue to backlog first to avoid having it in multiple sprints
                try:
                    self.client.move_to_backlog([issue_key])
                except Exception as e:
                    logger.warning(f"Could not move issue to backlog first (may already be there): {str(e)}")
                
                # Now add to the target sprint
                self.client.add_issues_to_sprint(sprint_id, [issue_key])
                logger.info(f"Added issue {issue_key} to sprint {sprint_name}")
                return True
            else:
                logger.warning(f"Could not find active sprint named '{sprint_name}', issue remains in backlog")
                return False
        
        except Exception as e:
            logger.error(f"Error managing issue sprint: {e}")
            return False
    
    def _jira_add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to a Jira ticket"""
        try:
            self.client.add_comment(ticket_id, comment)
            logger.info(f"Added comment to Jira issue {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Error adding comment to Jira ticket {ticket_id}: {e}")
            return False
    
    def _ado_create_ticket(self, title: str, description: str, **kwargs) -> str:
        """Create a work item in Azure DevOps with iteration support"""
        work_item_type = kwargs.get('work_item_type', 'Bug')
        
        document = [
            {
                "op": "add",
                "path": "/fields/System.Title",
                "value": title
            },
            {
                "op": "add",
                "path": "/fields/System.Description",
                "value": description
            }
        ]
        
        # Add priority if provided, with mapping to ADO system
        if 'priority' in kwargs:
            # Map textual priorities to Azure DevOps numerical system
            priority_mapping = {
                'critical': 1, 'highest': 1, 'high': 1,
                'medium': 2, 'normal': 2,
                'low': 3, 'lowest': 4
            }
            
            priority_text = kwargs['priority'].lower()
            priority_value = priority_mapping.get(priority_text, 2)  # Default to Medium (2)
            
            document.append({
                "op": "add",
                "path": "/fields/Microsoft.VSTS.Common.Priority",
                "value": priority_value
            })
        
        # Add tags if provided
        if 'tags' in kwargs:
            document.append({
                "op": "add",
                "path": "/fields/System.Tags",
                "value": "; ".join(kwargs['tags'])
            })
        
        # Add to iteration (sprint) if specified
        iteration = kwargs.get('iteration', self.default_iteration)
        if iteration:
            document.append({
                "op": "add",
                "path": "/fields/System.IterationPath",
                "value": f"{self.project}\\{iteration}"
            })
            logger.info(f"Assigning work item to iteration: {iteration}")
        else:
            logger.info(f"Work item will be created in backlog (no iteration specified)")
        
        response = self.session.post(
            f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/${work_item_type}",
            json=document,
            params={"api-version": "6.0"}
        )
        
        if response.status_code != 200:
            error_message = f"Failed to create work item: {response.text}"
            logger.error(error_message)
            raise Exception(error_message)
        
        return str(response.json()["id"])
    
    def _ado_add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to an Azure DevOps work item"""
        try:
            data = {
                "text": comment
            }
            
            response = self.session.post(
                f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/{ticket_id}/comments",
                json=data,
                params={"api-version": "6.0-preview.3"}
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to add comment: {response.text}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return False
            
    def get_active_sprints(self):
        """Get list of all active sprints/iterations"""
        if self.ticket_type == "jira":
            return self._get_jira_active_sprints()
        elif self.ticket_type == "ado":
            return self._get_ado_active_iterations()
        return []
        
    def _get_jira_active_sprints(self):
        """Get active sprints from Jira"""
        try:
            active_sprints = []
            
            # Get all boards for the project
            boards = [b for b in self.client.boards() 
                     if hasattr(b, 'location') and 
                     hasattr(b.location, 'projectKey') and 
                     b.location.projectKey == self.project_key]
                     
            for board in boards:
                for sprint in self.client.sprints(board.id):
                    if hasattr(sprint, 'state') and sprint.state.upper() == 'ACTIVE':
                        active_sprints.append({
                            'id': sprint.id,
                            'name': sprint.name,
                            'board_name': board.name
                        })
                        
            return active_sprints
        except Exception as e:
            logger.error(f"Error getting active sprints: {e}")
            return []
            
    def _get_ado_active_iterations(self):
        """Get active iterations from Azure DevOps"""
        try:
            # Implementation depends on your ADO setup
            # Basic implementation would query iterations API
            pass
        except Exception as e:
            logger.error(f"Error getting active iterations: {e}")
            return []
