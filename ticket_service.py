import os
import json
import requests
import base64
import logging
import time
import uuid
from typing import Dict, List, Any, Optional, Union

# Set up logging with better formatting
logger = logging.getLogger(__name__)

class TicketService:
    def __init__(self, ticket_type=None, **kwargs):
        """Initialize ticket service with enhanced routing capabilities"""
        self.ticket_type = ticket_type or os.environ.get("TICKET_TYPE", "jira")
        self.extra_params = kwargs or json.loads(os.environ.get("TICKET_PARAMS", "{}"))
        
        # Configure importance thresholds for decision making
        self.thresholds = {
            "sprint_threshold": self.extra_params.get("sprint_threshold", 7),
            "backlog_threshold": self.extra_params.get("backlog_threshold", 4),
            "notification_threshold": self.extra_params.get("notification_threshold", 3)
        }
        
        # Configure webhook settings for notifications
        self.webhook_config = {
            "enabled": self.extra_params.get("webhook_enabled", False),
            "url": self.extra_params.get("webhook_url", ""),
            "channel": self.extra_params.get("webhook_channel", "alerts")
        }
        
        # AI-only section configuration
        self.ai_section = {
            "enabled": self.extra_params.get("ai_section_enabled", False),
            "jira_component": self.extra_params.get("ai_section_component", "AI-Generated"),
            "jira_label": self.extra_params.get("ai_section_label", "ai-created"),
            "ado_area_path": self.extra_params.get("ai_section_area_path", "AI\\Issues")
        }
        
        # Initialize appropriate client
        if self.ticket_type == "jira":
            self._init_jira()
        elif self.ticket_type == "ado":
            self._init_ado()
        else:
            raise ValueError(f"Unsupported ticket type: {self.ticket_type}")
        
        logger.info(f"Initialized TicketService with thresholds: {self.thresholds}")
    
    def _init_jira(self):
        """Initialize Jira client with board/sprint capabilities"""
        self.server = self.extra_params.get("server")
        self.username = self.extra_params.get("username")
        self.api_token = self.extra_params.get("api_token")
        self.project_key = self.extra_params.get("project_key")
        
        # Additional board/sprint parameters
        self.default_board = self.extra_params.get("default_board")
        self.default_sprint = self.extra_params.get("default_sprint")
        self.ai_sprint = self.extra_params.get("ai_sprint", self.default_sprint)
        
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
        if self.ai_section["enabled"]:
            logger.info(f"AI section enabled with component: {self.ai_section['jira_component']}")
    
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
                        all_sprints = self.client.sprints(board.id)
                        active_sprints = []
                        for sprint in all_sprints:
                            sprint_state = getattr(sprint, 'state', 'UNKNOWN')
                            sprint_name = getattr(sprint, 'name', 'UNNAMED')
                            
                            # Cache ALL sprints, not just active ones
                            self.sprints[sprint_name.lower()] = sprint.id
                            
                            if sprint_state.upper() == 'ACTIVE':
                                active_sprints.append(sprint_name)
                        
                        logger.info(f"Found {len(active_sprints)} active sprints: {', '.join(active_sprints)}")
            
            # Cache components to check if AI component exists
            if self.ai_section["enabled"]:
                self.components = {}
                for component in self.client.project_components(self.project_key):
                    self.components[component.name.lower()] = component.id
                    
                # Create AI component if it doesn't exist
                ai_component_name = self.ai_section["jira_component"]
                if ai_component_name.lower() not in self.components:
                    try:
                        component = self.client.create_component(name=ai_component_name, 
                                                               project=self.project_key,
                                                               description="Issues created by AI system")
                        logger.info(f"Created AI component: {ai_component_name}")
                        self.components[ai_component_name.lower()] = component.id
                    except Exception as e:
                        logger.warning(f"Could not create AI component: {str(e)}")
            
        except Exception as e:
            logger.warning(f"Error caching Jira metadata: {str(e)}")
            # Initialize empty dictionaries if caching fails
            self.issue_types = {}
            self.priorities = {}
            self.boards = {}
            self.sprints = {}
            self.components = {}
    
    def _init_ado(self):
        """Initialize Azure DevOps client with AI section support"""
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
        
        # Setup area path for AI section if enabled
        if self.ai_section["enabled"]:
            self._ensure_ado_area_path_exists(self.ai_section["ado_area_path"])
            
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
            
    def _ensure_ado_area_path_exists(self, area_path):
        """Ensure the specified area path exists in Azure DevOps"""
        try:
            # This is a simplified implementation - actual implementation would
            # involve checking if the area path exists and creating it if needed
            logger.info(f"Ensuring area path exists: {area_path}")
            # In a real implementation, you would call the ADO API to create the area path
            return True
        except Exception as e:
            logger.warning(f"Error creating area path: {str(e)}")
            return False
    
    def create_ticket(self, title: str, description: str, **kwargs) -> Union[str, Dict[str, Any]]:
        """
        Create a ticket with intelligent routing based on issue importance
        
        Args:
            title: Issue title/summary
            description: Issue description/details
            **kwargs: Additional parameters including:
                - decision_type: fix_code, investigation_needed, add_ticket, notification_only
                - severity: CRITICAL, MAJOR, MINOR, TRIVIAL
                - data_sufficiency: 0-10 indicating how complete the data is (10 = complete)
                - components: List of components to assign
                - labels: List of labels to add
        
        Returns:
            Union[str, Dict[str, Any]]: Ticket ID or notification response
        """
        # Generate unique request ID for tracking
        request_id = kwargs.get("request_id", str(uuid.uuid4())[:8])
        logger.info(f"[{request_id}] Processing ticket creation request: {title}")
        
        # Auto-detect issue type if not provided
        if 'issue_type' not in kwargs and 'work_item_type' not in kwargs:
            issue_type = self.determine_issue_type(title, description)
            kwargs['issue_type'] = issue_type
            kwargs['work_item_type'] = issue_type
            logger.info(f"[{request_id}] Auto-detected issue type: {issue_type}")
        
        # Get decision type - default to "add_ticket" if not specified
        decision_type = kwargs.pop("decision_type", "add_ticket")
        
        # Calculate importance of the issue
        importance = self._calculate_importance(title, description, **kwargs)
        logger.info(f"[{request_id}] Calculated importance score: {importance}/10")
        
        # Check data sufficiency factor
        data_sufficiency = kwargs.get("data_sufficiency", 10)  # Default: full data
        if data_sufficiency < 5:
            logger.warning(f"[{request_id}] Limited data available (score: {data_sufficiency}/10)")
            # Adjust importance if data is insufficient unless it's critical 
            if importance < 8:
                adjusted_importance = max(importance - (10 - data_sufficiency) // 2, 1)
                logger.info(f"[{request_id}] Adjusted importance due to insufficient data: {importance} → {adjusted_importance}")
                importance = adjusted_importance
        
        # Determine where to add the ticket based on decision type and importance
        target_location = self._determine_ticket_location(decision_type, importance)
        logger.info(f"[{request_id}] Determined ticket target: {target_location}")
        
        # If notification only, don't create a ticket
        if target_location == "notification_only":
            logger.info(f"[{request_id}] Issue deemed common/low priority - sending notification only")
            notification_result = self._send_webhook_notification(
                title=title,
                description=description,
                importance=importance,
                decision_type=decision_type,
                **kwargs
            )
            return {"status": "notification_sent", "details": notification_result}
        
        # Add AI section information if enabled
        if self.ai_section["enabled"]:
            if self.ticket_type == "jira":
                # Add AI component
                if "components" not in kwargs:
                    kwargs["components"] = []
                if self.ai_section["jira_component"] not in kwargs["components"]:
                    kwargs["components"].append(self.ai_section["jira_component"])
                
                # Add AI label
                if "labels" not in kwargs:
                    kwargs["labels"] = []
                if self.ai_section["jira_label"] not in kwargs["labels"]:
                    kwargs["labels"].append(self.ai_section["jira_label"])
            elif self.ticket_type == "ado":
                # Set area path for ADO
                kwargs["area_path"] = self.ai_section["ado_area_path"]
        
        # Create the ticket in the system
        try:
            if self.ticket_type == "jira":
                ticket_id = self._jira_create_ticket(title, description, **kwargs)
            elif self.ticket_type == "ado":
                ticket_id = self._ado_create_ticket(title, description, **kwargs)
            
            # Route the ticket based on determined location
            routing_result = False
            if target_location == "sprint":
                sprint_name = kwargs.get('sprint', self.default_sprint)
                logger.info(f"[{request_id}] Adding ticket {ticket_id} to sprint based on decision: {decision_type}")
                routing_result = self._add_issue_to_sprint(ticket_id, sprint_name)
            elif target_location == "backlog":
                logger.info(f"[{request_id}] Adding ticket {ticket_id} to backlog based on decision: {decision_type}")
                routing_result = self._ensure_issue_in_backlog(ticket_id)
            
            # Add a specific comment noting AI creation and routing decision
            self.add_comment(ticket_id, (
                f"This issue was automatically created by the AI system.\n"
                f"- Decision type: {decision_type}\n"
                f"- Importance score: {importance}/10\n"
                f"- Target location: {target_location}\n"
                f"- Data sufficiency: {data_sufficiency}/10"
            ))
            
            # Send additional notification for high-importance issues
            if importance >= 8:
                self._send_webhook_notification(
                    title=f"[HIGH IMPORTANCE] {title}",
                    description=f"A high importance ticket has been created and added to {target_location}.\n\n{description}",
                    ticket_id=ticket_id,
                    importance=importance,
                    decision_type=decision_type,
                    **kwargs
                )
            
            return ticket_id
            
        except Exception as e:
            error_msg = f"[{request_id}] Error creating ticket: {str(e)}"
            logger.error(error_msg)
            
            # Send error notification
            self._send_webhook_notification(
                title=f"[ERROR] Failed to create ticket: {title}",
                description=f"Error: {str(e)}\n\nOriginal description: {description}",
                importance=importance,
                decision_type=decision_type,
                **kwargs
            )
            
            raise Exception(error_msg)
    
    def _calculate_importance(self, title: str, description: str, **kwargs) -> int:
        """
        Calculate importance score (0-10) based on multiple factors
        
        Considers:
        - Explicit severity rating
        - Keywords indicating urgency
        - Service criticality
        - Error pattern recognition
        - Impact scope
        """
        score = 5  # Default medium importance
        
        # Factor in explicitly provided severity
        severity = kwargs.get("severity", "").upper()
        if severity == "CRITICAL":
            score += 3
        elif severity == "MAJOR" or severity == "HIGH":
            score += 2
        elif severity == "MINOR" or severity == "LOW":
            score -= 1
        elif severity == "TRIVIAL":
            score -= 2
        
        # Check title and description for urgent keywords
        text = (title + " " + description).lower()
        
        # Critical issues that need immediate attention
        critical_terms = ["security breach", "data loss", "outage", "vulnerability", 
                          "production down", "customer impact", "money loss", "critical failure"]
        
        # Important but not necessarily critical
        urgent_terms = ["urgent", "broken", "crash", "failure", "error", "exception", 
                        "malfunction", "corrupt", "degraded"]
        
        # Less urgent issues
        minor_terms = ["improvement", "enhancement", "suggestion", "typo", "cosmetic", 
                       "documentation", "clarification"]
        
        # Add points for critical terms (max +4)
        critical_points = 0
        for term in critical_terms:
            if term in text:
                critical_points += 2
                if critical_points >= 4:
                    break
        score += critical_points
        
        # Add points for urgent terms (max +3)
        urgent_points = 0
        for term in urgent_terms:
            if term in text:
                urgent_points += 1
                if urgent_points >= 3:
                    break
        score += urgent_points
        
        # Subtract points for minor terms (max -2)
        minor_points = 0
        for term in minor_terms:
            if term in text:
                minor_points += 1
                if minor_points >= 2:
                    break
        score -= minor_points
        
        # Factor in service criticality if provided
        service_criticality = kwargs.get("service_criticality", 0)
        if service_criticality > 0:
            # Add up to 2 points for critical services
            score += min(service_criticality // 5, 2)
        
        # Consider scope of impact
        if "scope" in kwargs:
            scope = kwargs["scope"].lower()
            if scope in ["global", "all users", "all customers"]:
                score += 2
            elif scope in ["multiple users", "some customers", "region"]:
                score += 1
            elif scope in ["single user", "one customer", "edge case"]:
                score -= 1
        
        # Consider frequency
        if "frequency" in kwargs:
            frequency = kwargs["frequency"].lower()
            if frequency in ["constant", "continuous", "always"]:
                score += 2
            elif frequency in ["frequent", "often", "regular"]:
                score += 1
            elif frequency in ["rare", "occasional", "seldom"]:
                score -= 1
        
        # Cap score between 0-10
        return min(max(score, 0), 10)

    def _determine_ticket_location(self, decision_type: str, importance: int) -> str:
        """
        Determine where a ticket should be routed based on decision type and importance
        
        Args:
            decision_type: The type of decision (fix_code, investigation_needed, add_ticket)
            importance: The calculated importance score (0-10)
            
        Returns:
            str: "sprint", "backlog", or "notification_only"
        """
        # Get configured thresholds
        sprint_threshold = self.thresholds["sprint_threshold"]
        backlog_threshold = self.thresholds["backlog_threshold"]
        notification_threshold = self.thresholds["notification_threshold"]
        
        # Decision matrix based on type and importance
        if decision_type == "fix_code":
            # Code fix tickets go directly to sprint for immediate attention
            return "sprint"
        
        elif decision_type == "investigation_needed":
            # Investigation tickets go to sprint only if very important
            if importance >= sprint_threshold:
                return "sprint"
            elif importance >= backlog_threshold:
                return "backlog"
            else:
                return "notification_only"
        
        elif decision_type == "add_ticket":
            # Regular tickets are routed based on importance
            if importance >= sprint_threshold:
                return "sprint"
            elif importance >= backlog_threshold:
                return "backlog"
            else:
                return "notification_only"
        
        # Explicit notification only or very low importance
        elif decision_type == "notification_only" or importance <= notification_threshold:
            return "notification_only"
        
        # Default to backlog for unknown decision types
        return "backlog"

    def add_to_board(self, ticket_id: str, label: str) -> bool:
        """
        Add a ticket to either the sprint or backlog based on label
        
        Args:
            ticket_id: The ID of the created ticket
            label: The label, typically "current-sprint" or "backlog"
        
        Returns:
            bool: True if the operation was successful
        """
        logger.info(f"Explicitly adding ticket {ticket_id} to {label}")
        
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
                # Get the current iteration
                active_iterations = self._get_ado_active_iterations()
                if active_iterations:
                    iteration_path = active_iterations[0].get('path', self.default_iteration)
                    
                    # Update the work item's iteration path
                    document = [
                        {
                            "op": "add",
                            "path": "/fields/System.IterationPath",
                            "value": iteration_path
                        }
                    ]
                    
                    response = self.session.patch(
                        f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/{ticket_id}",
                        json=document,
                        params={"api-version": "6.0"}
                    )
                    
                    if response.status_code == 200:
                        logger.info(f"Added work item {ticket_id} to current iteration")
                        return True
                    else:
                        logger.warning(f"Failed to update iteration path: {response.text}")
                        return False
                else:
                    logger.warning(f"No active iterations found")
                    return False
            else:
                # For backlog in ADO, remove from any iteration
                document = [
                    {
                        "op": "add",
                        "path": "/fields/System.IterationPath",
                        "value": self.project  # Root project = backlog
                    }
                ]
                
                response = self.session.patch(
                    f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/{ticket_id}",
                    json=document,
                    params={"api-version": "6.0"}
                )
                
                if response.status_code == 200:
                    logger.info(f"Added work item {ticket_id} to backlog")
                    return True
                else:
                    logger.warning(f"Failed to update iteration path: {response.text}")
                    return False
        
        return False
    
    def _send_webhook_notification(self, title: str, description: str, **kwargs) -> Dict[str, Any]:
        """
        Send a notification to configured webhook (Slack, Teams, etc.)
        
        Args:
            title: Notification title
            description: Notification body
            **kwargs: Additional fields to include
            
        Returns:
            Dict with notification status
        """
        if not self.webhook_config["enabled"] or not self.webhook_config["url"]:
            logger.info(f"Webhook notifications disabled or URL not configured")
            return {"status": "skipped", "reason": "Webhooks not configured"}
        
        try:
            # Determine notification color based on importance
            importance = kwargs.get("importance", 5)
            if importance >= 8:
                color = "#FF0000"  # Red
            elif importance >= 6:
                color = "#FFA500"  # Orange
            elif importance >= 4:
                color = "#FFFF00"  # Yellow
            else:
                color = "#00FF00"  # Green
            
            # Truncate description if too long
            max_desc_length = 1000
            if len(description) > max_desc_length:
                description = description[:max_desc_length] + "... [truncated]"
            
            # Prepare webhook payload (generic format - customize as needed)
            payload = {
                "channel": self.webhook_config["channel"],
                "username": "AI Ticket System",
                "attachments": [
                    {
                        "title": title,
                        "text": description,
                        "color": color,
                        "fields": [
                            {
                                "title": "Importance",
                                "value": f"{importance}/10",
                                "short": True
                            },
                            {
                                "title": "Decision",
                                "value": kwargs.get("decision_type", "Unknown"),
                                "short": True
                            }
                        ]
                    }
                ]
            }
            
            # Add ticket ID if available
            if "ticket_id" in kwargs:
                payload["attachments"][0]["fields"].append({
                    "title": "Ticket ID",
                    "value": kwargs["ticket_id"],
                    "short": True
                })
            
            # Send the webhook
            response = requests.post(
                self.webhook_config["url"],
                json=payload,
                timeout=5
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Webhook notification sent successfully")
                return {"status": "success", "response_code": response.status_code}
            else:
                logger.warning(f"Webhook notification failed: {response.status_code} - {response.text}")
                return {"status": "error", "response_code": response.status_code, "details": response.text}
        
        except Exception as e:
            logger.error(f"Error sending webhook notification: {str(e)}")
            return {"status": "error", "exception": str(e)}

    def determine_issue_type(self, title: str, description: str) -> str:
        """Intelligently determine the appropriate issue type based on content"""
        text = (title + " " + description).lower()
        
        # Bug indicators with expanded patterns
        if any(term in text for term in ['bug', 'error', 'fix', 'broken', 'crash', 'failure', 'exception',
                                         'not working', 'doesn\'t work', 'issue', 'problem', 'defect',
                                         'malfunction', 'incorrect', 'unexpected', 'wrong']):
            return 'Bug'
        
        # Feature indicators
        if any(term in text for term in ['new feature', 'add capability', 'implement', 'create new', 
                                        'develop', 'feature', 'new functionality']):
            return 'Story'  # or 'New Feature' depending on your Jira setup
        
        # Improvement indicators
        if any(term in text for term in ['improve', 'enhance', 'upgrade', 'optimize', 'refactor',
                                        'performance', 'better', 'faster']):
            return 'Improvement'
        
        # Default fallback based on ticket system
        if self.ticket_type == 'jira':
            return 'Story'  # Common default for Jira
        else:
            return 'Task'   # Common default for Azure DevOps
            
    def _jira_create_ticket(self, title: str, description: str, **kwargs) -> str:
        """Create a ticket in Jira with board/sprint support"""
        request_id = kwargs.get("request_id", str(uuid.uuid4())[:8])
        
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
                priorities = self.client.priorities()
                priority_names = [p.name for p in priorities]
                
                if kwargs['priority'] in priority_names:
                    issue_dict['priority'] = {'name': kwargs['priority']}
                else:
                    logger.warning(f"[{request_id}] Priority '{kwargs['priority']}' not found")
        except Exception as e:
            logger.warning(f"[{request_id}] Could not set priority: {e}")
        
        # Add components if provided
        if 'components' in kwargs and kwargs['components']:
            issue_dict['components'] = [{'name': c} for c in kwargs['components']]
        
        # Add labels if provided
        if 'labels' in kwargs and kwargs['labels']:
            issue_dict['labels'] = kwargs['labels']
        
        # Create the issue
        try:
            issue = self.client.create_issue(fields=issue_dict)
            logger.info(f"[{request_id}] Created Jira issue {issue.key} - {title}")
            
            return issue.key
            
        except Exception as e:
            logger.error(f"[{request_id}] Error creating Jira ticket: {e}")
            raise

    def _ensure_issue_in_backlog(self, issue_key):
        """Ensure an issue is in the backlog (not in any sprint)"""
        try:
            # Check if the issue is in any active sprints
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
                        break
                except Exception as e:
                    logger.warning(f"Error checking sprint {sprint['name']}: {str(e)}")
            
            if not issue_removed:
                logger.info(f"Issue {issue_key} is already in backlog")
            
            return True
        except Exception as e:
            logger.error(f"Error ensuring issue in backlog: {e}")
            return False

    def _add_issue_to_sprint(self, issue_key, sprint_name):
        """Add a Jira issue to a sprint"""
        try:
            # Handle backlog case
            if sprint_name.lower() == "backlog":
                self.client.move_to_backlog([issue_key])
                logger.info(f"Moved issue {issue_key} to backlog")
                return True
            
            # Find sprint ID from cache or lookup
            sprint_id = None
            if hasattr(self, 'sprints') and self.sprints:
                sprint_id = self.sprints.get(sprint_name.lower())
            
            # If not found in cache, search for it
            if not sprint_id:
                board_id = None
                if hasattr(self, 'boards') and self.boards:
                    board_id = self.boards.get(self.default_board.lower())
                
                if board_id:
                    all_sprints = self.client.sprints(board_id)
                    for sprint in all_sprints:
                        if hasattr(sprint, 'name') and sprint.name.lower() == sprint_name.lower():
                            sprint_id = sprint.id
                            break
            
            if sprint_id:
                # Move to backlog first to avoid multiple sprint assignments
                try:
                    self.client.move_to_backlog([issue_key])
                except Exception as e:
                    logger.warning(f"Could not move issue to backlog first: {str(e)}")
                
                # Add to target sprint
                self.client.add_issues_to_sprint(sprint_id, [issue_key])
                logger.info(f"Added issue {issue_key} to sprint {sprint_name}")
                return True
            else:
                logger.warning(f"Could not find sprint '{sprint_name}', issue remains in backlog")
                return False
        
        except Exception as e:
            logger.error(f"Error managing issue sprint: {e}")
            return False

    def add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to a ticket"""
        if self.ticket_type == "jira":
            return self._jira_add_comment(ticket_id, comment)
        elif self.ticket_type == "ado":
            return self._ado_add_comment(ticket_id, comment)
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
        """Create a work item in Azure DevOps"""
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
        
        # Add priority if provided
        if 'priority' in kwargs:
            priority_mapping = {
                'critical': 1, 'highest': 1, 'high': 1,
                'medium': 2, 'normal': 2,
                'low': 3, 'lowest': 4
            }
            
            priority_text = kwargs['priority'].lower()
            priority_value = priority_mapping.get(priority_text, 2)
            
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
        
        # Add to iteration if specified
        iteration = kwargs.get('iteration', self.default_iteration)
        if iteration:
            document.append({
                "op": "add",
                "path": "/fields/System.IterationPath",
                "value": f"{self.project}\\{iteration}"
            })
        
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

    def _get_jira_active_sprints(self):
        """Get active sprints from Jira"""
        try:
            active_sprints = []
            
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
            
    def get_active_sprints(self):
        """Get list of all active sprints/iterations"""
        if self.ticket_type == "jira":
            return self._get_jira_active_sprints()
        elif self.ticket_type == "ado":
            return self._get_ado_active_iterations()
        return []
        
    def _get_ado_active_iterations(self):
        """Get active iterations from Azure DevOps"""
        try:
            active_iterations = []
            
            response = self.session.get(
                f"https://dev.azure.com/{self.organization}/{self.project}/_apis/work/teamsettings/iterations",
                params={"$timeframe": "current", "api-version": "6.0"}
            )
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('value', []):
                    active_iterations.append({
                        'id': item['id'],
                        'name': item['name'],
                        'path': item.get('path', '')
                    })
                    
            return active_iterations
        except Exception as e:
            logger.error(f"Error getting active iterations: {e}")
            return []
