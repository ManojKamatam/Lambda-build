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
        # ... [ADO initialization code remains similar] ...
        
        # Setup area path for AI section if enabled
        if self.ai_section["enabled"]:
            self._ensure_ado_area_path_exists(self.ai_section["ado_area_path"])
    
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
    
    # [Rest of the methods remain similar with possible tweaks for enterprise use]

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
