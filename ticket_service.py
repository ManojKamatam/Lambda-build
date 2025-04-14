import os
import json
import requests
import base64
from typing import Dict, List, Any, Optional

class TicketService:
    def __init__(self, ticket_type=None, **kwargs):
        self.ticket_type = ticket_type or os.environ.get("TICKET_TYPE", "jira")
        self.extra_params = kwargs or json.loads(os.environ.get("TICKET_PARAMS", "{}"))
        
        if self.ticket_type == "jira":
            self._init_jira()
        elif self.ticket_type == "ado":
            self._init_ado()
        else:
            raise ValueError(f"Unsupported ticket type: {self.ticket_type}")
    
    def _init_jira(self):
        """Initialize Jira client"""
        self.server = self.extra_params.get("server")
        self.username = self.extra_params.get("username")
        self.api_token = self.extra_params.get("api_token")
        self.project_key = self.extra_params.get("project_key")
        
        if not all([self.server, self.username, self.api_token, self.project_key]):
            raise ValueError("Jira requires 'server', 'username', 'api_token', and 'project_key' parameters")
        
        from jira import JIRA
        self.client = JIRA(
            server=self.server,
            basic_auth=(self.username, self.api_token)
        )
    
    def _init_ado(self):
        """Initialize Azure DevOps client"""
        self.organization = self.extra_params.get("organization")
        self.project = self.extra_params.get("project")
        self.token = self.extra_params.get("token")
        
        if not all([self.organization, self.project, self.token]):
            raise ValueError("ADO requires 'organization', 'project', and 'token' parameters")
        
        auth = base64.b64encode(f":{self.token}".encode()).decode()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json-patch+json"
        })
    
    def create_ticket(self, title: str, description: str, **kwargs) -> str:
        """Create a ticket in the ticket system"""
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
        """Create a ticket in Jira"""
        issue_dict = {
            'project': {'key': self.project_key},
            'summary': title,
            'description': description,
            'issuetype': {'name': kwargs.get('issue_type', 'Bug')}
        }
        
        # Add optional fields if provided
        if 'priority' in kwargs:
            issue_dict['priority'] = {'name': kwargs['priority']}
        if 'components' in kwargs:
            issue_dict['components'] = [{'name': c} for c in kwargs['components']]
        if 'labels' in kwargs:
            issue_dict['labels'] = kwargs['labels']
        
        issue = self.client.create_issue(fields=issue_dict)
        return issue.key
    
    def _jira_add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to a Jira ticket"""
        self.client.add_comment(ticket_id, comment)
        return True
    
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
            document.append({
                "op": "add",
                "path": "/fields/Microsoft.VSTS.Common.Priority",
                "value": kwargs['priority']
            })
        
        # Add tags if provided
        if 'tags' in kwargs:
            document.append({
                "op": "add",
                "path": "/fields/System.Tags",
                "value": "; ".join(kwargs['tags'])
            })
        
        response = self.session.post(
            f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/${work_item_type}",
            json=document,
            params={"api-version": "6.0"}
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to create work item: {response.text}")
        
        return str(response.json()["id"])
    
    def _ado_add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to an Azure DevOps work item"""
        data = {
            "text": comment
        }
        
        response = self.session.post(
            f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/{ticket_id}/comments",
            json=data,
            params={"api-version": "6.0-preview.3"}
        )
        
        return response.status_code == 200