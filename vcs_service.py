import requests
import json
import base64
import os
from typing import Dict, List, Optional, Any

class VCSService:
    def __init__(self, vcs_type=None, token=None, **kwargs):
        self.vcs_type = vcs_type or os.environ.get("VCS_TYPE", "github")
        self.token = token or os.environ.get("VCS_TOKEN")
        self.extra_params = kwargs or json.loads(os.environ.get("VCS_EXTRA_PARAMS", "{}"))
        
        # Initialize based on VCS type
        if self.vcs_type == "github":
            self._init_github()
        elif self.vcs_type == "ado":
            self._init_ado()
        elif self.vcs_type == "bitbucket":
            self._init_bitbucket()
        else:
            raise ValueError(f"Unsupported VCS type: {self.vcs_type}")
    
    def _init_github(self):
        """Initialize GitHub client"""
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        })
    
    def _init_ado(self):
        """Initialize Azure DevOps client"""
        self.organization = self.extra_params.get("organization")
        self.project = self.extra_params.get("project")
        
        if not self.organization or not self.project:
            raise ValueError("ADO requires 'organization' and 'project' parameters")
        
        auth = base64.b64encode(f":{self.token}".encode()).decode()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        })
    
    def _init_bitbucket(self):
        """Initialize Bitbucket client"""
        self.workspace = self.extra_params.get("workspace")
        
        if not self.workspace:
            raise ValueError("Bitbucket requires 'workspace' parameter")
        
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })
    
    def get_repository_files(self, repo: str, ref: str = "main") -> List[str]:
        """Get list of files in the repository"""
        if self.vcs_type == "github":
            return self._github_get_files(repo, ref)
        elif self.vcs_type == "ado":
            return self._ado_get_files(repo, ref)
        elif self.vcs_type == "bitbucket":
            return self._bitbucket_get_files(repo, ref)
    
    def get_file_content(self, repo: str, path: str, ref: str = "main") -> str:
        """Get content of a file from the repository"""
        if self.vcs_type == "github":
            return self._github_get_content(repo, path, ref)
        elif self.vcs_type == "ado":
            return self._ado_get_content(repo, path, ref)
        elif self.vcs_type == "bitbucket":
            return self._bitbucket_get_content(repo, path, ref)
    
    def create_branch(self, repo: str, branch_name: str, base_ref: str = "main") -> bool:
        """Create a new branch"""
        if self.vcs_type == "github":
            return self._github_create_branch(repo, branch_name, base_ref)
        elif self.vcs_type == "ado":
            return self._ado_create_branch(repo, branch_name, base_ref)
        elif self.vcs_type == "bitbucket":
            return self._bitbucket_create_branch(repo, branch_name, base_ref)
    
    def update_file(self, repo: str, path: str, content: str, commit_msg: str, branch: str) -> bool:
        """Update a file in the repository"""
        if self.vcs_type == "github":
            return self._github_update_file(repo, path, content, commit_msg, branch)
        elif self.vcs_type == "ado":
            return self._ado_update_file(repo, path, content, commit_msg, branch)
        elif self.vcs_type == "bitbucket":
            return self._bitbucket_update_file(repo, path, content, commit_msg, branch)
    
    def create_pull_request(self, repo: str, title: str, body: str, head: str, base: str = "main") -> str:
        """Create a pull request"""
        if self.vcs_type == "github":
            return self._github_create_pr(repo, title, body, head, base)
        elif self.vcs_type == "ado":
            return self._ado_create_pr(repo, title, body, head, base)
        elif self.vcs_type == "bitbucket":
            return self._bitbucket_create_pr(repo, title, body, head, base)
    
    # GitHub implementations
    def _github_get_files(self, repo: str, ref: str = "main") -> List[str]:
        """Get list of files from GitHub repository"""
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/git/trees/{ref}",
                params={"recursive": "1"}
            )
            
            if response.status_code == 200:
                data = response.json()
                return [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]
            
            # Try alternative branches if main doesn't exist
            alt_branches = ["master", "develop", "dev"]
            for branch in alt_branches:
                response = self.session.get(
                    f"https://api.github.com/repos/{repo}/git/trees/{branch}",
                    params={"recursive": "1"}
                )
                if response.status_code == 200:
                    data = response.json()
                    return [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]
            
            return []
        except Exception as e:
            print(f"Error getting GitHub files: {str(e)}")
            return []
    
    def _github_get_content(self, repo: str, path: str, ref: str = "main") -> str:
        """Get file content from GitHub"""
        response = self.session.get(
            f"https://api.github.com/repos/{repo}/contents/{path}",
            params={"ref": ref}
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get file: {response.json().get('message')}")
        
        content = response.json().get("content", "")
        return base64.b64decode(content).decode('utf-8')
    
    def _github_create_branch(self, repo: str, branch_name: str, base_ref: str = "main") -> bool:
        """Create a new branch in GitHub"""
        # Get the SHA of the base branch
        response = self.session.get(f"https://api.github.com/repos/{repo}/git/refs/heads/{base_ref}")
        
        if response.status_code != 200:
            # Try alternative base branches
            alt_branches = ["master", "develop", "dev"]
            for branch in alt_branches:
                response = self.session.get(f"https://api.github.com/repos/{repo}/git/refs/heads/{branch}")
                if response.status_code == 200:
                    base_ref = branch
                    break
            
            if response.status_code != 200:
                raise Exception(f"Failed to get base branch: {response.json().get('message')}")
        
        sha = response.json()["object"]["sha"]
        
        # Create the new branch
        response = self.session.post(
            f"https://api.github.com/repos/{repo}/git/refs",
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": sha
            }
        )
        
        return response.status_code == 201
    
    def _github_update_file(self, repo: str, path: str, content: str, commit_msg: str, branch: str) -> bool:
        """Update a file in GitHub"""
        # Get the current file to obtain its SHA
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/contents/{path}",
                params={"ref": branch}
            )
            current_sha = response.json().get("sha") if response.status_code == 200 else None
        except Exception:
            current_sha = None
        
        # Prepare the update payload
        data = {
            "message": commit_msg,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch
        }
        
        if current_sha:
            data["sha"] = current_sha
        
        # Update the file
        response = self.session.put(
            f"https://api.github.com/repos/{repo}/contents/{path}",
            json=data
        )
        
        return response.status_code in (200, 201)
    
    def _github_create_pr(self, repo: str, title: str, body: str, head: str, base: str = "main") -> str:
        """Create a pull request in GitHub"""
        response = self.session.post(
            f"https://api.github.com/repos/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base
            }
        )
        
        if response.status_code != 201:
            raise Exception(f"Failed to create PR: {response.json().get('message')}")
        
        return response.json()["html_url"]
    
    # ADO implementations would go here
    # Bitbucket implementations would go here