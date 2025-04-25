# vcs_service.py
import re
import requests
import json
import base64
import os
import logging
from typing import Dict, List, Optional, Any
import datetime
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class VCSService:
    def __init__(self, vcs_type=None, token=None, **kwargs):
        """
        Initialize VCS service based on environment variables
        
        Args:
            vcs_type: The type of VCS provider (github, bitbucket, ado, gitlab)
            token: Authentication token
            **kwargs: Additional provider-specific parameters
        """
        # Get configuration from params or environment variables
        self.vcs_type = vcs_type or os.environ.get("VCS_TYPE", "github").lower()
        self.token = token or os.environ.get("VCS_TOKEN")
        self.extra_params = kwargs or json.loads(os.environ.get("VCS_EXTRA_PARAMS", "{}"))
        
        # Force lowercase for consistent matching
        self.vcs_type = self.vcs_type.lower()
        
        # Add VCS provider name logging
        logger.info(f"Initializing VCS service for provider: {self.vcs_type}")
        
        # Initialize provider-specific clients and settings
        if self.vcs_type == "github":
            self._init_github()
        elif self.vcs_type in ["ado", "azure", "azuredevops"]:
            self._init_ado()
        elif self.vcs_type == "bitbucket":
            self._init_bitbucket()
        elif self.vcs_type == "gitlab":
            self._init_gitlab()
        else:
            raise ValueError(f"Unsupported VCS provider type: {self.vcs_type}")
    
    def _init_github(self):
        """Initialize GitHub client"""
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        })
        self.api_base_url = "https://api.github.com"
        logger.info("GitHub client initialized")
    
    def _init_ado(self):
        """Initialize Azure DevOps client"""
        self.organization = self.extra_params.get("organization")
        self.project = self.extra_params.get("project")
        
        if not self.organization or not self.project:
            raise ValueError("Azure DevOps requires 'organization' and 'project' parameters in VCS_EXTRA_PARAMS")
        
        auth = base64.b64encode(f":{self.token}".encode()).decode()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        })
        self.api_base_url = f"https://dev.azure.com/{self.organization}/{self.project}"
        logger.info(f"Azure DevOps client initialized for org: {self.organization}, project: {self.project}")
    
    def _init_bitbucket(self):
        """Initialize Bitbucket client"""
        self.workspace = self.extra_params.get("workspace")
        
        if not self.workspace:
            raise ValueError("Bitbucket requires 'workspace' parameter in VCS_EXTRA_PARAMS")
        
        # Get username from extra params or environment
        self.username = self.extra_params.get("username") or os.environ.get("BITBUCKET_USERNAME", "")
        
        # Validate we have required credentials
        if not self.username or not self.token:
            logger.error("Missing Bitbucket credentials: username or token is empty")
        else:
            logger.info(f"Using Bitbucket authentication with username: {self.username}")
        
        self.session = requests.Session()
        
        # If we have a username, use Basic Auth with app password (no spaces allowed in username)
        if self.username:
            # Remove any whitespace from username and token
            username = self.username.strip()
            token = self.token.strip() if self.token else ""
            
            # Use Basic Authentication with app password
            auth = f"{username}:{token}"
            auth_encoded = base64.b64encode(auth.encode()).decode()
            self.session.headers.update({
                "Authorization": f"Basic {auth_encoded}",
                "Content-Type": "application/json"
            })
        else:
            # Fall back to Bearer token (OAuth)
            self.session.headers.update({
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            })
        
        self.api_base_url = "https://api.bitbucket.org/2.0"
        logger.info(f"Bitbucket client initialized for workspace: {self.workspace}")
    
    def _init_gitlab(self):
        """Initialize GitLab client"""
        self.gitlab_url = self.extra_params.get("gitlab_url", "https://gitlab.com")
        
        self.session = requests.Session()
        self.session.headers.update({
            "Private-Token": self.token
        })
        self.api_base_url = f"{self.gitlab_url}/api/v4"
        logger.info(f"GitLab client initialized, API URL: {self.api_base_url}")
    
    def authenticate(self) -> bool:
        """Test authentication with the VCS provider"""
        try:
            if self.vcs_type == "github":
                response = self.session.get(f"{self.api_base_url}/user")
                return response.status_code == 200
                
            elif self.vcs_type in ["ado", "azure", "azuredevops"]:
                response = self.session.get(f"{self.api_base_url}/_apis/projects?api-version=6.0")
                return response.status_code == 200
                
            elif self.vcs_type == "bitbucket":
                response = self.session.get(f"{self.api_base_url}/workspaces/{self.workspace}")
                return response.status_code == 200
                
            elif self.vcs_type == "gitlab":
                response = self.session.get(f"{self.api_base_url}/user")
                return response.status_code == 200
                
            return False
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
    def verify_repository_access(self, repo: str) -> bool:
        """Verify that the repository exists and is accessible"""
        try:
            url = f"{self.api_base_url}/repos/{repo}"
            logger.info(f"Checking repository existence at: {url}")
            
            response = self.session.get(url)
            
            if response.status_code == 200:
                logger.info(f"Repository {repo} exists and is accessible")
                return True
            else:
                error_message = response.json().get("message", "Unknown error")
                logger.error(f"Repository access error: {error_message}")
                return False
        except Exception as e:
            logger.error(f"Error verifying repository access: {str(e)}")
            return False
    
    def check_token_permissions(self) -> Dict[str, bool]:
        """Check permissions of the current token"""
        try:
            response = self.session.get(f"{self.api_base_url}/user")
            if response.status_code != 200:
                logger.error("Token authentication failed")
                return {"authenticated": False}
                
            # Get scopes from headers
            scopes = response.headers.get("X-OAuth-Scopes", "").split(", ")
            
            permissions = {
                "authenticated": True,
                "repo_read": "repo" in scopes or "public_repo" in scopes,
                "repo_write": "repo" in scopes,
                "user_read": "read:user" in scopes or "user" in scopes
            }
            
            logger.info(f"Token permissions: {permissions}")
            return permissions
        except Exception as e:
            logger.error(f"Error checking token permissions: {str(e)}")
            return {"authenticated": False}
    
    def check_repository_content(self, repo: str, ref: str) -> bool:
        """Check if repository has content via direct API call"""
        try:
            url = f"{self.api_base_url}/repos/{repo}/contents"
            logger.info(f"Checking repository contents at: {url}")
            
            response = self.session.get(
                url,
                params={"ref": ref}
            )
            
            logger.info(f"Repository contents response status: {response.status_code}")
            
            if response.status_code == 200:
                contents = response.json()
                if isinstance(contents, list):
                    logger.info(f"Repository contains {len(contents)} items at root level")
                    if len(contents) > 0:
                        logger.info(f"Sample items: {[item.get('name') for item in contents[:5]]}")
                    return len(contents) > 0
                else:
                    logger.error(f"Unexpected response format: {type(contents)}")
                    return False
            else:
                error_message = response.json().get("message", "Unknown error")
                logger.error(f"Error checking repository contents: {error_message}")
                return False
        except Exception as e:
            logger.error(f"Exception checking repository contents: {str(e)}")
            return False
    
    def get_default_branch(self, repo: str) -> str:
        """Get the default branch for a repository"""
        try:
            url = f"{self.api_base_url}/repos/{repo}"
            response = self.session.get(url)
            
            if response.status_code == 200:
                default_branch = response.json().get("default_branch", "main")
                logger.info(f"Repository default branch: {default_branch}")
                return default_branch
            else:
                logger.error(f"Error getting repository info: {response.text}")
                return "main"  # Fallback to main
        except Exception as e:
            logger.error(f"Exception getting default branch: {str(e)}")
            return "main"
    
    def check_rate_limit(self) -> Dict[str, Any]:
        """Check GitHub API rate limit status"""
        try:
            response = self.session.get(f"{self.api_base_url}/rate_limit")
            
            if response.status_code == 200:
                limit_info = response.json()
                core_limit = limit_info.get("resources", {}).get("core", {})
                
                remaining = core_limit.get("remaining", 0)
                limit = core_limit.get("limit", 0)
                reset_time = datetime.fromtimestamp(core_limit.get("reset", 0)).strftime('%Y-%m-%d %H:%M:%S')
                
                rate_info = {
                    "limit": limit,
                    "remaining": remaining,
                    "reset_time": reset_time
                }
                
                logger.info(f"GitHub API rate limit: {remaining}/{limit}, resets at {reset_time}")
                return rate_info
            else:
                logger.error(f"Error checking rate limit: {response.text}")
                return {"error": "Failed to check rate limit"}
        except Exception as e:
            logger.error(f"Exception checking rate limit: {str(e)}")
            return {"error": str(e)}
    
    def get_repository_files(self, repo: str, ref: str = None) -> List[str]:
        """
        Get list of files in the repository
        
        Args:
            repo: Repository identifier (e.g., "owner/repo")
            ref: Branch/tag reference (if None, uses default branch)
        
        Returns:
            List of file paths
        """
        # If ref is not provided, use environment variable or fall back to 'main'
        if ref is None:
            ref = os.environ.get("REPO_DEFAULT_BRANCH", "main")
            
        logger.info(f"Getting repository files for {repo}, ref: {ref}")
        
        try:
            if self.vcs_type == "github":
                return self._github_get_files(repo, ref)
            elif self.vcs_type in ["ado", "azure", "azuredevops"]:
                return self._ado_get_files(repo, ref)
            elif self.vcs_type == "bitbucket":
                return self._bitbucket_get_files(repo, ref)
            elif self.vcs_type == "gitlab":
                return self._gitlab_get_files(repo, ref)
            
            return []
        except Exception as e:
            logger.error(f"Error getting repository files: {str(e)}")
            return []
    
    def get_file_content(self, repo: str, path: str, ref: str = None) -> str:
        """
        Get content of a file from the repository
        
        Args:
            repo: Repository identifier (e.g., "owner/repo")
            path: File path within the repository
            ref: Branch/tag reference (if None, uses default branch)
            
        Returns:
            File content as string
        """
        # If ref is not provided, use environment variable or fall back to 'main'
        if ref is None:
            ref = os.environ.get("REPO_DEFAULT_BRANCH", "main")
            
        try:
            if self.vcs_type == "github":
                return self._github_get_content(repo, path, ref)
            elif self.vcs_type in ["ado", "azure", "azuredevops"]:
                return self._ado_get_content(repo, path, ref)
            elif self.vcs_type == "bitbucket":
                return self._bitbucket_get_content(repo, path, ref)
            elif self.vcs_type == "gitlab":
                return self._gitlab_get_content(repo, path, ref)
            
            raise ValueError(f"Unsupported VCS provider: {self.vcs_type}")
        except Exception as e:
            logger.error(f"Error getting file content for {path}: {str(e)}")
            raise
    
    def create_branch(self, repo: str, branch_name: str, base_ref: str = None) -> bool:
        """
        Create a new branch
        
        Args:
            repo: Repository identifier (e.g., "owner/repo")
            branch_name: Name for the new branch
            base_ref: Base branch/reference (if None, uses default branch)
            
        Returns:
            True if successful
        """
        # If base_ref is not provided, use environment variable or fall back to 'main'
        if base_ref is None:
            base_ref = os.environ.get("REPO_DEFAULT_BRANCH", "main")
            
        logger.info(f"Creating branch {branch_name} from {base_ref} in {repo}")
        
        try:
            if self.vcs_type == "github":
                return self._github_create_branch(repo, branch_name, base_ref)
            elif self.vcs_type in ["ado", "azure", "azuredevops"]:
                return self._ado_create_branch(repo, branch_name, base_ref)
            elif self.vcs_type == "bitbucket":
                return self._bitbucket_create_branch(repo, branch_name, base_ref)
            elif self.vcs_type == "gitlab":
                return self._gitlab_create_branch(repo, branch_name, base_ref)
            
            raise ValueError(f"Unsupported VCS provider: {self.vcs_type}")
        except Exception as e:
            logger.error(f"Error creating branch {branch_name}: {str(e)}")
            raise
    
    def update_file(self, repo: str, path: str, content: str, commit_msg: str, branch: str) -> bool:
        """
        Update a file in the repository
        
        Args:
            repo: Repository identifier (e.g., "owner/repo")
            path: File path within the repository
            content: New file content
            commit_msg: Commit message
            branch: Branch name
            
        Returns:
            True if successful
        """
        logger.info(f"Updating file {path} in {repo} on branch {branch}")
        
        try:
            if self.vcs_type == "github":
                return self._github_update_file(repo, path, content, commit_msg, branch)
            elif self.vcs_type in ["ado", "azure", "azuredevops"]:
                return self._ado_update_file(repo, path, content, commit_msg, branch)
            elif self.vcs_type == "bitbucket":
                return self._bitbucket_update_file(repo, path, content, commit_msg, branch)
            elif self.vcs_type == "gitlab":
                return self._gitlab_update_file(repo, path, content, commit_msg, branch)
            
            raise ValueError(f"Unsupported VCS provider: {self.vcs_type}")
        except Exception as e:
            logger.error(f"Error updating file {path}: {str(e)}")
            raise
    
    def create_pull_request(self, repo: str, title: str, body: str, head: str, base: str = None) -> str:
        """
        Create a pull request
        
        Args:
            repo: Repository identifier (e.g., "owner/repo")
            title: PR title
            body: PR description
            head: Source branch
            base: Target branch (if None, uses default branch)
            
        Returns:
            PR URL or identifier
        """
        # If base is not provided, use environment variable or fall back to 'main'
        if base is None:
            base = os.environ.get("REPO_DEFAULT_BRANCH", "main")
            
        logger.info(f"Creating PR from {head} to {base} in {repo}")
        
        try:
            if self.vcs_type == "github":
                return self._github_create_pr(repo, title, body, head, base)
            elif self.vcs_type in ["ado", "azure", "azuredevops"]:
                return self._ado_create_pr(repo, title, body, head, base)
            elif self.vcs_type == "bitbucket":
                return self._bitbucket_create_pr(repo, title, body, head, base)
            elif self.vcs_type == "gitlab":
                return self._gitlab_create_pr(repo, title, body, head, base)
            
            raise ValueError(f"Unsupported VCS provider: {self.vcs_type}")
        except Exception as e:
            logger.error(f"Error creating PR: {str(e)}")
            raise
            
    def _github_get_files(self, repo: str, ref: str) -> List[str]:
        """Get list of files from GitHub repository"""
        all_files = []
        
        try:
            # Try to use recursive tree API to get all files at once (most efficient)
            url = f"{self.api_base_url}/repos/{repo}/git/trees/{ref}"
            logger.info(f"Making GitHub API request to: {url}")
            
            response = self.session.get(
                url,
                params={"recursive": "1"}
            )
            
            logger.info(f"GitHub API response status: {response.status_code}")
            
            if response.status_code != 200:
                error_message = response.json().get("message", "Unknown error")
                logger.error(f"GitHub API error: {error_message}")
                
                # Check common error conditions
                if "Not Found" in error_message:
                    logger.error(f"Repository {repo} not found, branch {ref} not found, or token lacks access")
                elif "API rate limit exceeded" in error_message:
                    logger.error(f"GitHub API rate limit exceeded")
                elif "No commit found for ref" in error_message:
                    logger.error(f"Branch or reference '{ref}' not found")
                    
                # Try direct contents API as fallback
                logger.info("Trying alternate contents API as fallback")
                return self._github_get_contents_alternative(repo, ref)
                
            if response.status_code == 200:
                data = response.json()
                if data.get("truncated", False):
                    logger.warning("Repository tree is truncated, results may be incomplete")
                    
                files = [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]
                logger.info(f"GitHub API returned {len(files)} files")
                
                # Log a sample of files
                if files:
                    logger.info(f"Sample files: {files[:5]}")
                
                return files
            
            # If we get here, try iterative approach
            logger.info("Using iterative approach to get files")
            self._github_get_directory_contents(repo, "", ref, all_files)
            logger.info(f"Iterative approach found {len(all_files)} files")
            return all_files
            
        except Exception as e:
            logger.error(f"Error getting GitHub files: {str(e)}")
            # Try contents API as last resort
            return self._github_get_contents_alternative(repo, ref)
    
    def _github_get_contents_alternative(self, repo: str, ref: str) -> List[str]:
        """Alternative method to get files using contents API"""
        logger.info(f"Using alternative contents API to get files")
        all_files = []
        
        try:
            response = self.session.get(
                f"{self.api_base_url}/repos/{repo}/contents",
                params={"ref": ref}
            )
            
            if response.status_code != 200:
                logger.error(f"Alternative method failed with status {response.status_code}")
                return []
                
            items = response.json()
            if not isinstance(items, list):
                logger.error(f"Expected list response but got {type(items)}")
                return []
                
            # Process root items
            for item in items:
                if item["type"] == "file":
                    all_files.append(item["path"])
                elif item["type"] == "dir":
                    # Need to make additional requests for directories
                    self._github_get_directory_contents(repo, item["path"], ref, all_files)
                    
            logger.info(f"Alternative method found {len(all_files)} files")
            return all_files
        except Exception as e:
            logger.error(f"Error in alternative file retrieval: {str(e)}")
            return []
    
    def _github_get_directory_contents(self, repo: str, path: str, ref: str, all_files: List[str]):
        """Recursively get all files in a GitHub directory"""
        url = f"{self.api_base_url}/repos/{repo}/contents/{path}"
        response = self.session.get(url, params={"ref": ref})
        
        if response.status_code != 200:
            return
        
        items = response.json()
        if not isinstance(items, list):
            return
        
        for item in items:
            if item["type"] == "file":
                all_files.append(item["path"])
            elif item["type"] == "dir":
                self._github_get_directory_contents(repo, item["path"], ref, all_files)
    
    def _github_get_content(self, repo: str, path: str, ref: str) -> str:
        """Get file content from GitHub"""
        response = self.session.get(
            f"{self.api_base_url}/repos/{repo}/contents/{path}",
            params={"ref": ref}
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get file: {response.json().get('message')}")
        
        content = response.json().get("content", "")
        return base64.b64decode(content).decode('utf-8')
    
    def _github_create_branch(self, repo: str, branch_name: str, base_ref: str) -> bool:
        """Create a new branch in GitHub"""
        # Get the SHA of the base branch
        response = self.session.get(f"{self.api_base_url}/repos/{repo}/git/refs/heads/{base_ref}")
        
        if response.status_code != 200:
            # Try alternative base branches
            alt_branches = ["master", "develop", "dev"]
            for branch in alt_branches:
                response = self.session.get(f"{self.api_base_url}/repos/{repo}/git/refs/heads/{branch}")
                if response.status_code == 200:
                    base_ref = branch
                    break
            
            if response.status_code != 200:
                raise Exception(f"Failed to get base branch: {response.json().get('message')}")
        
        sha = response.json()["object"]["sha"]
        
        # Create the new branch
        response = self.session.post(
            f"{self.api_base_url}/repos/{repo}/git/refs",
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
                f"{self.api_base_url}/repos/{repo}/contents/{path}",
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
            f"{self.api_base_url}/repos/{repo}/contents/{path}",
            json=data
        )
        
        return response.status_code in (200, 201)
    
    def _github_create_pr(self, repo: str, title: str, body: str, head: str, base: str) -> str:
        """Create a pull request in GitHub"""
        response = self.session.post(
            f"{self.api_base_url}/repos/{repo}/pulls",
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
    
    # ADO (Azure DevOps) methods
    def _ado_get_files(self, repo: str, ref: str) -> List[str]:
        """Get list of files from Azure DevOps repository"""
        all_files = []
        
        try:
            # Make API call to get repository items
            response = self.session.get(
                f"{self.api_base_url}/_apis/git/repositories/{repo}/items",
                params={
                    "recursionLevel": "Full",
                    "versionDescriptor.version": ref,
                    "versionDescriptor.versionType": "branch",
                    "api-version": "6.0"
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                # Filter out folders, only include files
                return [item["path"] for item in data.get("value", []) if item.get("isFolder", True) == False]
            else:
                logger.warning(f"ADO API returned status code {response.status_code}: {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting ADO files: {str(e)}")
            return []
    
    def _ado_get_content(self, repo: str, path: str, ref: str) -> str:
        """Get file content from Azure DevOps"""
        response = self.session.get(
            f"{self.api_base_url}/_apis/git/repositories/{repo}/items",
            params={
                "path": path,
                "versionDescriptor.version": ref,
                "includeContent": "true",
                "api-version": "6.0"
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get file: {response.text}")
        
        return response.text
    
    def _ado_create_branch(self, repo: str, branch_name: str, base_ref: str) -> bool:
        """Create a new branch in Azure DevOps"""
        # Get the object ID of the base branch
        response = self.session.get(
            f"{self.api_base_url}/_apis/git/repositories/{repo}/refs",
            params={
                "filter": f"heads/{base_ref}",
                "api-version": "6.0"
            }
        )
        
        if response.status_code != 200 or not response.json().get("value"):
            raise Exception(f"Failed to get base branch: {response.text}")
        
        base_object_id = response.json()["value"][0]["objectId"]
        
        # Create the new branch
        data = {
            "name": f"refs/heads/{branch_name}",
            "oldObjectId": "0000000000000000000000000000000000000000",
            "newObjectId": base_object_id
        }
        
        response = self.session.post(
            f"{self.api_base_url}/_apis/git/repositories/{repo}/refs",
            json=[data],
            params={"api-version": "6.0"}
        )
        
        return response.status_code == 200
    
    def _ado_update_file(self, repo: str, path: str, content: str, commit_msg: str, branch: str) -> bool:
        """Update a file in Azure DevOps"""
        # ADO requires more complex API calls for updates, using a push operation
        # First, get the latest commit on the branch
        response = self.session.get(
            f"{self.api_base_url}/_apis/git/repositories/{repo}/refs",
            params={
                "filter": f"heads/{branch}",
                "api-version": "6.0"
            }
        )
        
        if response.status_code != 200 or not response.json().get("value"):
            raise Exception(f"Failed to get branch reference: {response.text}")
        
        old_object_id = response.json()["value"][0]["objectId"]
        
        # Create a push with the changes
        push_data = {
            "refUpdates": [
                {
                    "name": f"refs/heads/{branch}",
                    "oldObjectId": old_object_id
                }
            ],
            "commits": [
                {
                    "comment": commit_msg,
                    "changes": [
                        {
                            "changeType": "edit",
                            "item": {
                                "path": path
                            },
                            "newContent": {
                                "content": content,
                                "contentType": "rawtext"
                            }
                        }
                    ]
                }
            ]
        }
        
        response = self.session.post(
            f"{self.api_base_url}/_apis/git/repositories/{repo}/pushes",
            json=push_data,
            params={"api-version": "6.0"}
        )
        
        return response.status_code == 201
    
    def _ado_create_pr(self, repo: str, title: str, body: str, head: str, base: str) -> str:
        """Create a pull request in Azure DevOps"""
        data = {
            "sourceRefName": f"refs/heads/{head}",
            "targetRefName": f"refs/heads/{base}",
            "title": title,
            "description": body
        }
        
        response = self.session.post(
            f"{self.api_base_url}/_apis/git/repositories/{repo}/pullrequests",
            json=data,
            params={"api-version": "6.0"}
        )
        
        if response.status_code != 201:
            raise Exception(f"Failed to create PR: {response.text}")
        
        return response.json()["url"]
    
    # Bitbucket methods
    def _bitbucket_get_files(self, repo: str, ref: str) -> List[str]:
        """Get list of files from Bitbucket repository"""
        all_files = []
        
        try:
            # Start with the root directory
            self._bitbucket_get_directory_contents(repo, "", ref, all_files)
            return all_files
        except Exception as e:
            logger.error(f"Error getting Bitbucket files: {str(e)}")
            return []
    
    def _bitbucket_get_directory_contents(self, repo: str, path: str, ref: str, all_files: List[str]):
        """Recursively get all files in a Bitbucket directory"""
        url = f"{self.api_base_url}/repositories/{self.workspace}/{repo}/src/{ref}/{path}"
        logger.info(f"Bitbucket API request: {url}")
        response = self.session.get(url)
        logger.info(f"Bitbucket response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Bitbucket API error: {response.text}")
            return
        
        data = response.json()
        
        # Process files
        for item in data.get("values", []):
            if item["type"] == "commit_file":
                full_path = path + "/" + item["path"] if path else item["path"]
                all_files.append(full_path)
            elif item["type"] == "commit_directory":
                dir_path = path + "/" + item["path"] if path else item["path"]
                self._bitbucket_get_directory_contents(repo, dir_path, ref, all_files)
    
    def _bitbucket_get_content(self, repo: str, path: str, ref: str) -> str:
        """Get file content from Bitbucket"""
        response = self.session.get(
            f"{self.api_base_url}/repositories/{self.workspace}/{repo}/src/{ref}/{path}"
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get file: {response.text}")
        
        return response.text
    
    def _bitbucket_create_branch(self, repo: str, branch_name: str, base_ref: str) -> bool:
        """Create a new branch in Bitbucket"""
        data = {
            "name": branch_name,
            "target": {
                "hash": base_ref
            }
        }
        
        response = self.session.post(
            f"{self.api_base_url}/repositories/{self.workspace}/{repo}/refs/branches",
            json=data
        )
        
        return response.status_code == 201
    
    def _bitbucket_update_file(self, repo: str, path: str, content: str, commit_msg: str, branch: str) -> bool:
        """
        Update a file in Bitbucket with a generic implementation that works for any file type.
        Ensures proper API formatting for reliable updates.
        """
        change_detected = True
        
        try:
            # Get existing content for comparison
            existing_content = self._bitbucket_get_content(repo, path, branch)
            
            # Simple binary comparison - don't update if identical
            if existing_content == content:
                logger.warning(f"File {path} content is identical - skipping update")
                return False
                
            logger.info(f"Changes detected in {path} - proceeding with update")
            
        except Exception as e:
            # If we can't get existing content, proceed with update
            logger.info(f"Could not compare file contents: {str(e)} - proceeding with update")
        
        # Prepare the request
        # NOTE: Bitbucket API is sensitive to the format - this is the correct format
        form_data = {
            'message': commit_msg,
            'branch': branch
        }
        
        # Prepare the file - this exact format is important for Bitbucket
        files_data = {path: (None, content)}
        
        # Debug logging
        logger.info(f"Sending update to Bitbucket: file={path}, branch={branch}")
        
        try:
            # Make the API request
            url = f"{self.api_base_url}/repositories/{self.workspace}/{repo}/src"
            response = self.session.post(
                url,
                data=form_data,
                files=files_data
            )
            
            # Enhanced error logging
            if response.status_code >= 400:
                logger.error(f"Bitbucket API error: {response.status_code}")
                logger.error(f"Response: {response.text}")
                
                # Try to parse error details if available
                try:
                    error_data = response.json()
                    logger.error(f"Error details: {error_data}")
                except:
                    pass
            
            success = response.status_code in (200, 201)
            if success:
                logger.info(f"Successfully updated {path}")
            
            return success
            
        except Exception as e:
            logger.error(f"Exception during Bitbucket API call: {str(e)}")
            return False
    
    def _bitbucket_create_pr(self, repo: str, title: str, body: str, head: str, base: str) -> str:
        """Create a pull request in Bitbucket"""
        data = {
            "title": title,
            "description": body,
            "source": {
                "branch": {
                    "name": head
                }
            },
            "destination": {
                "branch": {
                    "name": base
                }
            }
        }
        
        response = self.session.post(
            f"{self.api_base_url}/repositories/{self.workspace}/{repo}/pullrequests",
            json=data
        )
        
        if response.status_code != 201:
            raise Exception(f"Failed to create PR: {response.text}")
        
        return response.json()["links"]["html"]["href"]
    
    # GitLab methods 
    def _gitlab_get_files(self, repo: str, ref: str) -> List[str]:
        """Get list of files from GitLab repository"""
        # GitLab requires URL-encoded repository path
        import urllib.parse
        repo_encoded = urllib.parse.quote_plus(repo)
        
        all_files = []
        page = 1
        per_page = 100
        
        while True:
            response = self.session.get(
                f"{self.api_base_url}/projects/{repo_encoded}/repository/tree",
                params={
                    "ref": ref,
                    "recursive": "true",
                    "per_page": per_page,
                    "page": page
                }
            )
            
            if response.status_code != 200:
                break
                
            items = response.json()
            if not items:
                break
                
            # Add file paths
            for item in items:
                if item["type"] == "blob":
                    all_files.append(item["path"])
                    
            # If we got fewer items than per_page, we're done
            if len(items) < per_page:
                break
                
            page += 1
        
        return all_files
    
    def _gitlab_get_content(self, repo: str, path: str, ref: str) -> str:
        """Get file content from GitLab"""
        import urllib.parse
        repo_encoded = urllib.parse.quote_plus(repo)
        path_encoded = urllib.parse.quote_plus(path)
        
        response = self.session.get(
            f"{self.api_base_url}/projects/{repo_encoded}/repository/files/{path_encoded}",
            params={
                "ref": ref
            }
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get file: {response.text}")
        
        content = response.json()["content"]
        encoding = response.json()["encoding"]
        
        if encoding == "base64":
            return base64.b64decode(content).decode('utf-8')
        else:
            return content
    
    def _gitlab_create_branch(self, repo: str, branch_name: str, base_ref: str) -> bool:
        """Create a new branch in GitLab"""
        import urllib.parse
        repo_encoded = urllib.parse.quote_plus(repo)
        
        data = {
            "branch": branch_name,
            "ref": base_ref
        }
        
        response = self.session.post(
            f"{self.api_base_url}/projects/{repo_encoded}/repository/branches",
            json=data
        )
        
        return response.status_code == 201
    
    def _gitlab_update_file(self, repo: str, path: str, content: str, commit_msg: str, branch: str) -> bool:
        """Update a file in GitLab"""
        import urllib.parse
        repo_encoded = urllib.parse.quote_plus(repo)
        path_encoded = urllib.parse.quote_plus(path)
        
        data = {
            "branch": branch,
            "content": content,
            "commit_message": commit_msg
        }
        
        # Check if file exists first
        try:
            self._gitlab_get_content(repo, path, branch)
            # File exists, use PUT to update
            response = self.session.put(
                f"{self.api_base_url}/projects/{repo_encoded}/repository/files/{path_encoded}",
                json=data
            )
        except:
            # File doesn't exist, use POST to create
            data["content"] = content
            response = self.session.post(
                f"{self.api_base_url}/projects/{repo_encoded}/repository/files/{path_encoded}",
                json=data
            )
        
        return response.status_code in (200, 201)
    
    def _gitlab_create_pr(self, repo: str, title: str, body: str, head: str, base: str) -> str:
        """Create a merge request (PR) in GitLab"""
        import urllib.parse
        repo_encoded = urllib.parse.quote_plus(repo)
        
        data = {
            "title": title,
            "description": body,
            "source_branch": head,
            "target_branch": base
        }
        
        response = self.session.post(
            f"{self.api_base_url}/projects/{repo_encoded}/merge_requests",
            json=data
        )
        
        if response.status_code != 201:
            raise Exception(f"Failed to create merge request: {response.text}")
        
        return response.json()["web_url"]
