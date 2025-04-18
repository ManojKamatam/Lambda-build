import requests
import json
import os
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class APMService:
    def __init__(self, apm_type=None, api_key=None, **kwargs):
        self.apm_type = apm_type or os.environ.get("APM_TYPE", "dynatrace")
        self.api_key = api_key or os.environ.get("APM_API_KEY")
        self.extra_params = kwargs or json.loads(os.environ.get("APM_EXTRA_PARAMS", "{}"))
        
        if self.apm_type == "dynatrace":
            self._init_dynatrace()
        elif self.apm_type == "datadog":
            self._init_datadog()
        elif self.apm_type == "newrelic":
            self._init_newrelic()
        else:
            raise ValueError(f"Unsupported APM type: {self.apm_type}")
    
    def _init_dynatrace(self):
        """Initialize Dynatrace client with support for both metrics and logs"""
        self.base_url = self.extra_params.get("base_url")
        if not self.base_url:
            raise ValueError("Dynatrace requires 'base_url' parameter")
        
        self.session = requests.Session()
        
        # Check if Grail is enabled (using OAuth)
        self.uses_grail = self.extra_params.get("uses_grail", False)
        
        # Store API token for metrics
        self.api_token = self.api_key
        
        # Initialize OAuth token for logs if Grail is enabled
        self.oauth_token = None
        
        if self.uses_grail:
            # Get client credentials from extra_params
            client_id = self.extra_params.get("client_id")
            client_secret = self.extra_params.get("oauth_client_secret")  # Use specific param
            
            if not client_secret:
                logger.info("No oauth_client_secret found, falling back to api_key as client_secret")
                client_secret = self.api_key
            
            if client_id and client_secret:
                # Get OAuth token
                token_url = "https://sso.dynatrace.com/sso/oauth2/token"
                token_data = {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "storage:logs:read storage:buckets:read"
                }
                
                token_headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                
                try:
                    response = requests.post(token_url, headers=token_headers, data=token_data)
                    if response.status_code == 200:
                        self.oauth_token = response.json().get("access_token")
                        logger.info("Successfully obtained Dynatrace OAuth token")
                    else:
                        logger.warning(f"Failed to get OAuth token: {response.text}")
                except Exception as e:
                    logger.error(f"Error getting OAuth token: {str(e)}")
            
            # Initialize session with API token for default operations
            self.session.headers.update({
                "Authorization": f"Api-Token {self.api_token}",
                "Content-Type": "application/json"
            })
        else:
            # Not using Grail, just set API token
            self.session.headers.update({
                "Authorization": f"Api-Token {self.api_token}",
                "Content-Type": "application/json"
            })
            
    def _init_datadog(self):
        """Initialize Datadog client"""
        self.api_key = self.api_key
        self.app_key = self.extra_params.get("app_key")
        
        if not self.app_key:
            raise ValueError("Datadog requires 'app_key' parameter")
        
        self.session = requests.Session()
        self.session.headers.update({
            "DD-API-KEY": self.api_key,
            "DD-APPLICATION-KEY": self.app_key,
            "Content-Type": "application/json"
        })
    
    def _init_newrelic(self):
        """Initialize New Relic client"""
        self.account_id = self.extra_params.get("account_id")
        
        if not self.account_id:
            raise ValueError("New Relic requires 'account_id' parameter")
        
        self.session = requests.Session()
        self.session.headers.update({
            "Api-Key": self.api_key,
            "Content-Type": "application/json"
        })
    
    def get_logs(self, service_name, time_range=None, log_level="ERROR"):
        """Get logs for a service"""
        if self.apm_type == "dynatrace":
            return self._dynatrace_get_logs(service_name, time_range, log_level)
        elif self.apm_type == "datadog":
            return self._datadog_get_logs(service_name, time_range, log_level)
        elif self.apm_type == "newrelic":
            return self._newrelic_get_logs(service_name, time_range, log_level)
    
    def get_metrics(self, service_name, metric_type, time_range=None):
        """Get metrics for a service"""
        if self.apm_type == "dynatrace":
            return self._dynatrace_get_metrics(service_name, metric_type, time_range)
        elif self.apm_type == "datadog":
            return self._datadog_get_metrics(service_name, metric_type, time_range)
        elif self.apm_type == "newrelic":
            return self._newrelic_get_metrics(service_name, metric_type, time_range)
    
    def _dynatrace_get_logs(self, service_name, time_range=None, log_level="ERROR"):
        """Get logs from Dynatrace with proper OAuth handling"""
        # Time range processing code remains the same...
        
        # Format the query for Dynatrace Logs API
        query = f"service:{service_name} AND level:{log_level}"
        
        url = f"{self.base_url}/api/v2/logs/search"
        params = {
            "query": query,
            "from": from_time,
            "to": to_time,
            "limit": 100
        }
        
        # If we have an OAuth token and Grail is enabled, use it
        if self.uses_grail and self.oauth_token:
            original_auth = self.session.headers.get("Authorization")
            try:
                # Switch to OAuth token temporarily
                self.session.headers.update({
                    "Authorization": f"Bearer {self.oauth_token}"
                })
                response = self.session.get(url, params=params)
                
                if response.status_code == 200:
                    return response.json().get("logs", [])
            finally:
                # Restore original authorization header
                self.session.headers.update({
                    "Authorization": original_auth
                })
        
        # Otherwise try with current session auth (API token)
        response = self.session.get(url, params=params)
        
        # If OAuth error and we're not using stored OAuth token, try to get one
        if (response.status_code == 401 and "OAuth token is missing" in response.text):
            if not self.oauth_token:
                logger.warning("Need OAuth token for logs but none available")
            raise Exception(
                "Failed to get Dynatrace logs: OAuth token is required. " +
                response.text
            )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get Dynatrace logs: {response.text}")
        
        return response.json().get("logs", [])
    
    def _dynatrace_get_metrics(self, service_name, metric_type, time_range=None):
        """Get metrics from Dynatrace with auth fallback"""
        # Map generic metric types to Dynatrace metrics
        metric_mapping = {
            "cpu": "builtin:host.cpu.usage",
            "memory": "builtin:host.mem.usage",
            "latency": "builtin:service.response.time",
            "error_rate": "builtin:service.errors.total.rate", 
            "throughput": "builtin:service.requestCount.total"
        }
        
        dynatrace_metric = metric_mapping.get(metric_type)
        if not dynatrace_metric:
            raise ValueError(f"Unsupported metric type: {metric_type}")
        
        # Format time range
        if isinstance(time_range, str):
            # Handle different time formats
            if time_range.endswith('h') or time_range.endswith('m') or time_range.endswith('d'):
                from_time = f"now-{time_range}"
            else:
                from_time = "now-1h"  # Default fallback
        else:
            from_time = "now-1h"
        
        url = f"{self.base_url}/api/v2/metrics/query"
        params = {
            "metricSelector": f"{dynatrace_metric}:filter(entity.name:'{service_name}')",
            "from": from_time,
            "resolution": "Inf"
        }
        
        # First try with current auth (should be API token)
        response = self.session.get(url, params=params)
        
        # If it fails and we have OAuth token, try with that
        if response.status_code == 401 and self.oauth_token:
            logger.info("API token failed for metrics, trying OAuth token")
            original_auth = self.session.headers.get("Authorization")
            try:
                self.session.headers.update({
                    "Authorization": f"Bearer {self.oauth_token}"
                })
                response = self.session.get(url, params=params)
            finally:
                # Restore original auth
                self.session.headers.update({
                    "Authorization": original_auth
                })
    
        if response.status_code != 200:
            raise Exception(f"Failed to get Dynatrace metrics: {response.text}")
        
        return response.json().get("result", [])
