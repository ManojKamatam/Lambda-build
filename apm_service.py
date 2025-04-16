import requests
import json
import os
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

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
        """Initialize Dynatrace client"""
        self.base_url = self.extra_params.get("base_url")
        if not self.base_url:
            raise ValueError("Dynatrace requires 'base_url' parameter")
        
        self.session = requests.Session()
        
        # Check if Grail is enabled (using OAuth)
        self.uses_grail = self.extra_params.get("uses_grail", False)
        
        # Default to API token authentication
        auth_type = "Bearer" if self.uses_grail else "Api-Token"
        self.session.headers.update({
            "Authorization": f"{auth_type} {self.api_key}",
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
        """Get logs from Dynatrace"""
        # Parse time_range string if provided in that format
        if isinstance(time_range, str):
            end_time = datetime.utcnow()
            
            # Handle different time formats like "1h", "30m", etc.
            if time_range.endswith('h'):
                try:
                    hours = int(time_range[:-1])
                    start_time = end_time - timedelta(hours=hours)
                except ValueError:
                    start_time = end_time - timedelta(hours=1)
            elif time_range.endswith('m'):
                try:
                    minutes = int(time_range[:-1])
                    start_time = end_time - timedelta(minutes=minutes)
                except ValueError:
                    start_time = end_time - timedelta(hours=1)
            elif time_range.endswith('d'):
                try:
                    days = int(time_range[:-1])
                    start_time = end_time - timedelta(days=days)
                except ValueError:
                    start_time = end_time - timedelta(hours=1)
            else:
                # Default to 1 hour if format not recognized
                start_time = end_time - timedelta(hours=1)
            
            # Format timestamps with millisecond precision (3 decimal places)
            from_time = start_time.isoformat().split('.')[0]
            if start_time.microsecond > 0:
                # Add millisecond precision (3 decimal places)
                from_time += f".{start_time.microsecond // 1000:03d}"
            from_time += "Z"
            
            to_time = end_time.isoformat().split('.')[0]
            if end_time.microsecond > 0:
                # Add millisecond precision (3 decimal places)
                to_time += f".{end_time.microsecond // 1000:03d}"
            to_time += "Z"
        # Handle dictionary format
        elif isinstance(time_range, dict) and "start" in time_range and "end" in time_range:
            from_time = time_range["start"]
            to_time = time_range["end"]
        # Default case
        else:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            
            # Format timestamps with millisecond precision
            from_time = start_time.isoformat().split('.')[0]
            if start_time.microsecond > 0:
                from_time += f".{start_time.microsecond // 1000:03d}"
            from_time += "Z"
            
            to_time = end_time.isoformat().split('.')[0]
            if end_time.microsecond > 0:
                to_time += f".{end_time.microsecond // 1000:03d}"
            to_time += "Z"
        
        # Format the query for Dynatrace Logs API
        query = f"service:{service_name} AND level:{log_level}"
    
        url = f"{self.base_url}/api/v2/logs/search"
        params = {
            "query": query,
            "from": from_time,
            "to": to_time,
            "limit": 100
        }
        
        # First attempt with current authentication
        response = self.session.get(url, params=params)
        
        # If we get an OAuth token missing error and we're not already using OAuth, 
        # try switching to OAuth authentication and retry
        if (response.status_code == 401 and 
            "OAuth token is missing" in response.text and 
            not self.uses_grail):
            
            print("Detected Grail environment, switching to OAuth authentication")
            self.uses_grail = True
            self.session.headers.update({
                "Authorization": f"Bearer {self.api_key}"
            })
            
            # Retry the request with OAuth authentication
            response = self.session.get(url, params=params)
        
        if response.status_code != 200:
            if response.status_code == 401 and "OAuth token is missing" in response.text:
                raise Exception(
                    "Failed to get Dynatrace logs: OAuth token is required for Grail environments. "
                    "Please provide an OAuth token with storage:logs:read and storage:buckets:read scopes "
                    "and set uses_grail=True in extra_params or APM_EXTRA_PARAMS environment variable."
                )
            raise Exception(f"Failed to get Dynatrace logs: {response.text}")
        
        return response.json().get("logs", [])
    
    def _dynatrace_get_metrics(self, service_name, metric_type, time_range=None):
        """Get metrics from Dynatrace"""
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
        
        if isinstance(time_range, str):
            # Handle different time formats
            if time_range.endswith('h'):
                from_time = f"now-{time_range}"
            elif time_range.endswith('m'):
                from_time = f"now-{time_range}"
            elif time_range.endswith('d'):
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
        
        response = self.session.get(url, params=params)
        
        if response.status_code != 200:
            raise Exception(f"Failed to get Dynatrace metrics: {response.text}")
        
        return response.json().get("result", [])
