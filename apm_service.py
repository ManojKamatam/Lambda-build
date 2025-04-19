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
        """Initialize Dynatrace client with OAuth support"""
        self.base_url = self.extra_params.get("base_url")
        if not self.base_url:
            raise ValueError("Dynatrace requires 'base_url' parameter")
        
        self.session = requests.Session()
        
        # Check if Grail is enabled (using OAuth)
        self.uses_grail = self.extra_params.get("uses_grail", False)
        
        if self.uses_grail:
            # Get client credentials from extra_params
            client_id = self.extra_params.get("client_id")
            client_secret = self.extra_params.get("oauth_client_secret", self.api_key)  # Fall back to API key
            
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
                        oauth_token = response.json().get("access_token")
                        self.session.headers.update({
                            "Authorization": f"Bearer {oauth_token}",
                            "Content-Type": "application/json"
                        })
                        logger.info("Successfully obtained Dynatrace OAuth token")
                        return
                    else:
                        logger.warning(f"Failed to get OAuth token: {response.text}")
                except Exception as e:
                    logger.error(f"Error getting OAuth token: {str(e)}")
            
            # Fall back to using API key directly
            self.session.headers.update({
                "Authorization": f"Api-Token {self.api_key}",
                "Content-Type": "application/json"
            })
        else:
            # Default to API token authentication
            self.session.headers.update({
                "Authorization": f"Api-Token {self.api_key}",
                "Content-Type": "application/json"
            })
            
    def _init_datadog(self):
        """Initialize Datadog client"""
        self.api_key = self.api_key
        self.app_key = self.extra_params.get("app_key")
        
        if not self.app_key:
            raise ValueError("Datadog requires 'app_key' parameter")
        
        # Get regional site from extra_params, default to datadoghq.com (US)
        self.site = self.extra_params.get("site", "us5")  # Default to US5 since that's what you were using
        
        # Support for specifying a full domain or just the region code
        if '.' not in self.site:
            self.base_url = f"https://api.{self.site}.datadoghq.com"
        else:
            self.base_url = f"https://api.{self.site}"
            
        logger.info(f"Initializing Datadog client with site: {self.site}")
        
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
        
        # Log auth header for debugging
        auth_header = self.session.headers.get("Authorization", "")
        auth_type = "Bearer" if auth_header.startswith("Bearer") else "Api-Token"
        logger.info(f"Getting Dynatrace logs with auth type: {auth_type}")
        
        # First attempt with current authentication
        response = self.session.get(url, params=params)
        
        # If we get an OAuth token missing error and we're not already using OAuth, 
        # try switching to OAuth authentication and retry
        if (response.status_code == 401 and 
            "OAuth token is missing" in response.text and 
            not self.uses_grail):
            
            logger.info("Detected Grail environment, switching to OAuth authentication")
            self.uses_grail = True
            
            # Try to get OAuth token if we have client credentials
            client_id = self.extra_params.get("client_id")
            client_secret = self.extra_params.get("oauth_client_secret", self.api_key)
            
            if client_id and client_secret:
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
                    token_response = requests.post(token_url, headers=token_headers, data=token_data)
                    if token_response.status_code == 200:
                        oauth_token = token_response.json().get("access_token")
                        self.session.headers.update({
                            "Authorization": f"Bearer {oauth_token}"
                        })
                        logger.info("Successfully obtained Dynatrace OAuth token for logs")
                    else:
                        logger.warning(f"Failed to get OAuth token: {token_response.text}")
                        # Fall back to using API key as Bearer token
                        self.session.headers.update({
                            "Authorization": f"Bearer {self.api_key}"
                        })
                except Exception as e:
                    logger.error(f"Error getting OAuth token: {str(e)}")
                    # Fall back to using API key as Bearer token
                    self.session.headers.update({
                        "Authorization": f"Bearer {self.api_key}"
                    })
            else:
                # No client credentials, use API key as Bearer token
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

    def _datadog_get_logs(self, service_name, time_range=None, log_level="ERROR"):
        """Get logs from Datadog"""
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
            
            # Convert to Unix timestamps in milliseconds for Datadog
            from_time = int(start_time.timestamp() * 1000)
            to_time = int(end_time.timestamp() * 1000)
        # Handle dictionary format
        elif isinstance(time_range, dict) and "start" in time_range and "end" in time_range:
            try:
                # Check if these are timestamps or ISO strings
                if isinstance(time_range["start"], (int, float)):
                    from_time = int(time_range["start"] * 1000) if time_range["start"] < 10000000000 else int(time_range["start"])
                    to_time = int(time_range["end"] * 1000) if time_range["end"] < 10000000000 else int(time_range["end"])
                else:
                    # Parse ISO strings
                    from_time = int(datetime.fromisoformat(time_range["start"].replace('Z', '+00:00')).timestamp() * 1000)
                    to_time = int(datetime.fromisoformat(time_range["end"].replace('Z', '+00:00')).timestamp() * 1000)
            except Exception as e:
                logger.error(f"Error parsing time range: {e}")
                # Default to last hour
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=1)
                from_time = int(start_time.timestamp() * 1000)
                to_time = int(end_time.timestamp() * 1000)
        # Default case
        else:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            from_time = int(start_time.timestamp() * 1000)
            to_time = int(end_time.timestamp() * 1000)
        
        # Build query for Datadog Logs API
        query = f"service:{service_name} status:{log_level.lower()}"
        
        # Datadog logs API endpoint - use base_url property from self
        url = f"{self.base_url}/api/v2/logs/events"
        
        params = {
            "filter[query]": query,
            "filter[from]": from_time,
            "filter[to]": to_time,
            "page[limit]": 100
        }
        
        logger.info(f"Getting Datadog logs for service: {service_name}, level: {log_level}")
        response = self.session.get(url, params=params)
        
        if response.status_code != 200:
            raise Exception(f"Failed to get Datadog logs: {response.text}")
        
        # Add sanitization of response to handle invalid control characters
        try:
            logs_data = response.json()
            return logs_data.get("data", [])
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Datadog logs response: {e}")
            # Try to sanitize the response to remove control characters
            import re
            sanitized_text = re.sub(r'[\x00-\x1F\x7F]', '', response.text)
            try:
                logs_data = json.loads(sanitized_text)
                logger.info("Successfully parsed logs after sanitizing response")
                return logs_data.get("data", [])
            except:
                logger.error("Failed to parse logs even after sanitization")
                return []
    
    def _datadog_get_metrics(self, service_name, metric_type, time_range=None):
        """Get metrics from Datadog with multiple query formats for better success rate"""
        # Map generic metric types to Datadog metrics with multiple formats to try
        metric_queries = {
            "cpu": [
                f"avg:system.cpu.user{{service:{service_name}}}",
                f"avg:system.cpu.user{{host:{service_name}}}",
                "avg:system.cpu.user{*}"  # Fallback to all hosts
            ],
            "memory": [
                f"avg:system.mem.used{{service:{service_name}}}",
                f"avg:system.mem.used{{host:{service_name}}}",
                "avg:system.mem.used{*}"
            ],
            "latency": [
                f"avg:trace.http.request.duration{{service:{service_name}}}",
                f"avg:http.request.duration{{service:{service_name}}}",
                f"avg:trace.http.request.duration{{resource_name:{service_name}}}"
            ],
            "error_rate": [
                f"sum:trace.servlet.request.errors{{service:{service_name}}}.as_count()",
                f"sum:errors.count{{service:{service_name}}}.as_count()",
                f"sum:http.errors{{service:{service_name}}}.as_count()"
            ],
            "throughput": [
                f"sum:trace.servlet.request.hits{{service:{service_name}}}.as_count()",
                f"sum:http.requests{{service:{service_name}}}.as_count()"
            ]
        }
        
        queries_to_try = metric_queries.get(metric_type)
        if not queries_to_try:
            raise ValueError(f"Unsupported metric type: {metric_type}")
        
        # Parse time range
        now = int(datetime.utcnow().timestamp())
        
        if isinstance(time_range, str):
            # Handle different time formats
            if time_range.endswith('h'):
                try:
                    hours = int(time_range[:-1])
                    from_time = now - (hours * 3600)
                except ValueError:
                    from_time = now - 3600  # Default 1 hour
            elif time_range.endswith('m'):
                try:
                    minutes = int(time_range[:-1])
                    from_time = now - (minutes * 60)
                except ValueError:
                    from_time = now - 3600  # Default 1 hour
            elif time_range.endswith('d'):
                try:
                    days = int(time_range[:-1])
                    from_time = now - (days * 86400)
                except ValueError:
                    from_time = now - 3600  # Default 1 hour
            else:
                from_time = now - 3600  # Default 1 hour
        else:
            from_time = now - 3600  # Default 1 hour
        
        # Datadog metrics API endpoint - use base_url property
        url = f"{self.base_url}/api/v1/query"
        
        # Try each query format
        last_error = None
        for i, query in enumerate(queries_to_try):
            logger.info(f"Trying Datadog metric query ({i+1}/{len(queries_to_try)}): {query}")
            
            payload = {
                "query": query,
                "from": from_time,
                "to": now
            }
            
            try:
                response = self.session.get(url, params=payload)
                
                if response.status_code == 200:
                    logger.info(f"Successfully retrieved Datadog metrics with query format {i+1}")
                    # Add sanitization to handle potential JSON parsing errors
                    try:
                        return response.json().get("series", [])
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing Datadog metrics response: {e}")
                        import re
                        sanitized_text = re.sub(r'[\x00-\x1F\x7F]', '', response.text)
                        metrics_data = json.loads(sanitized_text)
                        return metrics_data.get("series", [])
                else:
                    last_error = response.text
                    logger.warning(f"Query format {i+1} failed with status {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.error(f"Error with query format {i+1}: {str(e)}")
        
        # If we get here, all queries failed
        raise Exception(f"Failed to get Datadog metrics: {last_error}")
    
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
        
        # Clean service name of any quotes
        safe_service_name = service_name.replace("'", "").replace('"', '')
        
        url = f"{self.base_url}/api/v2/metrics/query"
        
        # Use double quotes in the filter (Dynatrace syntax requirement)
        params = {
            "metricSelector": f'{dynatrace_metric}:filter(entity.name="{safe_service_name}")',
            "from": from_time,
            "resolution": "Inf"
        }
        
        # Save current auth header which may be OAuth
        current_auth = self.session.headers.get("Authorization", "")
        
        # Temporarily switch to API token for metrics
        self.session.headers.update({
            "Authorization": f"Api-Token {self.api_key}"
        })
        
        try:
            logger.info(f"Getting Dynatrace metrics with Api-Token authentication for service: {safe_service_name}")
            response = self.session.get(url, params=params)
            
            if response.status_code != 200:
                # Try alternative approach with entitySelector
                logger.info("First attempt failed, trying with entitySelector")
                alt_params = {
                    "metricSelector": dynatrace_metric,
                    "entitySelector": f'type(SERVICE),entityName("{safe_service_name}")',
                    "from": from_time,
                    "resolution": "Inf"
                }
                response = self.session.get(url, params=alt_params)
                
                if response.status_code != 200:
                    # Try once more with no filter as last resort
                    logger.info("Second attempt failed, trying with no filter")
                    simple_params = {
                        "metricSelector": dynatrace_metric,
                        "from": from_time,
                        "resolution": "Inf"
                    }
                    response = self.session.get(url, params=simple_params)
                    
                    if response.status_code != 200:
                        raise Exception(f"Failed to get Dynatrace metrics: {response.text}")
            
            return response.json().get("result", [])
        finally:
            # Restore original auth header
            self.session.headers.update({
                "Authorization": current_auth
            })
