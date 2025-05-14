import requests
import json
import os
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
import logging
import time
import uuid
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
        
        # Support for different site formats
        if not self.site or self.site.lower() == "app":
            # Main Datadog site (no region)
            self.base_url = "https://api.datadoghq.com"
        elif '.' not in self.site:
            # Regional site (us5, eu1, etc)
            self.base_url = f"https://api.{self.site}.datadoghq.com"
        else:
            # Full custom domain
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

    def _datadog_get_logs(self, service_name: str, time_range: Optional[Union[str, dict]] = None, 
                     log_level: str = "ERROR") -> List[Dict[str, Any]]:
        """
        Retrieve logs from Datadog for a specific service with automatic rate-limit management.
        
        This method implements an intelligent fallback strategy to find logs across different
        service naming patterns while optimizing requests to avoid rate limits.
        
        Args:
            service_name: The name of the service to retrieve logs for
            time_range: Time range for logs, can be a string like "15m", "1h" or a dict with "start" and "end" keys
                       (automatically limited to 15 minutes max to prevent rate limiting)
            log_level: The log level to filter for (ERROR, WARN, INFO, etc.)
            
        Returns:
            A list of log entries as dictionaries, or empty list if no logs found or errors occurred
            
        Note:
            This method automatically caps time ranges to 15 minutes to avoid rate limits,
            and employs multiple fallback strategies to find relevant logs.
        """
        request_id = str(uuid.uuid4())[:8]  # Request identifier for tracing
        logs_found = False
        
        try:
            # Configuration validation and logging
            if not self.api_key or not self.app_key:
                logger.error(f"[{request_id}] Missing Datadog credentials - API key: {bool(self.api_key)}, App key: {bool(self.app_key)}")
                return []
            
            logger.info(f"[{request_id}] Retrieving logs for service: {service_name}, level: {log_level}, site: {self.site}")
            
            # Input sanitization
            if not service_name or not isinstance(service_name, str):
                logger.error(f"[{request_id}] Invalid service name: {type(service_name)}")
                return []
                
            # Sanitize service name by removing port/colon for consistent queries
            clean_service_name = service_name
            if ':' in service_name:
                clean_service_name = service_name.split(':', 1)[0]
                logger.debug(f"[{request_id}] Sanitized service name from {service_name} to {clean_service_name}")
                service_name = clean_service_name
            
            # Time range calculation with built-in safeguards
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=15)  # Default: 15-minute window
            time_window_source = "default"
            
            # Process time_range parameter with rate-limit protection
            if time_range:
                try:
                    if isinstance(time_range, str):
                        time_window_source = f"string '{time_range}'"
                        # Parse time string formats (e.g., "15m", "1h", "1d")
                        if time_range.endswith('h'):
                            hours = int(time_range[:-1])
                            if hours > 1:
                                logger.info(f"[{request_id}] Limiting time window from {hours}h to 15m to prevent rate limits")
                            else:
                                start_time = end_time - timedelta(hours=hours)
                                
                        elif time_range.endswith('m'):
                            minutes = int(time_range[:-1])
                            if minutes > 15:
                                logger.info(f"[{request_id}] Limiting time window from {minutes}m to 15m to prevent rate limits")
                            else:
                                start_time = end_time - timedelta(minutes=minutes)
                                
                        elif time_range.endswith('d'):
                            logger.info(f"[{request_id}] Limiting requested time range from {time_range} to 15m to prevent rate limits")
                            
                    elif isinstance(time_range, dict) and "start" in time_range and "end" in time_range:
                        time_window_source = "dictionary"
                        # Parse dictionary with start/end timestamps
                        if isinstance(time_range["start"], (int, float)):
                            # Timestamps provided as epoch time
                            start_epoch = time_range["start"]
                            end_epoch = time_range["end"]
                            
                            # Convert to ms if seconds were provided
                            start_ms = int(start_epoch * 1000) if start_epoch < 10000000000 else int(start_epoch)
                            end_ms = int(end_epoch * 1000) if end_epoch < 10000000000 else int(end_epoch)
                            
                            # Convert to datetime for calculations
                            start_datetime = datetime.fromtimestamp(start_ms / 1000)
                            end_datetime = datetime.fromtimestamp(end_ms / 1000)
                            
                        else:
                            # ISO formatted timestamps
                            start_datetime = datetime.fromisoformat(time_range["start"].replace('Z', '+00:00'))
                            end_datetime = datetime.fromisoformat(time_range["end"].replace('Z', '+00:00'))
                        
                        # Calculate and limit time range
                        minutes_diff = (end_datetime - start_datetime).total_seconds() / 60
                        if minutes_diff > 15:
                            logger.info(f"[{request_id}] Limiting time window from {minutes_diff:.1f}m to 15m to prevent rate limits")
                            start_time = end_datetime - timedelta(minutes=15)
                            end_time = end_datetime
                        else:
                            start_time = start_datetime
                            end_time = end_datetime
                except Exception as e:
                    logger.warning(f"[{request_id}] Error parsing time range (using default 15m): {str(e)}")
                    # Continue with default time window
            
            # Log the final time window being used
            time_window_minutes = (end_time - start_time).total_seconds() / 60
            logger.info(f"[{request_id}] Using {time_window_minutes:.1f} minute time window (source: {time_window_source})")
            
            # Convert to Unix timestamps in milliseconds for Datadog API
            from_time = int(start_time.timestamp() * 1000)
            to_time = int(end_time.timestamp() * 1000)
            
            # Define prioritized query strategies to maximize chances of finding logs
            query_strategies = [
                # Start with exact matches, then progressively broaden
                {"type": "service-exact", "query": f"service:{service_name} status:{log_level.lower()}"},
                {"type": "host-exact", "query": f"host:{service_name} status:{log_level.lower()}"},
                {"type": "service-app", "query": f"service:{service_name}-app status:{log_level.lower()}"},
                {"type": "service-flask", "query": f"service:flask status:{log_level.lower()}"},
                # Last resort - any logs for the service regardless of level
                {"type": "service-any", "query": f"service:{service_name}"},
                {"type": "host-any", "query": f"host:{service_name}"}
            ]
            
            # API endpoint for logs
            url = f"{self.base_url}/api/v2/logs/events"
            
            # Conservative page limit to reduce risk of rate limiting
            page_limit = 30
            
            # Process each strategy with built-in delays to reduce rate limit risk
            for strategy_index, strategy in enumerate(query_strategies):
                # Add a small delay between strategies to reduce rate limit risks
                if strategy_index > 0:
                    time.sleep(0.5)
                    
                max_retries = 3
                retry_count = 0
                retry_delay = 2  # Base delay in seconds
                
                while retry_count <= max_retries:
                    try:
                        logger.debug(f"[{request_id}] Trying logs query strategy: {strategy['type']} ({strategy_index+1}/{len(query_strategies)})")
                        
                        params = {
                            "filter[query]": strategy['query'],
                            "filter[from]": from_time,
                            "filter[to]": to_time,
                            "page[limit]": page_limit,
                            "sort": "-timestamp"  # Newest first
                        }
                        
                        response = self.session.get(
                            url, 
                            params=params,
                            timeout=10  # Add explicit timeout
                        )
                        
                        status_code = response.status_code
                        logger.debug(f"[{request_id}] Response status for {strategy['type']}: {status_code}")
                        
                        # Handle response based on status code
                        if status_code == 200:
                            # Success path - process results
                            try:
                                logs_data = response.json()
                                logs = logs_data.get("data", [])
                                
                                if logs:
                                    logs_found = True
                                    log_count = len(logs)
                                    logger.info(f"[{request_id}] Found {log_count} logs with strategy: {strategy['type']}")
                                    return logs
                                else:
                                    logger.debug(f"[{request_id}] No logs found with strategy: {strategy['type']}")
                                    break  # Skip to next strategy
                                    
                            except json.JSONDecodeError as e:
                                logger.warning(f"[{request_id}] Error parsing JSON from Datadog response: {str(e)}")
                                # Try to sanitize response to handle invalid control characters
                                try:
                                    import re
                                    sanitized_text = re.sub(r'[\x00-\x1F\x7F]', '', response.text)
                                    logs_data = json.loads(sanitized_text)
                                    logs = logs_data.get("data", [])
                                    
                                    if logs:
                                        logs_found = True
                                        logger.info(f"[{request_id}] Found {len(logs)} logs after sanitizing response")
                                        return logs
                                    else:
                                        break  # Skip to next strategy
                                except Exception as sanitize_error:
                                    logger.error(f"[{request_id}] Failed to parse logs after sanitization: {str(sanitize_error)}")
                                    break  # Skip to next strategy
                        
                        elif status_code == 401:
                            logger.error(f"[{request_id}] Authentication failed - check Datadog API key")
                            return []  # Authentication failure is terminal - stop trying
                            
                        elif status_code == 403:
                            logger.error(f"[{request_id}] Authorization failed - check Datadog App key permissions")
                            return []  # Authorization failure is terminal - stop trying
                            
                        elif status_code == 429:
                            # Rate limit handling with exponential backoff
                            retry_count += 1
                            if retry_count <= max_retries:
                                # Calculate wait time with exponential backoff (2, 4, 8 seconds)
                                wait_time = retry_delay * (2 ** (retry_count - 1))
                                logger.warning(f"[{request_id}] Rate limit exceeded - retrying in {wait_time}s (attempt {retry_count}/{max_retries})")
                                time.sleep(wait_time)
                                continue  # Retry the same strategy
                            else:
                                logger.error(f"[{request_id}] Rate limit exceeded - max retries reached for strategy {strategy['type']}")
                                # Move to next strategy with a longer delay to help rate limits recover
                                time.sleep(2.0)
                                break
                                
                        else:
                            # Other HTTP errors
                            logger.warning(f"[{request_id}] Query failed with HTTP {status_code}: {response.text[:200]}...")
                            break  # Skip to next strategy
                    
                    except requests.exceptions.Timeout:
                        logger.warning(f"[{request_id}] Request timeout for strategy {strategy['type']}")
                        break  # Skip to next strategy
                        
                    except Exception as request_error:
                        logger.error(f"[{request_id}] Request error with strategy {strategy['type']}: {str(request_error)}")
                        break  # Skip to next strategy
            
            # If we exhausted all strategies without finding logs, log a clear message
            if not logs_found:
                logger.warning(f"[{request_id}] No logs found for '{service_name}' with log level '{log_level}' after trying all query strategies")
            
            return []
                
        except Exception as e:
            logger.error(f"[{request_id}] Unexpected error in Datadog logs retrieval: {str(e)}", exc_info=True)
            return []

    def extract_service_names_from_datadog(body):
        """Extract service names from Datadog webhook payload with proper prioritization"""
        service_names = []
        
        # 1. First priority: Look for service tags (most reliable)
        if "tags" in body and isinstance(body["tags"], list):
            for tag in body["tags"]:
                if isinstance(tag, str) and tag.startswith("service:"):
                    service = tag.split(":", 1)[1]
                    if service and service not in service_names:
                        service_names.append(service)
                        logger.info(f"Found service name in tags: {service}")
        
        # 2. Second priority: Check alertScope for service or host tags
        if "alertScope" in body and body["alertScope"]:
            scopes = body["alertScope"].split(",")
            for scope in scopes:
                scope = scope.strip()
                if scope.startswith("service:"):
                    service = scope.split(":", 1)[1]
                    if service and service not in service_names:
                        service_names.append(service)
                        logger.info(f"Found service name in alertScope: {service}")
                elif scope.startswith("host:"):
                    host = scope.split(":", 1)[1]
                    if host and host not in service_names:
                        service_names.append(host)
                        logger.info(f"Found host in alertScope: {host}")
        
        # 3. Third priority: Use hostname field
        if "hostname" in body and body["hostname"]:
            hostname = body["hostname"]
            if hostname not in service_names:
                service_names.append(hostname)
                logger.info(f"Using hostname as service name: {hostname}")
        
        # 4. Last resort: Extract from title/message (least reliable)
        if not service_names and "title" in body:
            title = body["title"]
            # Look for service mentions in the title
            if "Flask API" in title:
                service_names.append("flask-api")
                logger.info("Found 'flask-api' in title")
            elif "API" in title:
                service_names.append("api-service")
                logger.info("Found 'api-service' in title")
            
        # Default
        if not service_names:
            service_names.append("unknown-service")
            logger.info("No service name found, using default: unknown-service")
        
        return service_names
    
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
        
        # Function to recursively sanitize data structures
        def sanitize_data(data):
            import re
            control_char_pattern = re.compile(r'[\x00-\x1F\x7F]')
            
            if isinstance(data, str):
                # Remove control characters from strings
                return control_char_pattern.sub('', data)
            elif isinstance(data, dict):
                # Recursively sanitize dictionary values
                return {k: sanitize_data(v) for k, v in data.items()}
            elif isinstance(data, list):
                # Recursively sanitize list items
                return [sanitize_data(item) for item in data]
            else:
                # Return other types unchanged (numbers, None, etc.)
                return data
        
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
                        metrics_data = response.json()
                        # Sanitize the entire response data structure
                        sanitized_data = sanitize_data(metrics_data)
                        series_data = sanitized_data.get("series", [])
                        
                        # Verify the sanitized data can be safely JSON serialized
                        try:
                            json.dumps(series_data)
                            logger.info("Successfully verified metrics data JSON serialization")
                        except Exception as json_e:
                            logger.error(f"Error in JSON serialization after sanitization: {json_e}")
                            # If serialization still fails, create a simplified safe version
                            simplified_data = []
                            for series in series_data:
                                # Create a simplified version with just essential data
                                simple_series = {
                                    "metric": str(series.get("metric", "unknown")),
                                    "points": [[p[0], p[1]] for p in series.get("points", [])[:10]],
                                    "scope": str(series.get("scope", "unknown"))
                                }
                                simplified_data.append(simple_series)
                            return simplified_data
                        
                        return series_data
                        
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing Datadog metrics response: {e}")
                        import re
                        sanitized_text = re.sub(r'[\x00-\x1F\x7F]', '', response.text)
                        metrics_data = json.loads(sanitized_text)
                        # Also sanitize after parsing
                        sanitized_data = sanitize_data(metrics_data)
                        return sanitized_data.get("series", [])
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
