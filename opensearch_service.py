import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
from requests_aws4auth import AWS4Auth
import json
import time
import os
import logging
import random

logger = logging.getLogger()

class OpenSearchService:
    def __init__(self, endpoint=None, index_name="ai-response", vector_dimension=1536):
        self.endpoint = endpoint or os.environ.get("OPENSEARCH_ENDPOINT")
        self.index_name = index_name
        self.vector_dimension = vector_dimension
        
        if not self.endpoint:
            logger.warning("No OpenSearch endpoint provided")
            self.client = None
            return
        
        try:
            # Clean the endpoint to extract just the hostname
            host = self.endpoint
            if host.startswith("https://"):
                host = host[8:]  # Remove 'https://' prefix
            if host.startswith("http://"):
                host = host[7:]  # Remove 'http://' prefix
                
            # Get AWS credentials
            region = host.split('.')[1] if host else 'us-east-1'
            credentials = boto3.Session().get_credentials()
            self.awsauth = AWS4Auth(
                credentials.access_key,
                credentials.secret_key,
                region,
                'aoss',
                session_token=credentials.token
            )
            
            # Initialize OpenSearch client with the cleaned host
            self.client = OpenSearch(
                hosts=[{'host': host, 'port': 443}],
                http_auth=self.awsauth,
                use_ssl=True,
                verify_certs=True,
                connection_class=RequestsHttpConnection
            )
            
            # Create index with proper mapping if it doesn't exist
            self.create_index_if_not_exists()
            logger.info(f"Successfully connected to OpenSearch at {self.endpoint}")
        except Exception as e:
            logger.error(f"Failed to initialize OpenSearch client: {str(e)}")
            self.client = None
    
    def create_index_if_not_exists(self):
        """Create the index with proper vector mapping if it doesn't exist"""
        try:
            # First check if index exists without creating it
            try:
                exists = self.client.indices.exists(index=self.index_name)
                if exists:
                    logger.info(f"Index {self.index_name} already exists")
                    return True
            except Exception as check_error:
                # If we can't even check if the index exists, log it and continue to creation attempt
                logger.warning(f"Error checking if index exists: {str(check_error)}")
                
            # If not, try to create it
            index_mapping = {
                "mappings": {
                    "properties": {
                        "vector": {
                            "type": "knn_vector",
                            "dimension": self.vector_dimension
                        },
                        "doc_id": {"type": "keyword"}, # Added to store original document ID
                        "type": {"type": "keyword"},
                        "file_path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                        "content_sample": {"type": "text"},
                        "repository": {"type": "keyword"},
                        "problem_id": {"type": "keyword"},
                        "timestamp": {"type": "date"}
                    }
                },
                "settings": {
                    "index": {
                        "knn": True,
                        "knn.algo_param.ef_search": 100
                    }
                }
            }
            
            self.client.indices.create(index=self.index_name, body=index_mapping)
            logger.info(f"Created index {self.index_name} with kNN mapping")
            return True
            
        except Exception as e:
            error_message = str(e)
            if "AuthorizationException" in error_message or "403" in error_message:
                logger.warning(f"Authorization issue with OpenSearch: {error_message}. Check IAM permissions and ensure the Lambda role has access to AOSS.")
                # Still consider the client initialized as other operations might work
                return False
            elif "resource_already_exists_exception" in error_message.lower():
                # Index already exists - this is a common race condition and not an error
                logger.info(f"Index {self.index_name} already exists (created by another process)")
                return True
            else:
                logger.error(f"Failed to create index: {error_message}")
                return False
    
    def index_vector(self, doc_id, vector, metadata=None):
        """Index a vector in OpenSearch"""
        if not self.client:
            logger.warning("OpenSearch client not initialized")
            return None
            
        if metadata is None:
            metadata = {}
        
        try:
            # Validate vector
            if not isinstance(vector, list):
                vector = list(vector)  # Convert numpy arrays or other sequence types
                
            if len(vector) != self.vector_dimension:
                logger.warning(f"Vector dimension mismatch: expected {self.vector_dimension}, got {len(vector)}")
            
            # Include doc_id as a field in the document instead of API parameter
            document = {
                "vector": vector,
                "doc_id": doc_id,  # Store ID as field in the document
                **metadata
            }
            
            # Remove refresh=true parameter since it's not supported
            response = self.client.index(
                index=self.index_name,
                body=document
            )
            return response
        except Exception as e:
            logger.error(f"Error indexing vector {doc_id}: {str(e)}")
            return None
    
    def search_similar_vectors(self, vector, k=5, filter_query=None):
        """Find similar vectors in OpenSearch"""
        if not self.client:
            logger.warning("OpenSearch client not initialized")
            return []
            
        try:
            # Convert vector if needed
            if not isinstance(vector, list):
                vector = list(vector)
            
            query = {
                "size": k,
                "query": {
                    "knn": {
                        "vector": {
                            "vector": vector,
                            "k": k
                        }
                    }
                }
            }
            
            # Add filter if provided
            if filter_query:
                query["query"] = {
                    "bool": {
                        "must": [
                            {"knn": {"vector": {"vector": vector, "k": k}}},
                            filter_query
                        ]
                    }
                }
            
            response = self.client.search(
                body=query,
                index=self.index_name
            )
            
            return response['hits']['hits']
        except Exception as e:
            logger.error(f"Error searching vectors: {str(e)}")
            return []
    
    def store_file_vectors(self, problem_id, file_paths, file_embeddings, file_contents=None, repository=None):
        """Store file vectors in bulk - simplified robust approach"""
        if not self.client:
            logger.warning("OpenSearch client not initialized")
            return 0
            
        try:
            # Prepare bulk indexing data - simple format without IDs
            bulk_data = []
            
            for i, (file_path, embedding) in enumerate(zip(file_paths, file_embeddings)):
                # Include logical ID as field instead of document ID
                logical_id = f"file_{problem_id}_{i}"
                content_sample = file_contents.get(file_path, "")[:200] if file_contents else ""
                
                document = {
                    "vector": list(embedding),
                    "logical_id": logical_id,  # Store ID as a field
                    "type": "file",
                    "file_path": file_path,
                    "content_sample": content_sample,
                    "repository": repository,
                    "problem_id": problem_id,
                    "timestamp": time.time()
                }
                
                # Simple action without _id
                action = {"index": {"_index": self.index_name}}
                bulk_data.append(action)
                bulk_data.append(document)
            
            if not bulk_data:
                return 0
                
            # Simple retry logic - 3 attempts
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                try:
                    logger.info(f"Bulk indexing attempt {attempt}/{max_attempts} with {len(bulk_data)//2} documents")
                    response = self.client.bulk(body=bulk_data)
                    
                    # Count successes/failures
                    if 'items' in response:
                        success_count = sum(1 for item in response['items'] if 'error' not in item.get('index', {}))
                        failed_count = len(response['items']) - success_count
                        logger.info(f"Bulk indexed {success_count} documents, {failed_count} failed")
                        
                        # If any succeeded or we're out of attempts, return what we have
                        if success_count > 0 or attempt == max_attempts:
                            return success_count
                            
                        # If everything failed, wait and retry
                        delay = 2 ** (attempt - 1)  # Simple exponential backoff: 1s, 2s, 4s...
                        logger.info(f"All documents failed, retrying in {delay}s...")
                        time.sleep(delay)
                    else:
                        logger.warning("Unexpected response format")
                        return 0
                        
                except Exception as e:
                    logger.error(f"Bulk operation failed: {str(e)}")
                    
                    # Last attempt - give up
                    if attempt == max_attempts:
                        return 0
                        
                    # Otherwise wait and retry
                    delay = 2 ** (attempt - 1)
                    logger.info(f"Error occurred, retrying in {delay}s...")
                    time.sleep(delay)
            
            return 0  # Shouldn't reach here, but just in case
            
        except Exception as e:
            logger.error(f"Unexpected error in bulk indexing: {str(e)}")
            return 0
            
    def delete_problem_vectors(self, problem_id):
        """Delete all vectors associated with a problem"""
        if not self.client:
            return False
            
        try:
            query = {
                "query": {
                    "term": {
                        "problem_id": problem_id
                    }
                }
            }
            
            self.client.delete_by_query(index=self.index_name, body=query)
            return True
        except Exception as e:
            logger.error(f"Error deleting problem vectors: {str(e)}")
            return False
    
    def get_bedrock_embeddings(self, texts):
        """Get embeddings using Amazon Bedrock"""
        try:
            bedrock_runtime = boto3.client('bedrock-runtime')
            model_id = os.environ.get("BEDROCK_MODEL_ID", "amazon.titan-embed-text-v1")
            
            embeddings = []
            for text in texts:
                try:
                    # Limit text length to avoid token limits
                    if len(text) > 8000:
                        text = text[:8000]
                        
                    response = bedrock_runtime.invoke_model(
                        modelId=model_id,
                        body=json.dumps({
                            "inputText": text
                        })
                    )
                    
                    # Handle both streaming and non-streaming responses
                    if hasattr(response['body'], 'read'):
                        response_body = json.loads(response['body'].read())
                    else:
                        response_body = json.loads(response['body']) if isinstance(response['body'], str) else response['body']
                    
                    embedding = response_body.get('embedding', [])
                    embeddings.append(embedding)
                except Exception as e:
                    logger.error(f"Error getting embedding for text: {str(e)}")
                    # Return zeros as fallback
                    embeddings.append([0.0] * self.vector_dimension)
            
            return embeddings
        except Exception as e:
            logger.error(f"Error in Bedrock embeddings service: {str(e)}")
            return [[0.0] * self.vector_dimension] * len(texts)
