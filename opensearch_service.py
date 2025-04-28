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
        """Store file vectors with individual indexing if bulk fails"""
        if not self.client:
            logger.warning("OpenSearch client not initialized")
            return 0
            
        # Try bulk indexing first
        bulk_data = []
        for i, (file_path, embedding) in enumerate(zip(file_paths, file_embeddings)):
            document = {
                "vector": list(embedding),
                "logical_id": f"file_{problem_id}_{i}",
                "type": "file",
                "file_path": file_path,
                "content_sample": file_contents.get(file_path, "")[:200] if file_contents else "",
                "repository": repository,
                "problem_id": problem_id,
                "timestamp": time.time()
            }
            action = {"index": {"_index": self.index_name}}
            bulk_data.append(action)
            bulk_data.append(document)
        
        # Try bulk first (it's faster)
        try:
            logger.info(f"Attempting bulk indexing of {len(bulk_data)//2} documents")
            response = self.client.bulk(body=bulk_data)
            if 'items' in response:
                success_count = sum(1 for item in response['items'] if 'error' not in item.get('index', {}))
                failed_count = len(response['items']) - success_count
                logger.info(f"Bulk indexed {success_count} documents, {failed_count} failed")
                
                # If all succeeded, we're done
                if failed_count == 0:
                    return len(bulk_data)//2
                    
                # If any failed, fall back to individual indexing for failed ones
                logger.info("Falling back to individual indexing for failed documents")
        except Exception as e:
            logger.error(f"Bulk indexing failed: {str(e)}")
            success_count = 0
            failed_count = len(bulk_data)//2
        
        # Fall back to individual indexing for reliability
        if failed_count > 0:
            individual_successes = 0
            for i, (file_path, embedding) in enumerate(zip(file_paths, file_embeddings)):
                # Skip if already succeeded in bulk operation
                if success_count > 0 and i < success_count:
                    continue
                    
                document = {
                    "vector": list(embedding),
                    "logical_id": f"file_{problem_id}_{i}",
                    "type": "file",
                    "file_path": file_path,
                    "content_sample": file_contents.get(file_path, "")[:200] if file_contents else "",
                    "repository": repository,
                    "problem_id": problem_id,
                    "timestamp": time.time()
                }
                
                # Try up to 3 times to index each document
                for attempt in range(3):
                    try:
                        self.client.index(index=self.index_name, body=document)
                        individual_successes += 1
                        break
                    except Exception as e:
                        if attempt == 2:  # Last attempt
                            logger.error(f"Failed to index document {i} after 3 attempts: {str(e)}")
                        else:
                            time.sleep(1)  # Brief pause before retry
            
            logger.info(f"Individually indexed {individual_successes} additional documents")
            return success_count + individual_successes
        
        return success_count
            
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
