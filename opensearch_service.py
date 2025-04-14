import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import json
import time
import os

class OpenSearchService:
    def __init__(self, endpoint=None, index_name="file-vectors"):
        self.endpoint = endpoint or os.environ.get("OPENSEARCH_ENDPOINT")
        self.index_name = index_name
        
        # Get AWS credentials
        region = self.endpoint.split('.')[1] if self.endpoint else 'us-east-1'
        credentials = boto3.Session().get_credentials()
        self.awsauth = AWS4Auth(
            credentials.access_key,
            credentials.secret_key,
            region,
            'es',
            session_token=credentials.token
        )
        
        # Initialize OpenSearch client
        self.client = OpenSearch(
            hosts=[{'host': self.endpoint, 'port': 443}],
            http_auth=self.awsauth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection
        )
    
    def index_vector(self, doc_id, vector, metadata=None):
        """Index a vector in OpenSearch"""
        if metadata is None:
            metadata = {}
        
        document = {
            "vector": vector,
            **metadata
        }
        
        response = self.client.index(
            index=self.index_name,
            body=document,
            id=doc_id,
            refresh=True
        )
        
        return response
    
    def search_similar_vectors(self, vector, k=5):
        """Find similar vectors in OpenSearch"""
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
        
        response = self.client.search(
            body=query,
            index=self.index_name
        )
        
        return response['hits']['hits']
    
    def store_file_vectors(self, problem_id, file_paths, file_embeddings, file_contents=None, repository=None):
        """Store file vectors in bulk"""
        success_count = 0
        
        for i, (file_path, embedding) in enumerate(zip(file_paths, file_embeddings)):
            try:
                content_sample = file_contents.get(file_path, "")[:200] if file_contents else ""
                
                self.index_vector(
                    f"file_{problem_id}_{i}",
                    embedding,
                    {
                        "type": "file",
                        "file_path": file_path,
                        "content_sample": content_sample,
                        "repository": repository,
                        "problem_id": problem_id,
                        "timestamp": time.time()
                    }
                )
                success_count += 1
            except Exception as e:
                print(f"Error indexing file {file_path}: {str(e)}")
        
        return success_count