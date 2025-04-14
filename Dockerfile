FROM public.ecr.aws/lambda/python:3.9

# Copy requirements
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install additional packages for vector operations
RUN pip install boto3==1.28.64 requests==2.28.2 numpy==1.24.3 opensearch-py==2.2.0 requests-aws4auth==1.2.0

# Copy function code
COPY lambda_function.py .
COPY opensearch_service.py .
COPY vcs_service.py .
COPY apm_service.py .
COPY ai_service.py .
COPY ticket_service.py .

# Set handler
CMD ["lambda_function.lambda_handler"]
