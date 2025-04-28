# Lambda-build
# A generic architecture among VCS - Bitbucket, Github, Gitlab and ADO. Borads - ADO and Jira. APM tools - Datadog and Dynatrace

# Secret manager needs
1. ANTHROPIC_API_KEY = "sk-ant...."
2. VCS_TOKEN = "bitbucket - ATB.." or "Github - github_pat_..."
# If bitbucket
Bitbucket UI > Personal bitbucket settings > Account Settings [get username of bitbucket]
                                           > App passwords [Create API key with all appropriate permissions]
# If Github
Github UI > Settings > Developer Settings > Personal Access Tokens > Fine grained tokens [Create a token with appropriate formats]

3. VCS_EXTRA_PARAMS = {} # only in case of bitbucket, if github leave it empty
# If Bitbucket
{"workspace":"..", "username": ".."}

4. APM_API_KEY = "..."
# If Dynatrace
This is regular access key which is with some read access on metrics only read.metrics scope is more than enough

# If Datadog
This is API key not APP key

5. NOTIFICATION_WEBHOOK = ".."   # This is generated with webhook configuring in a teams channel

6. TICKET_PARAMS = {}
# If JIRA Board
{"server":"https://username.atlassian.net","username":"jira-account-username","api_token":"api-token","project_key":"Board's scrum project key","default_board":"SCRUM Board","default_sprint":"SCRUM Sprint 1","assign_to_sprint":true}

  # For JIRA server
    JIRA UI > Manage account > Product settings

  # for JIRA api-token:
    JIRA UI > Manage account > security > API token (create and manage api tokens) > create classic API token

  # for Username
    Mostly email is more than enough
  # for project key
    Jira UI > Project > Project Settings > Project Key

7. APM_EXTRA_PARAMS = {}
# If datadog
  {"app_key":"..","site": "us5/app/<EMPTY>"}

# If dynatrace
{"base_url":"https://domain.live.dynatrace.com", "uses_grail":true, "client_id": "..", "oauth_client_secret":".."}

  # For client ID and oauth_client_secret
  Dynatrace UI > Account Management > Identity and access management > OAuth Client > Create client [storage:logs:read, storage:buckets:read] with these       permissions.

  # FYI: Dynatrace logs cannot be fetched directly with access token, logs collection is different from all other api accessing in Dynatrace!...So, our current configuration if logs can be handled with APM EXTRA PARAMS if metric API key is more than enough.

8. OPENSEARCH_ENDPOINT = ".."

   # check opensearch service whether its connecting with valid index there at your opensearch console or not
   # Also add inline policy {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "aoss:*",
                "Resource": "*"
            }
        ]
    }
   to the lambda exeucution role

# Lambda Environment Varibales
APM_TYPE = datadog/dynatrace
BEDROCK_MODEL_ID = amazon.titan-embed-text-v1
ENABLE_APM_TOOLS = true
REPO_DEFAULT_BRANCH = main/master/dev/stag...
REPO_NAME = Codebase target repo name 
REPO_OWNER = if bitbucket - repo owner name
             if bitbucket - workspace name
SECRET_NAME = secret manager name
TICKET_TYPE = JIRA/ADO
VCS_TYPE = bitbucket/github

