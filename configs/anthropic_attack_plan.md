# Anthropic Bug Bounty — Attack Plan
# Target: $7,500-$10,000 CRITICAL bugs

## HIGHEST VALUE TARGETS

### 1. API Key IDOR (console.anthropic.com)
- Create two accounts (jardani101@wearehackerone.com + jardani102@wearehackerone.com)  
- Get API key ID from account A
- Try accessing/modifying it from account B session
- Endpoint: /api/organizations/{org_id}/api_keys/{key_id}
- If B can read A's API key → CRITICAL $10,000

### 2. Organization/Workspace IDOR
- Create two orgs
- Try accessing org A resources from org B session
- /api/organizations/{org_id}/members
- /api/organizations/{org_id}/usage
- /api/organizations/{org_id}/settings

### 3. Conversation IDOR (claude.ai)
- Create two claude.ai accounts
- Share conversation ID from account A
- Try reading it from account B
- /api/organizations/{org}/chat_conversations/{conv_id}

### 4. SSRF via file/image processing
- Upload file to claude.ai
- Try SSRF payloads in filename or content
- Internal Anthropic infra could be accessible

### 5. OAuth token theft
- Test OAuth flows on claude.ai
- Check redirect_uri validation
- Check state parameter validation

### 6. Stored XSS in conversation
- Inject XSS payload in conversation
- Share conversation with another user
- If payload executes → Stored XSS → HIGH/CRITICAL

### 7. Race condition on API key creation
- Simultaneously create multiple API keys
- Check if limits can be bypassed

## REQUIRED FOR EACH SUBMISSION
1. Create test account: jardani101@wearehackerone.com
2. Add header: X-HackerOne-Handle: jardani101
3. Reproduce manually — tool finds it, you verify it
4. Write report yourself (not AI-generated text)
5. Include working curl PoC

## WHAT NOT TO SUBMIT
- Missing headers
- Rate limiting  
- Jailbreaks (different program)
- Social engineering
- DoS
