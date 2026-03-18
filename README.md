# PII MCP Server

**Privacy and PII compliance tools for AI agents — via MCP.**

[PII API](https://pii-api.rebaselabs.online) detects, masks, and audits Personally Identifiable Information without sending data to an LLM. This MCP server makes those tools available to any Claude, ChatGPT, or MCP-compatible agent.

## Tools

| Tool | Description |
|------|-------------|
| `detect_pii` | Scan text and return all PII found with types and positions |
| `mask_pii` | Replace PII with markers, fake data, hashes, or pseudonyms |
| `audit_pii` | Full GDPR compliance report with risk score |
| `scan_and_mask` | Detect + mask in one call (most common usage) |

## Supported PII Types

Names, emails, phones, SSNs, credit cards, bank accounts, IP addresses, physical addresses, dates of birth, passport numbers, driver's licenses, medical record numbers, and more (20+ types).

## Installation

```bash
pip install pii-mcp
```

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "pii": {
      "command": "uvx",
      "args": ["pii-mcp"],
      "env": {
        "PII_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Usage Examples

```
"Scan this user comment for any personal information before storing it"
→ detect_pii("Hi I'm John, my email is john@test.com and phone is 555-1234")

"Sanitize this customer support log before sending to our analytics provider"
→ mask_pii(log_text, strategy="mask")

"Replace all real names/emails in this dataset with realistic fake data"
→ mask_pii(text, strategy="fake")

"Run a GDPR audit on this form submission"
→ audit_pii(form_data)
```

## License

MIT
