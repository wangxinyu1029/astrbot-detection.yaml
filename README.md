id: astrbot-detection

info:
  name: AstrBot Detection
  author: ProjectDiscoveryAI
  severity: medium
  description: |
    This template identifies the presence of AstrBot by analyzing its HTTP response headers and body content.
    AstrBot is commonly identified by its unique user-agent or specific response patterns.
  tags: bot, detection

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        User-Agent: AstrBot
        Accept: */*

    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "Server: AstrBot"
      - type: regex
        part: body
        regex:
          - "(?i)AstrBot detected"
      - type: word
        part: header
        words:
          - "X-Powered-By: AstrBot"

    stop-at-first-match: true
