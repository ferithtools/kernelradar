# Slack and Telegram

Both work as plain HTTP POST receivers, so use the kernelradar webhook.

## Config (shared)

```toml
[webhook]
enabled = true
url     = "<see below>"
severity_filter_alert_or_higher = true   # avoid spam from Warnings
timeout_secs = 3
```

Each alert is POSTed as JSON. The receiver decides how to render it.

## Slack (incoming webhook)

1. Create an Incoming Webhook in Slack → get a URL like
   `https://hooks.slack.com/services/T0000/B0000/XXXX`
2. Slack expects a body with `text` field. Direct kernelradar JSON
   won't render nicely. Use a small adapter:

```python
# /usr/local/bin/kernelradar-to-slack
#!/usr/bin/env python3
import sys, json, urllib.request

SLACK_URL = "https://hooks.slack.com/services/.../..."

for line in sys.stdin:
    a = json.loads(line)
    msg = f"*[{a['severity']}] {a['detector']}*\n{a['title']}\n" \
          f"`pid={a['pid']} uid={a['uid']} comm={a['comm']}`"
    req = urllib.request.Request(
        SLACK_URL,
        data=json.dumps({"text": msg}).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=3)
```

```bash
# Pipe kernelradar JSON output through the adapter:
kernelradar --format=json daemon | /usr/local/bin/kernelradar-to-slack
```

## Telegram

1. Create a bot via @BotFather → token `123:ABC...`.
2. Get your chat_id: send /start to bot, then
   `curl https://api.telegram.org/bot123:ABC.../getUpdates`.
3. Post messages:

```python
# /usr/local/bin/kernelradar-to-telegram
import sys, json, urllib.request, urllib.parse

BOT  = "123:ABC..."
CHAT = "-100123456789"

def send(text):
    url = f"https://api.telegram.org/bot{BOT}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": CHAT, "text": text, "parse_mode": "Markdown",
    }).encode()
    urllib.request.urlopen(url, data=data, timeout=3)

for line in sys.stdin:
    a = json.loads(line)
    send(f"*[{a['severity']}] {a['detector']}*\n"
         f"{a['title']}\n"
         f"`pid={a['pid']} uid={a['uid']} comm={a['comm']}`")
```

## Native webhook (no adapter)

If you have a custom receiver - kernelradar will send the alert as-is.
The full Alert schema is documented in `docs/logging.md`.
