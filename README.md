# gre-4

## Quick run

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/vahid162/gre-4/main/gre4.sh")
```

## Recommended (more stable on Iran server)

If you see intermittent issues on the Iran server, use the download-then-run method.
This approach is more stable and practically removes stream/execution errors:

```bash
url="https://raw.githubusercontent.com/vahid162/gre-4/main/gre4.sh"
curl -fsSL "$url" -o /root/gre4.sh
chmod +x /root/gre4.sh
bash /root/gre4.sh
```
