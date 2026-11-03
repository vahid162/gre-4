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

## Updating an existing installation

Run the updated local `gre4.sh` and repeat the matching Setup option to regenerate
the installed apply script and systemd unit. The old service is stopped before
its configuration is replaced. Management changes also stop the service using
the previous configuration before applying the replacement.

Existing managed SSH allow rules are retained with their original restrictions.
No new SSH allowance is created during cleanup. OpenSSH remains optional. When
it is installed but its ports cannot be detected, managed UFW rules are kept and
a warning is printed; startup refuses to report success when required firewall
cleanup or reload fails. SSH servers other than OpenSSH are not detected.

Rules orphaned by older versions, including `gre4-ssh-safety` allowances, are not
removed automatically. Review the existing iptables/UFW rules before upgrading;
do not delete an SSH allowance without confirming another access path.

## Local regression checks

From the repository root, with Bash and Python 3 installed:

```bash
python3 -B -m unittest discover -s tests -v
bash -n gre4.sh
```

The tests use temporary files and substitutes for systemd and networking commands.
They do not configure a tunnel or modify the host firewall. Live GRE traffic and
systemd/UFW integration still need validation on disposable Linux hosts.
