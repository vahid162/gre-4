# gre-4

Configure a GRE tunnel between Iran and Kharej Linux servers. The Iran side
forwards selected TCP ports, with optional UDP; the Kharej side configures
matching UFW allowances when UFW is active.

## Requirements

- Root access and a Linux host running systemd.
- Bash 4 or newer, iproute2 (`ip`), iptables, and procps (`sysctl`).
- GRE protocol 47 permitted between the servers by the hosting network.
- UFW is optional. OpenSSH is optional; when installed, its configuration must
  be valid so cleanup can identify SSH ports and preserve existing allowances.
- `curl` for the download commands below; `sha256sum` to verify a release.

## Recommended: a verified release

For a published v1.0.0 release, download the script and its checksum file from
the release assets, then verify before running it. If the assets are not yet
available, use the main-branch download below:

```bash
release_url="https://github.com/vahid162/gre-4/releases/download/v1.0.0"
curl -fsSL "$release_url/gre4.sh" -o gre4.sh
curl -fsSL "$release_url/SHA256SUMS" -o SHA256SUMS
sha256sum --check SHA256SUMS && sudo bash ./gre4.sh
```

Run the script only if checksum verification succeeds. Release assets are listed
on the [releases page](https://github.com/vahid162/gre-4/releases).

## Quick run

To run the current `main` branch as root:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/vahid162/gre-4/main/gre4.sh")
```

## Download the current main branch

If you see intermittent issues on the Iran server, use the download-then-run method.
Downloading the complete file first avoids executing an interrupted stream.
Run these commands as root:

```bash
url="https://raw.githubusercontent.com/vahid162/gre-4/main/gre4.sh"
curl -fsSL "$url" -o /root/gre4.sh
chmod +x /root/gre4.sh
bash /root/gre4.sh
```

## Updating an existing installation

Run the updated local `gre4.sh` and repeat the matching Setup option to regenerate
the installed apply script and systemd unit. The old service is stopped before
its configuration is replaced. Management changes also clean up using the
previous configuration before applying the replacement, including when the unit
is already inactive. The cleanup helper is refreshed atomically before stopping
an older installation, so its strict error handling also applies during upgrades.
If cleanup fails, the original configuration remains so
the operation can be retried. A failed uninstall retains the configuration,
apply script, and systemd unit for recovery.

Existing managed SSH allow rules are retained with their original restrictions.
This includes listener ports specified by `ListenAddress`, for IPv4 and IPv6.
Cleanup creates no new SSH allowance. If installed OpenSSH has invalid or
unreadable configuration, managed UFW rules are kept and cleanup fails. SSH
servers other than OpenSSH are not detected.

Existing public UFW allowances remain user-owned. Setup adds tagged rules only
for missing port, protocol, and address-family combinations, checking IPv4 and
IPv6 separately. Required cleanup, rule deletion, or firewall reload failures
return an error. The systemd unit also runs cleanup after a failed start.

When UFW is inactive, cleanup checks its persistent rule files. If GRE4 rules
remain, removal and configuration replacement fail and retain the deployment
files for recovery. UFW is never enabled just to clean up. Review the owned rules
and preserve SSH access before retrying with UFW active, or arrange offline
cleanup yourself. An unreadable rule file also blocks cleanup.

New iptables rules carry a `gre4-managed` ownership comment. Cleanup removes only
tagged rules; matching administrator rules are preserved. Untagged rules from
older versions, including wide DNAT rules, cannot safely be distinguished from
administrator rules and need manual review. Legacy `gre4-ssh-safety` UFW allowances
are not removed automatically either. Do not delete an SSH allowance without
confirming another access path.

Configuration updates are written to a temporary file and atomically replaced
only after writing and setting private permissions succeeds. Failed replacement
keeps the previous configuration available for recovery.

New installations record the original forwarding and conntrack values under
`/var/lib/gre4/sysctl` before changing them. Stopping the service, failed-start
cleanup, and uninstall remove the owned sysctl files and restore those values.
Later administrator changes are preserved. A failed restoration retains the
recovery record so Stop or Remove can be retried.

Existing sysctl files without a recovery record, including files from older
GRE4 versions, are preserved and block automatic setup/cleanup. Their original
values cannot be reconstructed safely. Review and recover those settings, then
move the legacy files aside before retrying. Do not blindly disable forwarding
on a host that other services also use. Administrator-edited files and their
ownership records are retained; a new start requires resolving the edited file.

## Local regression checks

From the repository root, with Bash and Python 3 installed:

```bash
python3 -B -m unittest discover -s tests -v
bash -n gre4.sh
shellcheck --severity=warning gre4.sh
```

The tests use only the Python standard library and Bash. ShellCheck is required
for the final command and runs in CI alongside the regression and syntax checks.

The tests use temporary files and substitutes for systemd and networking commands.
They do not configure a tunnel or modify the host firewall. Live GRE traffic and
systemd/UFW integration still need validation on disposable Linux hosts.
