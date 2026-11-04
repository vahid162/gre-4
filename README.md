# gre-4

Manage independent GRE tunnels from several Iran gateways to one Kharej
(outside) Linux server. Each Iran gateway forwards selected TCP ports, with
optional UDP, to the same port numbers on its own Kharej tunnel address.

Version 1.1.0 introduces connection profiles. The published `v1.0.1` release is
still the earlier single-connection version. No `v1.1.0` release assets are
available until a maintainer publishes them.

## Requirements

- Root access on Linux hosts running systemd, with Bash 4 or newer.
- iproute2 (`ip`), iptables, procps (`sysctl`), util-linux (`flock`), and the
  usual GNU core utilities.
- A distinct, static public IPv4 address for each server. The local endpoint
  must be configured on the local host.
- GRE **IP protocol 47**, allowed between each endpoint pair by the hosting
  network and any host firewall. This is a protocol number, not TCP/UDP port 47.
- UFW is optional. OpenSSH is optional; when installed, its configuration must
  be readable and valid so cleanup can preserve existing SSH allowances.
- The application on Kharej must listen on every selected tunnel destination,
  or on an appropriate wildcard address such as `0.0.0.0`. GRE4 does not edit
  application listener settings.

The runtime remains one downloadable `gre4.sh`. It generates a shared apply
helper and a systemd service template; Python is needed only for the tests.
GRE itself does not provide encryption.

## Run a source revision

Use a reviewed checkout of the revision you intend to install:

```bash
sudo bash ./gre4.sh
```

To download the current main branch, save the complete file before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/vahid162/gre-4/main/gre4.sh -o gre4.sh
sudo bash ./gre4.sh
```

An unmerged feature is available only in its feature branch or checkout.
Downloading `main` does not download an unmerged PR.

Published releases provide `gre4.sh` and `SHA256SUMS`. Download both from the
same release, then verify before running:

```bash
sha256sum --check SHA256SUMS
```

## Set up multiple Iran gateways

Start on Kharej and add one Iran peer at a time. Give each connection a short,
stable ID, for example `iran1`, `iran2`, or `iran3`. Enter the public endpoint
addresses, service ports, UDP choice, and a non-overlapping `/30` tunnel subnet.
Use the displayed connection summary to enter matching values on its Iran host.
Configuration is local: GRE4 does not log into or configure another server.

For example, all three gateways can forward `443,2096` to the same application:

| ID | Iran tunnel address | Kharej tunnel address | Subnet |
|---|---|---|---|
| `iran1` | `172.16.1.1/30` | `172.16.1.2/30` | `172.16.1.0/30` |
| `iran2` | `172.16.1.5/30` | `172.16.1.6/30` | `172.16.1.4/30` |
| `iran3` | `172.16.1.9/30` | `172.16.1.10/30` | `172.16.1.8/30` |

These are examples, not reserved address space. Check both hosts for conflicts
with existing addresses, routes, VPNs, containers, and other GRE4 profiles.
Default routes are not treated as subnet conflicts. Once assigned, addresses
stay with a profile; removing another profile does not renumber them.

On each Iran server choose the Iran gateway role and enter its corresponding
profile settings. The Kharej public IP is the same for all Iran gateways; its
internal tunnel address differs for each connection. Reusing `443` on distinct
Iran public IPs is supported. Port translation, load balancing, and automatic
client failover are not provided.

## Manage a connection

Select a connection before changing its ports, peer IP, or UDP setting, or
starting, stopping, restarting, and removing it. Adding or operating one profile
does not deliberately restart another profile. Actions affect only the local
server; remove both ends separately when retiring a complete connection.

New interfaces are named from the connection ID, and services use instances
such as `gre4@iran1.service`. Local service state and interface presence do not
prove that the remote path or application is reachable. Test actual traffic as
described in [the three-server acceptance guide](docs/three-server-acceptance.md).

Profiles are stored privately under `/etc/gre4/profiles/`. Applied snapshots and
recovery data live under `/var/lib/gre4/`. Cleanup uses the applied snapshot even
if the editable configuration has changed or is missing. Do not delete recovery
files to force a failed operation to appear successful.

If start or cleanup fails, retain the deployment files and retry the selected
profile's cleanup. On a 1.1.0 profile installation, if its editable configuration
is missing, the installed helper can still use the applied snapshot:

```bash
sudo systemctl stop gre4@iran1.service
sudo /usr/local/sbin/gre4-apply.sh stop iran1
```

Use the affected ID in place of `iran1`; this command form is for the profile
helper, not the old v1.0.1 singleton helper. Restore a valid configuration before
starting it again. A cleanup-pending profile cannot be started again until its
cleanup succeeds. Configuration replacement is atomic; write or permission
failures preserve the previous configuration.

### Firewall and shared settings

Per-profile NAT and forwarding rules carry ownership comments. Cleanup preserves
untagged administrator rules. Kharej UFW service-port allowances are shared:
removing one profile keeps a port needed by another. GRE peer allowances are
restricted to the configured public endpoint pairs. Existing SSH restrictions
and administrator-owned public allowances are preserved.

With inactive UFW, persistent obsolete GRE4 rules can block cleanup. Rules still
needed by another profile are distinguished from obsolete rules; GRE4 does not
enable UFW solely for cleanup. Inspect the reported rules and preserve a separate
management path before correcting the firewall and retrying.

Forwarding and Kharej connection-tracking tuning are host-wide resources. Their
original values are captured once, remain available to dependent profiles, and
are restored only after the final dependent cleanup completes. Later
administrator changes are preserved. Changed shared runtime values, unowned
files, or administrator-edited sysctl files can require manual review before
a new start; GRE4 does not silently overwrite them.

## Migrate a v1.0.1 installation

Use the explicit migration menu option, rather than creating a second deployment
on top of the old singleton service. Migration supports the recognized canonical
v1.0.1 helper and installation layout. Unknown or modified legacy helpers and
ambiguous ownership/recovery state are rejected for manual review.

Migration backs up the old configuration, helper, service, and recovery data in
a private location. It stops and cleans the old deployment with the verified old
helper **before replacing it**, then imports the connection as `legacy`, keeping
its `GRE` interface, public endpoints, tunnel addresses, ports, and UDP setting.
The old service's active and enabled states are preserved: an intentionally
stopped or disabled installation is not silently started or enabled.

Expect a short interruption on the migrated host. Either host can migrate first
because the original tunnel addresses are retained. The old and new services
must never manage the tunnel simultaneously.

Rollback is attempted only after new-profile cleanup succeeds. Incomplete
cleanup retains the backup and recovery records and reports recovery needed.
Old recovery backups are not copied over live recovery state. Retain the backup
after a successful migration until you have completed server acceptance tests.
Older untagged iptables rules, legacy `gre4-ssh-safety` allowances, and sysctl
files without recovery records still require manual review.

## Local checks and server acceptance

From the repository root:

```bash
python3 -B -m unittest discover -s tests -v
bash -n gre4.sh
shellcheck --severity=warning gre4.sh
```

Tests use Python's standard library, Bash, temporary directories, and substitutes
for networking/systemd commands. They do not configure a real tunnel or modify
the host firewall/sysctls. Tests also validate the generated helper's Bash syntax
and ShellCheck warnings when ShellCheck is available. CI installs and requires
ShellCheck, so helper linting is mandatory there.

Passing repository checks is not live GRE/systemd/UFW validation. Before using
this version for production traffic, run the
[three-server acceptance guide](docs/three-server-acceptance.md) on disposable
hosts and record the outcome, including migration and recovery failures.
