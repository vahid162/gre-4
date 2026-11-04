# Changelog

## Unreleased

### Fixed

- Set and verify the GRE ownership alias after interface creation, including
  kernels that ignore the initial netlink alias attribute; retain strict
  ownership checks during cleanup.
- Check role-specific commands and prepare Kharej conntrack before changing
  forwarding, firewall rules, or an existing connection. Keep the same checks
  in the generated runtime helper without unloading shared kernel modules.
- Confirm the connection is active after systemd startup commands before
  reporting successful setup, including versions that return success from
  `enable --now` despite a failed start.
- Accept mixed-case OpenSSH configuration dump directives when detecting SSH
  ports before removing shared UFW rules; keep invalid or unknown ports blocked.
- Order GRE startup after the Ubuntu SSH service/socket, so shutdown cleanup
  can inspect SSH configuration before its runtime directory disappears.

### Tests

- Cover successful interface creation without an alias and preflight failures
  without changing an existing deployment.
- Add Ubuntu release coverage and disposable-VM acceptance for actual kernels,
  systemd, UFW, and multi-peer TCP/UDP traffic. Passing isolated tests alone
  remains insufficient evidence of live Ubuntu compatibility.

### Documentation

- Translate the main README into Persian and keep project release metadata in
  VERSION and CHANGELOG; use version-free download links with checksum gating.
- Add repository agent instructions for documentation language, versioning,
  pull requests, validation, and preservation of existing work.

## 1.1.0 - 2026-11-04

### Added

- Independent GRE connection profiles for multiple Iran gateways sharing one
  Kharej server, with stable tunnel subnets and per-profile systemd services.
- Profile selection, independent lifecycle operations, applied snapshots,
  serialized management/runtime changes, and retryable cleanup records.
- Explicit migration of recognized v1.0.1 singleton installations, preserving
  their addresses and active/enabled service intent with private backups.
- Multi-profile and migration regression coverage, generated-helper syntax and
  ShellCheck checks, and a three-server acceptance guide.

### Changed

- Scope NAT/forwarding ownership per profile; reconcile shared Kharej UFW
  allowances and retain host-wide tuning while another profile needs it.
- Reject conflicting peers, tunnel subnets, unsafe profile paths, and unowned
  interface collisions rather than replacing another deployment.

### Upgrade notes

- Interrupted migration rollback blocks new-profile startup and rechecks cleanup
  before restoring the singleton helper; partial restoration resumes separately.
- Interrupted edits release their per-profile lock automatically. Unassigned
  local IPv4 edits are rejected before stopping the working connection.
- Use explicit migration for an existing singleton deployment; a short outage
  is possible. Unknown helpers or ambiguous recovery state require manual review.
- Failed cleanup retains recovery data. Rollback does not overwrite live state
  or enable competing old/new service owners.
- This release does not add automatic client failover, load balancing, port
  translation, or encryption. The Kharej application must accept connections
  on all configured tunnel destination addresses.
- Repository checks use isolated substitutes. Live GRE/systemd/UFW acceptance
  on two Iran hosts and one Kharej host remains a separate deployment gate.

## 1.0.1 - 2026-11-03

### Fixed

- Preserve managed SSH allowances for ports specified by OpenSSH ListenAddress,
  including IPv6 listeners.
- Refuse to discard deployment recovery files while inactive UFW retains GRE4
  rules, including encoded UFW comments.
- Replace configuration atomically and preserve it on write or permission errors.
- Tag newly installed iptables rules and remove only owned rules; preserve
  untagged administrator and legacy rules for manual review.
- Validate real UFW file transformations with temporary fixtures; reject missing
  filter tables and malformed managed blocks without replacing the original.
- Record and restore owned forwarding/conntrack changes on stop, failed-start
  cleanup, and uninstall; preserve administrator changes and retry failed recovery.
  Legacy sysctl files without recovery records require manual review.

### Upgrade notes

- This release does not provide automatic migration or complete removal of
  initial-version deployments. Untagged iptables rules and legacy
  `gre4-ssh-safety` allowances require manual review.
- Existing sysctl files without recovery records block automatic setup/cleanup.
  Inactive UFW with remaining GRE4 rules also blocks cleanup while preserving
  deployment recovery files.
- Cleanup can stop the tunnel before reporting an error; use separate management
  access when reviewing or removing an older deployment.
- All 58 isolated regression tests pass. Live GRE/systemd/UFW integration on
  disposable hosts remains unverified.

## 1.0.0 - 2026-11-03

### Added

- Version metadata, release checksum verification instructions, and CI for the
  regression suite, Bash syntax, and ShellCheck warnings.
- Expanded regression coverage using temporary files and command substitutes.

### Fixed

- Stop and clean up using the old configuration before replacing it, so removed
  ports and changed peers do not leave their previous rules behind.
- Preserve existing managed SSH allowances with their source and interface
  restrictions; never create a global SSH allowance during cleanup.
- Repeating Setup regenerates the installed apply script and systemd unit.
- Report required UFW reload failures instead of reporting a successful start.
- Preserve pre-existing public UFW allowances and add managed rules only for
  missing port/protocol combinations, checking IPv4 and IPv6 separately.
- Propagate cleanup, UFW status-query, and rule deletion failures, stop retrying
  failed iptables deletions, and retain recovery files when uninstall fails.
- Run cleanup after failed systemd starts as well as normal stops, and retry
  cleanup for inactive units before changing their configuration.
- Refresh the cleanup helper atomically before upgrading older installations,
  and follow UFW's IPv6 configuration parsing and precedence.

### Upgrade notes

- Run the updated script and repeat the matching Setup option to install the
  new apply script and unit. Failed cleanup preserves the original configuration
  for a retry.
- OpenSSH is optional. If installed, invalid or unreadable configuration blocks
  managed UFW cleanup so existing SSH access rules remain intact.
- Review legacy orphaned rules and `gre4-ssh-safety` allowances manually; this
  release does not delete them automatically.
- Regression checks use command substitutes. Live GRE traffic and systemd/UFW
  integration still require validation on disposable Linux hosts.
