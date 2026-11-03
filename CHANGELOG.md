# Changelog

## Unreleased

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
