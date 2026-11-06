# Changelog

## Unreleased

## 1.3.2 - 2026-11-06

### Changed

- Require installer and upgrade changes to demonstrate compatibility in CI
  using actual artifacts from the preceding stable release, including settings,
  service intent, failure rollback and repeated-entry preservation.
- Document migration and provenance requirements for known modified deployments
  and temporary server patches without relaxing unknown-artifact protections.

### Validation and limits

- Repository policy and release metadata only; installer, helper and unit code
  are unchanged. These rules require evidence for future relevant changes;
  this release does not add CI scenarios or deploy to production servers.

### فارسی

- قواعد ارتقا، آزمون با فایل‌های واقعی انتشار قبلی و بررسی حفظ تنظیمات، وضعیت
  سرویس، برگشت پس از شکست و اجرای مجدد بدون restart را الزامی می‌کنند.
- نصب‌های اصلاح‌شدهٔ شناخته‌شده باید مسیر انتقال مشخص داشته باشند و وصله‌های
  موقت با هش و راه برگشت ثبت شوند. این انتشار فقط قوانین مخزن را تغییر می‌دهد.

## 1.3.1 - 2026-11-06

### Fixed

- Repair a recognizable partial profile installation through the existing
  verified-release installation command instead of rejecting every incomplete
  runtime pair. Back up the existing evidence before creating missing files;
  preserve profile bytes, public and tunnel addresses, ports and UDP settings.
- Preserve inactive and boot-disabled connections during repair. Unknown or
  modified artifacts, unsafe paths, unit overrides and ambiguous recovery state
  still require manual review rather than automatic overwrite.
- Make interrupted connection setup safe to revisit, with staged artifacts and
  retained progress evidence. Retry must not overwrite a later administrator
  change or discard a profile that was already saved.

### Validation and limits

- Exercise the reported official-helper/missing-template case, repeated entry,
  interrupted setup and repair, failure cleanup and preservation of service
  intent in regression tests and disposable Ubuntu VM acceptance.
- Recovery remains bounded to installations whose ownership and current state
  can be verified. Existing migration and upgrade recovery limits still apply.
- The default installation URL remains unchanged. Publication does not deploy
  the script or change settings on production servers.

### فارسی

- نصب ناقصِ قابل شناسایی با همان دستور نصب و پس از بکاپ ترمیم می‌شود؛ فایل
  تنظیمات، آدرس‌ها، پورت‌ها و انتخاب UDP حفظ می‌شوند.
- ترمیم، اتصال غیرفعال را شروع یا برای بوت فعال نمی‌کند. فایل سفارشی، مسیر
  ناامن یا وضعیت بازیابی مبهم همچنان برای بررسی دستی حفظ می‌شود.
- مراحل افزودن اتصال برای اجرای دوباره پس از قطع عملیات شواهد نگه می‌دارند؛
  تغییر بعدی مدیر سرور با retry بازنویسی نمی‌شود.

## 1.3.0 - 2026-11-06

### Added

- Add independent read-only status, diagnostics and backup views that do not
  download an update, install files, restart services or repair host settings.
- Add explicit guarded recovery of supported upgrade backups, with a concrete
  backup summary and confirmation before changing an installation. Validate
  private recovery evidence, target paths, profiles and installed artifacts;
  retain ambiguous or incomplete state for manual review.
- Retry invalid connection inputs at the relevant prompt and show the complete
  settings before applying a new connection. EOF aborts without saving a profile.

### Changed

- When a newer release produces identical helper and unit bytes, retain service
  identity and update release metadata with a backup, without a runtime cutover.
  Metadata-only failures and recovery do not restart connections.
- Prepare changed-runtime prerequisites before stopping services; keep the
  default fixed-command verified-release installation and same-release no-op.

### Fixed

- Retry transient release reads with bounded backoff and poll for visibility
  after successful publication steps. Address delayed draft, asset and published
  state visibility without blindly replaying mutations or overwriting assets.
- Keep authentication errors, wrong release targets and corrupt assets fatal.

### Administration and upgrade notes

- Document GitHub's administrator-controlled immutable release setting and its
  verification. A code change alone does not enable this repository setting;
  published tags and assets are never rewritten by the publisher.
- Recovery of older backups without sufficient verification evidence remains
  manual. Runtime snapshots are never copied over live host state. Existing
  canonical-singleton rollback limitations remain unchanged.
- A normal invocation still selects the latest stable release, including after
  an explicit rollback; use read-only commands when inspecting a restored host.

### فارسی

- وضعیت، عیب‌یابی و فهرست بکاپ‌ها مسیر فقط‌خواندنی دارند و ارتقا یا restart
  انجام نمی‌دهند. ورودی نامعتبر در همان سؤال اصلاح می‌شود و خلاصهٔ تنظیمات
  پیش از اعمال نمایش داده می‌شود.
- اگر فایل اجرایی تونل و قالب سرویس تغییر نکرده باشند، ارتقا فقط رکورد انتشار
  را با بکاپ به‌روزرسانی می‌کند و اتصال‌ها قطع نمی‌شوند.
- بازیابی بکاپ‌های قابل تأیید با نمایش وضعیت و تأیید صریح ارائه می‌شود؛ دادهٔ
  مبهم و بکاپ قدیمیِ فاقد شواهد کافی برای بررسی دستی حفظ می‌شود.
- انتشار برای خطاهای گذرای خواندن و تأخیر دیده‌شدن پیش‌نویس و فایل‌ها تلاش
  مجدد محدود دارد؛ خطای دسترسی، تگ نادرست یا فایل خراب همچنان متوقف می‌شود.
- قفل ریلیزهای بعدی در GitHub یک تنظیم مدیریتی جداگانه است و روش فعال‌سازی
  و بررسی آن در راهنمای انتشار آمده است. سرور عملیاتی از طریق CI تغییر نمی‌کند.

## 1.2.0 - 2026-11-05

### Added

- Keep the documented raw-main command as a release bootstrap: resolve the
  latest stable release once, download both assets from that exact tag, strictly
  validate the checksum manifest and payload, then execute the verified script.
- Automatically upgrade recognized profile deployments with private backups,
  durable transaction records, local health checks and verified rollback when
  cleanup succeeds. Preserve profile bytes and active/enabled service intent.
- Record installed releases; opening the same release again leaves services
  running without reinstallation or restart. Refuse automatic downgrades,
  modified executables, custom units, ambiguous state and unfinished recovery.
- Adopt the exact canonical unmarked profile helper from v1.1.1, and route the
  recognized v1.0.1 singleton through its existing bounded migration path.

### Tests

- Cover release pinning, rejected downloads/manifests, payload verification,
  temporary-file cleanup and recursive handoff without public-network access.
- Cover upgrade intent preservation, same-release no-op, preflight rejection,
  unknown installations, rollback and retained recovery records on failures.
- Recognize only independently derived canonical helper fingerprints, including
  the different function serialization emitted by Ubuntu 22.04's Bash 5.1.
- Extend disposable three-VM Ubuntu acceptance with previous-release fixtures,
  outside-only upgrade while Iran remains old, a real GRE-start failure and
  rollback, interruption followed by reboot with persistent masks, and service
  identity checks for same-release no-op.

### Upgrade notes

- Run the same command separately on each host. No scheduler or remote-peer
  deployment is installed; destination applications retain their own settings.
- Active connections may pause during upgrade. Inactive services remain
  inactive, and enabled/disabled intent is retained.
- Interrupted cutovers may leave persistent per-instance masks. Preserve the
  backup and pending record and follow its RECOVERY.txt; do not restore runtime
  snapshots over live networking. Failed or unverified cleanup requires manual
  recovery. Existing canonical-singleton rollback limitations remain.
- HTTPS and the publisher account remain the trust basis; checksums downloaded
  from the same release are not independent signatures.

### فارسی

- فرمان ثابت نصب، آخرین انتشار پایدار را پیدا می‌کند و اسکریپت و checksum را
  از همان تگ مشخص می‌گیرد؛ اجرای فایل به تأیید دقیق checksum وابسته است.
- نصب شناخته‌شده با بکاپ و حفظ آدرس‌ها، پورت‌ها، پروفایل‌ها و وضعیت سرویس‌ها
  ارتقا پیدا می‌کند. اجرای دوبارهٔ همان انتشار، اتصال‌ها را restart نمی‌کند.
- نصب ناشناخته یا ویرایش‌شده و بازیابی ناتمام خودکار بازنویسی نمی‌شوند.
  در قطع عملیات یا شکست پاک‌سازی، بکاپ و journal حفظ می‌شوند و ممکن است
  بازیابی دستی لازم باشد. اتصال فعال هنگام ارتقا ممکن است وقفه داشته باشد.
- ارتقا فقط برای همان میزبان است؛ سرور دیگر و برنامهٔ مقصد تغییر نمی‌کنند.
  آزمون‌های واقعی Ubuntu، ارتقای خارج در کنار ایرانِ قدیمی، شکست و rollback
  و اجرای دوبارهٔ بدون restart را بررسی می‌کنند.

## 1.1.1 - 2026-11-05

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
- Normalize SSH dump directive names only in the cleanup child of a verified
  canonical legacy helper during migration, preserving its original backup,
  port values, and failure status on newer OpenSSH versions.

### Tests

- Cover successful interface creation without an alias and preflight failures
  without changing an existing deployment.
- Add Ubuntu release coverage and disposable-VM acceptance for actual kernels,
  systemd, UFW, and multi-peer TCP/UDP traffic. Passing isolated tests alone
  remains insufficient evidence of live Ubuntu compatibility.
- Retry SSH transport failures while waiting for cloud-init after a VM reboot,
  without accepting cloud-init failure statuses or retrying mutating commands.
- Match disposable VM network interfaces by MAC without forcing a rename during
  boot; retain the same test addresses and routes.

### Documentation

- Require a new release for every completed change, including documentation,
  CI, and repository rules; publish verified script/checksum assets after CI.
- Clarify that downloading and running main opens the menu; existing deployments
  require the appropriate management or migration action to apply an update.
- Document the remaining manual-recovery case when rollback restarts an
  unchanged legacy helper with retained SSH rules on mixed-case OpenSSH builds.
- Translate the main README into Persian and keep project release metadata in
  VERSION and CHANGELOG; use version-free download links with checksum gating.
- Add repository agent instructions for documentation language, versioning,
  pull requests, validation, and preservation of existing work.

### فارسی

- نشان مالکیت تونل صریح ثبت و بررسی می‌شود و پیش‌نیازهای conntrack و فایروال
  پیش از تغییر اتصال فعال بررسی می‌شوند.
- گزارش موفقیت systemd، ترتیب پاک‌سازی هنگام خاموش‌شدن و سازگاری با قالب جدید
  خروجی OpenSSH، از جمله پاک‌سازی در مهاجرت نصب رسمی قدیمی، اصلاح شده‌اند.
- آزمون‌های واقعی سه ماشین مجازی برای Ubuntu 22.04، 24.04، 26.04 و 26.10،
  ترافیک TCP/UDP، UFW، بوت و مهاجرت را پوشش می‌دهند. نتیجه به محیط ثبت‌شده
  محدود است؛ در بعضی حالت‌های شکست مهاجرت، بازگشت به helper قدیمی همچنان
  ممکن است بازیابی دستی بخواهد و بکاپ و رکوردهای بازیابی حفظ می‌شوند.
- هر مجموعهٔ تغییر، حتی مستندات و قوانین، باید در یک Release جدید عرضه شود.
  دریافت و اجرای اسکریپت فقط منو را باز می‌کند؛ نصب موجود با انتخاب عملیات
  مناسب مدیریت یا مهاجرت به‌روزرسانی می‌شود.
- انتظار آماده‌شدن ماشین آزمایشی پس از بوت، خطای گذرای ارتباط SSH را دوباره
  بررسی می‌کند؛ خطای واقعی cloud-init همچنان باعث شکست تست می‌شود.
- کارت‌های شبکهٔ ماشین آزمایشی با MAC تطبیق داده می‌شوند و تغییر نام اجباری
  هنگام بوت ندارند؛ آدرس‌ها و مسیرهای آزمایش حفظ می‌شوند.

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
