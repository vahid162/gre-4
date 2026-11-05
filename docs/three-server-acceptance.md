# Three-server acceptance for GRE4 1.1.0

This is a manual staging gate, not evidence that a deployment has passed.
Use two disposable Iran Linux hosts (A and B), one disposable Kharej host (X),
and an operator/client machine that can reach both Iran public IPs. Keep a
provider console or another management path throughout the test. Do not run the
failure or reboot cases on production traffic.

The automated Ubuntu VM matrix and its evidence limits are described in
[Ubuntu compatibility](ubuntu-compatibility.md). Those isolated VM runs do not
replace this gate for provider GRE filtering, public networking, or an existing
production deployment.

Record the source commit, Linux distribution/kernel, systemd/UFW/iptables
versions, public endpoint addresses, tunnel subnets, selected ports, UFW state,
and the result of each case. Never include credentials in the record.

## 1. Preflight and application

1. Verify root access, Bash 4+, iproute2, iptables, procps, and util-linux/flock
   on all three hosts. Confirm each public endpoint is actually local to its
   host and GRE IP protocol 47 is permitted by the provider and host firewall.
2. Check existing addresses and routes. Use the example subnets only if they do
   not overlap a VPN, container network, or another deployment.
3. Save the initial firewall and sysctl state for comparison. Identify existing
   SSH allowances, including nonstandard OpenSSH ListenAddress ports. Do not
   remove or broaden those allowances during this test.
4. On X, run the real target application, listening on both Kharej tunnel
   addresses or an appropriate wildcard address. A temporary TCP fixture on an
   otherwise unused disposable host can be started in a separate terminal:

   ```bash
   python3 -m http.server 2096 --bind 0.0.0.0
   ```

   Do not replace an existing application to run this fixture. Python is an
   optional acceptance-test tool, not a GRE4 runtime dependency.

## 2. Two simultaneous connections

On X, add both profiles using the local menu:

| ID | Remote public IP | Iran tunnel address | Kharej tunnel address | Ports |
|---|---|---|---|---|
| `iran1` | A's public IPv4 | `172.16.1.1/30` | `172.16.1.2/30` | `2096` |
| `iran2` | B's public IPv4 | `172.16.1.5/30` | `172.16.1.6/30` | `2096` |

On A and B, add their corresponding Iran gateway connection, using X's public
IP and exactly the matching ID, subnet, ports, and UDP choice. Confirm the summary
before applying. Use an alternate non-overlapping subnet if preflight rejected
these examples.

From the separate client, request both Iran public endpoints:

```bash
curl --fail --connect-timeout 5 http://IRAN_A_PUBLIC_IP:2096/
curl --fail --connect-timeout 5 http://IRAN_B_PUBLIC_IP:2096/
```

Replace placeholders with real addresses. Run requests concurrently and repeat
them while performing the following cases. Test from outside the gateway being
tested: a gateway's own locally generated request does not exercise its incoming
PREROUTING DNAT path. Confirm responses come from the application on X, rather
than an unrelated service on A or B.

Check each service instance and interface, but do not treat an UP interface or
an active oneshot service as proof of remote application connectivity.

## 3. Independent changes and shared resources

1. Stop `iran1` on X. Its traffic should stop; requests through B must continue.
   The shared UFW TCP/2096 allowance and settings needed by `iran2` must remain.
2. Start `iran1` again. Both paths must recover without duplicate interfaces or
   rules. Repeat start/restart and inspect the result for idempotency.
3. Add a second application port only to `iran1`, updating the matching endpoint
   settings. Remove it again; `iran2` and the shared port must remain intact.
4. Remove `iran1` on X and A. `iran2` must retain its addresses, service state,
   firewall rules, and traffic. Adding a new profile must not renumber `iran2`.
5. Remove the final profile. Compare owned sysctl and firewall changes with the
   captured originals. Pre-existing administrator and SSH allowances must remain.
6. Repeat with UFW active on X. Run the cases with UFW absent/inactive as
   appropriate to the intended environment; provider/host GRE permission still
   applies. Do not enable UFW on an inaccessible host just to finish a test.

## 4. Optional UDP

Enable UDP on one matching pair while leaving it disabled on the other.
On X, a temporary echo fixture can share UDP/2096 with the TCP fixture:

```bash
python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(('0.0.0.0', 2096))
    while True:
        data, peer = s.recvfrom(2048)
        s.sendto(data, peer)
PY
```

From the separate client, send a unique payload to the UDP-enabled Iran public
IP and require the same payload in the response. Require a bounded timeout
through the UDP-disabled peer, then verify TCP still works through both.

```bash
python3 - <<'PY'
import socket
host = input('UDP-enabled Iran public IPv4: ').strip()
message = b'gre4-staging-udp'
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(5)
    s.sendto(message, (host, 2096))
    response, _ = s.recvfrom(2048)
    assert response == message, response
    print('UDP echo passed')
PY
```

A missing UDP reply alone is not a conclusive firewall diagnosis; inspect the
application and captures at both ends before attributing the failure.

## 5. Reboot, failed cleanup, and concurrency

- Reboot X, then A/B separately. Enabled profiles must return and disabled
  profiles must remain disabled. Verify actual TCP/UDP after each reboot.
- On a disposable setup with persistent GRE4 UFW rules, make UFW inactive and
  attempt removal. Obsolete persistent rules must produce a reported cleanup
  failure and retained recovery data; rules belonging to another profile must
  not be mistaken for that profile's obsolete rules. Correct the reported
  firewall condition while preserving management access, then retry cleanup.
- Attempt two management actions from different terminals. They must serialize
  or report a lock conflict without lost configuration or an indefinitely
  waiting systemctl/helper cycle.
- Try an edit with a valid-format local IPv4 that is not assigned to the host.
  It must fail before changing the configuration or interrupting current traffic.
- On disposable hosts, interrupt an editing process while its edit is live.
  A competing start must be excluded while the editor runs. After the editor
  dies, stop/start must recover without deleting guard files by hand.
- Induce a second-profile setup failure using a conflicting unowned interface.
  The interface must not be deleted, and the first profile's traffic must remain.
  Fix the conflict and verify the failed profile can be retried safely.
- Compare state after failed operations with the prior snapshot. Retain all
  recovery files until the affected cleanup has actually succeeded.

## 6. Migrate a real v1.0.1 pair

Use a separate disposable pair with a canonical v1.0.1 installation. Verify its
traffic before starting. Capture the old unit's active and enabled state and
retain the separate management path.

1. Migrate X locally using the explicit migration option. Keep A on v1.0.1.
2. Verify the imported `legacy` profile preserves interface `GRE`, endpoints,
   `.1/.2` addresses, ports, UDP choice, and service active/enabled intent.
3. Verify traffic resumes after the expected short interruption, with no active
   old singleton service competing with the profile instance.
4. Migrate A, then add another Iran peer to X and repeat independent traffic
   checks. Also test the opposite migration order with a fresh disposable pair.
5. Repeat with an intentionally stopped/disabled old unit. Migration must not
   silently start or enable it.
6. Verify an unknown/modified helper or ambiguous recovery state is rejected
   before replacing the original files. The unit tests cover injected failures
   during cutover and rollback; exercise failure recovery on staging only when
   the operator understands and records the specific induced failure.
7. After any incomplete cleanup, confirm backups and recovery data remain and
   competing old/new owners are not enabled. Follow the reported recovery path;
   do not copy an old state-tree backup over live recovery state.
8. For a controlled interruption during rollback, verify a reboot cannot start
   the imported profile during recovery. Repeating migration must recheck cleanup
   before restoring the old helper, and resume partial restoration separately.

## Acceptance record

Use one row per case, including environment variants:

| Case | Expected result | Actual result/evidence | Pass/fail |
|---|---|---|---|
| Simultaneous TCP | Both Iran paths reach X | | |
| Independent stop/remove | Other path continues | | |
| Shared port/sysctl | Retained until final dependent cleanup | | |
| Optional UDP | Echo through enabled pair only | | |
| Reboot | Enabled/disabled intent preserved; traffic restored | | |
| Failure/retry | Recovery retained, siblings preserved | | |
| Concurrent operations | Bounded serialization, no deadlock/lost state | | |
| Migration | Addresses and service intent preserved; one owner | | |

Do not label three-server integration verified until actual outcomes have been
recorded. Keep the code revision and recovery backups with the acceptance record.
