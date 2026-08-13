# systemd Deployment

For bare-metal/VM environments running the binary directly without a container platform.

## Installation Steps

```sh
# 1. Build the release binary
cargo build --release

# 2. Create a dedicated system account (no login shell)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin trident

# 3. Install the binary
sudo install -m 0755 target/release/trident /usr/local/bin/trident

# 4. Prepare config directory and file with restricted permissions
#    (config may contain plaintext passwords; see DEPLOYMENT.md section 4)
#
#    IMPORTANT: The default config.yaml uses ${ENV_VAR} placeholders for
#    node passwords (e.g. ${TRIDENT_PRIMARY_PASSWORD}). You must EITHER:
#      a) Edit the config to use plaintext passwords or .pgpass references, OR
#      b) Define the environment variables in the service unit file's
#         Environment= / EnvironmentFile= directives (see trident.service).
#    Also update the node host/port entries to match your PostgreSQL cluster.
sudo mkdir -p /etc/trident
sudo cp config.yaml /etc/trident/config.yaml
sudo chown trident:trident /etc/trident/config.yaml
sudo chmod 600 /etc/trident/config.yaml

# 5. Install and enable the service
sudo cp deploy/systemd/trident.service /etc/systemd/system/trident.service
sudo systemctl daemon-reload
sudo systemctl enable --now trident

# 6. Check status and logs
sudo systemctl status trident
sudo journalctl -u trident -f
```

## Notes

- `Restart=always` + `RestartSec=2s`: the process is automatically restarted on crash or
  normal exit; `StartLimitBurst=5` stops restart attempts after 5 failures within 60 seconds
  to avoid masking real configuration issues with a crash loop
  (use `systemctl reset-failed trident` to clear the rate limit and retry).
- `ProtectSystem=strict`/`ProtectHome=true`/`PrivateTmp=true`: sandboxing hardening. Trident
  does not need filesystem write access at runtime (unless file logging is configured; see
  `ReadWritePaths`).
- If Trident supports SIGHUP hot-reload (see the hot-reload section in `DEPLOYMENT.md`), you
  can trigger it with `systemctl reload trident`. The provided unit file already includes
  `ExecReload=/bin/kill -HUP $MAINPID`, so no additional configuration is needed.

## Log Files and logrotate (optional)

If file logging is configured via `logging.dir` in `config.yaml` (see `DEPLOYMENT.md`
section 3), Trident performs its own rolling cleanup ("retain the most recent N rotated
files"), checked on every rotation event (not just at startup). It also supports
`rotation: size_based` for per-file size limits. This means the core guarantee of "disk
won't fill up with logs" does not require an external `logrotate` configuration.

If you still want to compress archived logs (Trident does not compress them itself), you
can optionally add a `logrotate` config as a supplement:

```
# /etc/logrotate.d/trident
/var/log/trident/*.log.* {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
}
```

Since Trident generates independent files like `trident.log.YYYY-MM-DD` (or
`trident.log.1`, `trident.log.2` ... in `size_based` mode) rather than appending to a
single file and rotating in-place, this `logrotate` config only serves compression
purposes. It does not depend on `postrotate`/signal notifications (Trident never reuses
old rotated files). The old-file cleanup is redundant with Trident's own `max_files`
setting — use one or the other to avoid configuration conflicts.
