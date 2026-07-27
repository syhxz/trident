# systemd 部署

适用场景：裸机/VM 上直接跑二进制，没有容器平台。

## 安装步骤

```sh
# 1. 编译发布版二进制
cargo build --release

# 2. 创建专用系统账户（不允许登录）
sudo useradd --system --no-create-home --shell /usr/sbin/nologin trident

# 3. 安装二进制
sudo install -m 0755 target/release/trident /usr/local/bin/trident

# 4. 准备配置目录与文件，权限收紧（配置里目前可能含明文密码，见 DEPLOYMENT.md 第 4 节）
sudo mkdir -p /etc/trident
sudo cp config.yaml /etc/trident/config.yaml
sudo chown trident:trident /etc/trident/config.yaml
sudo chmod 600 /etc/trident/config.yaml

# 5. 安装并启用 service
sudo cp deploy/systemd/trident.service /etc/systemd/system/trident.service
sudo systemctl daemon-reload
sudo systemctl enable --now trident

# 6. 查看状态与日志
sudo systemctl status trident
sudo journalctl -u trident -f
```

## 说明

- `Restart=always` + `RestartSec=2s`：进程崩溃或正常退出都会自动重启；`StartLimitBurst=5`
  在 60 秒窗口内失败 5 次后 systemd 会停止继续重启，避免死循环崩溃掩盖真实配置问题
  （用 `systemctl reset-failed trident` 清除限流状态后可再重启）。
- `ProtectSystem=strict`/`ProtectHome=true`/`PrivateTmp=true`：加固沙箱，Trident 运行时
  不需要写文件系统（除非配置了文件日志，见 `ReadWritePaths`）。
- 如果 Trident 支持了 SIGHUP 热加载（见 `DEPLOYMENT.md` 热加载章节），可以用
  `systemctl reload trident` 触发（需要在 unit 文件里补充 `ExecReload=/bin/kill -HUP $MAINPID`）。

## 日志文件与 logrotate（可选，非必需）

如果在 `config.yaml` 的 `logging.dir` 配置了文件日志（见 `DEPLOYMENT.md` 第 3 节），
Trident 自身会持续执行"保留最近 N 个滚动文件"的清理（每次滚动都会检查一次，不是只
在启动时跑一次），并且支持 `rotation: size_based` 给单个文件设置大小上限（见
`DEPLOYMENT.md` 第 3 节）。也就是说，磁盘不被日志占满这个核心保证，不再需要额外配
`logrotate` 兜底。

如果仍然想要压缩归档旧日志（Trident 自身不做压缩），可以选择性地配一份 `logrotate`
配置作为补充：

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

由于 Trident 自己生成 `trident.log.YYYY-MM-DD`（或 `size_based` 模式下的
`trident.log.1`、`trident.log.2` ...）这样的独立文件（而不是原地追加同一个文件再切
割），这里的 `logrotate` 配置只起压缩归档的作用，不依赖 `postrotate`/信号通知
Trident（不需要，因为 Trident 从不复用旧的滚动文件），清理旧文件的部分与 Trident
自身的 `max_files` 配置是冗余的，二者取其一即可，建议只用 Trident 自身的保留策略
以避免两边配置不一致。
