# Kubernetes 部署

适用场景：已有 k8s 集群，希望用标准的 Deployment/Service 管理 Trident。

## 前提

- 已构建好 `trident:latest` 镜像（`docker build -t trident:latest .`）并推送到集群可访问的镜像仓库，
  或者本地集群（kind/minikube）已 `load` 该镜像。
- 后端 PostgreSQL 节点（Writer/Reader/Analytics）已经存在，本仓库不提供后端数据库的部署清单。

## 部署步骤

```sh
kubectl apply -f deploy/k8s/00-namespace.yaml

# 用真实密码生成 Secret（不要提交带真实密码的 10-config-secret.yaml 到版本库）
kubectl create secret generic trident-config \
  --namespace trident \
  --from-file=config.yaml=./config.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f deploy/k8s/20-deployment.yaml
kubectl apply -f deploy/k8s/30-service.yaml

kubectl -n trident get pods -w
kubectl -n trident logs -f deploy/trident
```

## 已知限制（务必先读）

1. **`replicas > 1` 属于 `DEPLOYMENT.md` 第 8 节讨论的多实例场景**：`ConsistencyLevel::Global`
   在跨 pod 场景下不正确，多副本时请把 `routing.default_consistency` 设为 `session` 或
   `eventual`。
2. **探活**：`readinessProbe` 已配成 `httpGet /healthz`（依赖 `10-config-secret.yaml` 里
   `admin.enabled: true` 且 `admin.listen_addr` 绑 `0.0.0.0`，见该文件内注释）；
   `livenessProbe` 仍用 TCP 探针（探活端点不健康不代表进程需要被杀重启，只应影响是否
   接流量，因此 liveness 故意没有跟 readiness 复用同一逻辑）。`/metrics`/`/healthz`
   只监听在 pod 内部端口，没有任何 Service 暴露到集群外，符合它们不做鉴权的设计前提。
3. **CANCEL 请求的会话粘滞**：`30-service.yaml` 已经配置了 `sessionAffinity: ClientIP`，
   降低（但不能消除）多副本下 CANCEL 请求被路由到另一个 pod 从而悄悄失效的概率，详见
   `DEPLOYMENT.md` 8.3 节。
4. **密码存储**：`NodeConfig.password` 现在支持 `${ENV_VAR}` 占位符或省略后走
   `.pgpass` 查找（见 `DEPLOYMENT.md` 第 2 节），可以把 `10-config-secret.yaml`
   拆分成 ConfigMap（非敏感的 `proxy`/`routing`/`pool`/`health`/`logging`）+
   一个只放密码的小 Secret（作为环境变量注入，配合 `${ENV_VAR}` 占位符），示例已在
   `10-config-secret.yaml` 顶部注释中说明；目前该文件仍演示"整份配置存 Secret"的
   简单做法，两种方式都可用。
