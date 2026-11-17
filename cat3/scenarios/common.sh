#!/usr/bin/env bash
# 추가 시나리오 공통 함수. 각 시나리오 스크립트가 source 해서 사용한다.
set -euo pipefail

NS="${NS:-pbl-security}"
APP_SA="pbl-crypto-platform-app"   # 기본 시나리오와 같은 앱 계정
LEGACY_SA="pbl-legacy-app"         # 권한이 과하게 부여된 앱 계정
OPS_SA="pbl-ops-operator"          # exec 권한이 있는 운영자 계정
SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

# 실습용 계정과 권한, 가짜 Secret 생성 (관리자 권한으로 실행, 탐지 대상 아님)
setup_identities() {
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata: {name: ${APP_SA}, namespace: ${NS}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: pbl-crypto-platform-reader, namespace: ${NS}}
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: pbl-crypto-platform-reader, namespace: ${NS}}
subjects: [{kind: ServiceAccount, name: ${APP_SA}, namespace: ${NS}}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: pbl-crypto-platform-reader}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ${LEGACY_SA}, namespace: ${NS}}
---
# 설정 실수: 앱은 pods/configmaps만 쓰지만 secrets 권한까지 받은 상태
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: pbl-legacy-overprivileged, namespace: ${NS}}
rules:
  - apiGroups: [""]
    resources: ["pods", "configmaps", "secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: pbl-legacy-overprivileged, namespace: ${NS}}
subjects: [{kind: ServiceAccount, name: ${LEGACY_SA}, namespace: ${NS}}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: pbl-legacy-overprivileged}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ${OPS_SA}, namespace: ${NS}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: pbl-ops-operator, namespace: ${NS}}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["get", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: pbl-ops-operator, namespace: ${NS}}
subjects: [{kind: ServiceAccount, name: ${OPS_SA}, namespace: ${NS}}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: pbl-ops-operator}
YAML
  # 실습용 가짜 자격증명 (실제 값 아님)
  kubectl -n "${NS}" create secret generic pbl-db-credentials \
    --from-literal=password=not-a-real-password \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

# 지정한 계정의 토큰으로 동작하는 kubectl 명령 배열을 K 에 만든다.
use_identity() {
  local sa="$1"
  TOKEN="$(kubectl -n "${NS}" create token "${sa}" --duration=10m)"
  K=(kubectl --kubeconfig=/dev/null --server="${SERVER}" \
     --insecure-skip-tls-verify --token="${TOKEN}" -n "${NS}")
}

# 실패가 예상되는 요청: 403이 나와도 스크립트를 멈추지 않는다.
try() { "$@" >/dev/null 2>&1 || true; }
