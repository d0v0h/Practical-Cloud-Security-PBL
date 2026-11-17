#!/usr/bin/env bash
# [공격] 권한 확인과 클러스터 정찰: 내 권한 목록, 노드, 권한 설정, 다른 네임스페이스
source "$(dirname "$0")/common.sh"
use_identity "${APP_SA}"
try "${K[@]}" auth can-i --list          # selfsubjectrulesreviews, 누구나 허용(201)
try "${K[@]}" get nodes
try "${K[@]}" get roles
try "${K[@]}" get rolebindings
try "${K[@]}" get pods -n kube-system
