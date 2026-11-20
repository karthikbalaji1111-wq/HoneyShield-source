#!/bin/sh
# Write nginx's `resolver` from this container's DNS configuration (Docker embedded DNS under
# Compose, kube-dns under Kubernetes) unless HS_RESOLVER is set. Runs before the template step.
set -eu
ns="${HS_RESOLVER:-$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)}"
case "$ns" in
  *:*) ns="[$ns]" ;;  # IPv6 literal
esac
printf 'resolver %s valid=10s ipv6=off;\n' "$ns" > /etc/nginx/conf.d/00-resolver.conf
echo "15-hs-resolver.sh: resolver $ns"
