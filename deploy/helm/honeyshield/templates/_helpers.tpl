{{- define "hs.name" -}}{{ .Release.Name }}{{- end -}}
{{- define "hs.labels" -}}
app.kubernetes.io/part-of: honeyshield
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "hs.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}
{{- define "hs.backendImage" -}}{{ .Values.image.backend.repository }}:{{ .Values.image.backend.tag }}{{- end -}}
{{- define "hs.redisHost" -}}
{{- if .Values.redis.enabled -}}{{ .Release.Name }}-redis:6379{{- else -}}{{ required "redis.externalHost is required when redis.enabled=false" .Values.redis.externalHost }}{{- end -}}
{{- end -}}

{{/* Restricted-profile container security context. */}}
{{- define "hs.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities: { drop: [ALL] }
seccompProfile: { type: RuntimeDefault }
{{- end -}}

{{/* Environment shared by every backend-image container (runtime identity). */}}
{{- define "hs.appEnv" -}}
- { name: APP_ENV, value: production }
- { name: POSTGRES_HOST, value: {{ .Values.postgresql.host | quote }} }
- { name: POSTGRES_PORT, value: {{ .Values.postgresql.port | quote }} }
- { name: POSTGRES_DB, value: {{ .Values.postgresql.database | quote }} }
- { name: POSTGRES_USER, value: {{ .Values.postgresql.appUser | quote }} }
- { name: POSTGRES_APP_USER, value: {{ .Values.postgresql.appUser | quote }} }
- { name: PUBLIC_INGEST_BASE_URL, value: "https://{{ .Values.hosts.ingest }}" }
- { name: CONTROL_PLANE_HOSTNAMES, value: {{ .Values.hosts.control | quote }} }
- { name: TRUSTED_PROXIES, value: {{ .Values.trustedProxies | quote }} }
- { name: SECURITY_HEADERS_HSTS_ENABLED, value: "true" }
- { name: DECOY_LINK_PATH, value: {{ .Values.decoyPaths.link | quote }} }
- { name: DECOY_PIXEL_PATH, value: {{ .Values.decoyPaths.pixel | quote }} }
- { name: DECOY_COLLECT_PATH, value: {{ .Values.decoyPaths.collect | quote }} }
- { name: DECOY_LEGACY_PATHS, value: {{ .Values.decoyPaths.legacy | quote }} }
- { name: CONTROL_PLANE_ALLOWED_CIDRS, value: {{ .Values.controlAllowCidrs | quote }} }
- name: POSTGRES_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: POSTGRES_PASSWORD } }
- name: JWT_SECRET_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: JWT_SECRET_KEY } }
- name: INTEGRATION_SIGNING_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: INTEGRATION_SIGNING_KEY } }
- name: MFA_SECRET_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: MFA_SECRET_KEY } }
- name: REDIS_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: REDIS_PASSWORD } }
- { name: REDIS_URL, value: "redis://:$(REDIS_PASSWORD)@{{ include "hs.redisHost" . }}/0" }
- name: METRICS_TOKEN
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: METRICS_TOKEN, optional: true } }
- name: SMTP_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: SMTP_PASSWORD, optional: true } }
- name: OIDC_CLIENT_SECRET
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: OIDC_CLIENT_SECRET, optional: true } }
{{- range $k, $v := .Values.backend.extraEnv }}
- { name: {{ $k }}, value: {{ $v | quote }} }
{{- end }}
{{- end -}}

{{- define "hs.s3Env" -}}
- { name: EVIDENCE_S3_ENDPOINT, value: {{ .Values.s3.endpoint | quote }} }
- { name: EVIDENCE_S3_BUCKET, value: {{ .Values.s3.bucket | quote }} }
- { name: EVIDENCE_S3_REGION, value: {{ .Values.s3.region | quote }} }
- { name: EVIDENCE_S3_ACCESS_KEY_ID, value: {{ .Values.s3.accessKeyId | quote }} }
- { name: EVIDENCE_S3_RETENTION_DAYS, value: {{ .Values.s3.retentionDays | quote }} }
- { name: EVIDENCE_S3_LOCK_MODE, value: {{ .Values.s3.lockMode | quote }} }
- name: EVIDENCE_S3_SECRET_ACCESS_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: EVIDENCE_S3_SECRET_ACCESS_KEY, optional: true } }
{{- end -}}

{{- define "hs.ownerEnv" -}}
- { name: POSTGRES_MIGRATION_USER, value: {{ .Values.postgresql.ownerUser | quote }} }
- name: POSTGRES_MIGRATION_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ .Values.secrets.existingSecret }}, key: POSTGRES_MIGRATION_PASSWORD } }
{{- end -}}
