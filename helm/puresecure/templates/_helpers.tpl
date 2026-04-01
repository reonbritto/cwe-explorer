{{/*
Common labels for all resources
*/}}
{{- define "puresecure.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: puresecure
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
App selector labels
*/}}
{{- define "puresecure.app.selectorLabels" -}}
app: {{ .Values.app.name }}
{{- end }}

{{/*
App labels
*/}}
{{- define "puresecure.app.labels" -}}
{{ include "puresecure.app.selectorLabels" . }}
tier: backend
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Prometheus selector labels
*/}}
{{- define "puresecure.prometheus.selectorLabels" -}}
app: prometheus
{{- end }}

{{/*
Prometheus labels
*/}}
{{- define "puresecure.prometheus.labels" -}}
{{ include "puresecure.prometheus.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Grafana selector labels
*/}}
{{- define "puresecure.grafana.selectorLabels" -}}
app: grafana
{{- end }}

{{/*
Grafana labels
*/}}
{{- define "puresecure.grafana.labels" -}}
{{ include "puresecure.grafana.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Locust selector labels
*/}}
{{- define "puresecure.locust.selectorLabels" -}}
app: locust
{{- end }}

{{/*
Locust labels
*/}}
{{- define "puresecure.locust.labels" -}}
{{ include "puresecure.locust.selectorLabels" . }}
tier: testing
{{ include "puresecure.labels" . }}
{{- end }}

{{/*
Alertmanager selector labels
*/}}
{{- define "puresecure.alertmanager.selectorLabels" -}}
app: alertmanager
{{- end }}

{{/*
Alertmanager labels
*/}}
{{- define "puresecure.alertmanager.labels" -}}
{{ include "puresecure.alertmanager.selectorLabels" . }}
tier: monitoring
{{ include "puresecure.labels" . }}
{{- end }}
