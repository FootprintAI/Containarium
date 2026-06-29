{{/*
Expand the name of the chart.
*/}}
{{- define "containarium-k8s.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "containarium-k8s.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "containarium-k8s.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "containarium-k8s.labels" -}}
helm.sh/chart: {{ include "containarium-k8s.chart" . }}
{{ include "containarium-k8s.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels for the daemon Deployment.
*/}}
{{- define "containarium-k8s.selectorLabels" -}}
app.kubernetes.io/name: {{ include "containarium-k8s.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Daemon image reference.
*/}}
{{- define "containarium-k8s.daemonImage" -}}
{{- $tag := .Values.daemon.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.daemon.image.repository $tag }}
{{- end }}

{{/*
Name of the daemon service account.
*/}}
{{- define "containarium-k8s.serviceAccountName" -}}
{{- printf "%s-daemon" (include "containarium-k8s.fullname" .) }}
{{- end }}

{{/*
Name of the sshpiper service account.
*/}}
{{- define "containarium-k8s.sshpiperServiceAccountName" -}}
{{- printf "%s-sshpiper" (include "containarium-k8s.fullname" .) }}
{{- end }}
