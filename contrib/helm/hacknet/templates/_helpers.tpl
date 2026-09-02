{{- define "hacknet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hacknet.fullname" -}}
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

{{- define "hacknet.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "hacknet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "hacknet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hacknet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end }}

{{- define "hacknet.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hacknet.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "hacknet.watchNamespace" -}}
{{- default .Release.Namespace .Values.watchNamespace }}
{{- end }}

{{- define "hacknet.runOperatorName" -}}
{{- printf "%s-run" (include "hacknet.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hacknet.runOperatorSelectorLabels" -}}
app.kubernetes.io/name: {{ include "hacknet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: run-operator
{{- end }}

{{- define "hacknet.runServiceAccountName" -}}
{{- if .Values.runServiceAccount.create }}
{{- default (include "hacknet.runOperatorName" .) .Values.runServiceAccount.name }}
{{- else }}
{{- required "runServiceAccount.name is required when runServiceAccount.create=false" .Values.runServiceAccount.name }}
{{- end }}
{{- end }}
