{{/*
Вспомогательные шаблоны kube-sentinel. Сосредоточивают общую логику: имена, метки, вычисление
единого тега образа, полного имени образа компонента, целевого наблюдаемого пространства имён и
блока imagePullSecrets. Держат остальные шаблоны короткими и согласованными.
*/}}

{{/* Базовое имя релиза, усечённое до 63 символов (ограничение имён DNS-1123). */}}
{{- define "kube-sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Пространство установки продукта. */}}
{{- define "kube-sentinel.namespace" -}}
{{- default "sentinel" .Values.namespace.install -}}
{{- end -}}

{{/*
Целевое наблюдаемое пространство имён. Отдельно от пространства установки: пусто означает
«то же, что установка». Используется в селекторе логов Alloy и как значение SENTINEL_NAMESPACE
по умолчанию вне пода (в подах его перекрывает downward API).
*/}}
{{- define "kube-sentinel.targetNamespace" -}}
{{- if .Values.namespace.target -}}
{{- .Values.namespace.target -}}
{{- else -}}
{{- include "kube-sentinel.namespace" . -}}
{{- end -}}
{{- end -}}

{{/* Единый тег образа: image.tag, иначе Chart.appVersion. */}}
{{- define "kube-sentinel.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag -}}
{{- end -}}

{{/*
Полное имя образа компонента. Аргумент: список из корневого контекста и имени компонента,
например (list . "agent-panel"). Собирает registry/repository/<компонент>:<единый тег>.
*/}}
{{- define "kube-sentinel.image" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- printf "%s/%s/%s:%s" $root.Values.image.registry $root.Values.image.repository $component (include "kube-sentinel.imageTag" $root) -}}
{{- end -}}

{{/* Общие метки всех ресурсов чарта. */}}
{{- define "kube-sentinel.labels" -}}
app.kubernetes.io/name: {{ include "kube-sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/part-of: kube-sentinel
{{- end -}}

{{/* Блок imagePullSecrets, если заданы. */}}
{{- define "kube-sentinel.imagePullSecrets" -}}
{{- if .Values.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.imagePullSecrets }}
  - name: {{ .name }}
{{- end }}
{{- end -}}
{{- end -}}
