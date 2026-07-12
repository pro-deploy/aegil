{{/*
Вспомогательные шаблоны aegil. Сосредоточивают общую логику: имена, метки, вычисление
единого тега образа, полного имени образа компонента, целевого наблюдаемого пространства имён и
блока imagePullSecrets. Держат остальные шаблоны короткими и согласованными.
*/}}

{{/* Базовое имя релиза, усечённое до 63 символов (ограничение имён DNS-1123). */}}
{{- define "aegil.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Пространство установки продукта. */}}
{{- define "aegil.namespace" -}}
{{- default "aegil" .Values.namespace.install -}}
{{- end -}}

{{/*
Целевое наблюдаемое пространство имён. Отдельно от пространства установки: пусто означает
«то же, что установка». Используется в селекторе логов Alloy и как значение AEGIL_NAMESPACE
по умолчанию вне пода (в подах его перекрывает downward API).
*/}}
{{- define "aegil.targetNamespace" -}}
{{- if .Values.namespace.target -}}
{{- .Values.namespace.target -}}
{{- else -}}
{{- include "aegil.namespace" . -}}
{{- end -}}
{{- end -}}

{{/* Единый тег образа: image.tag, иначе Chart.appVersion. */}}
{{- define "aegil.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag -}}
{{- end -}}

{{/*
Полное имя образа компонента. Аргумент: список из корневого контекста и имени компонента,
например (list . "agent-panel"). Собирает registry/repository/<компонент>:<единый тег>.
*/}}
{{- define "aegil.image" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- printf "%s/%s/%s:%s" $root.Values.image.registry $root.Values.image.repository $component (include "aegil.imageTag" $root) -}}
{{- end -}}

{{/* Общие метки всех ресурсов чарта. */}}
{{- define "aegil.labels" -}}
app.kubernetes.io/name: {{ include "aegil.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/part-of: aegil
{{- end -}}

{{/* Блок imagePullSecrets, если заданы. */}}
{{- define "aegil.imagePullSecrets" -}}
{{- if .Values.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.imagePullSecrets }}
  - name: {{ .name }}
{{- end }}
{{- end -}}
{{- end -}}
