{{/* port49's image: the tag defaults to the chart's appVersion. */}}
{{- define "port49.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/* The labels that pick a component's pods. Called with (dict "root" . "component" "port49d"). */}}
{{- define "port49.selector" -}}
app.kubernetes.io/name: port49
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "port49.labels" -}}
{{ include "port49.selector" . }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end }}

{{/*
The pod-level placement: one replica per node where it can, spread across zones where the
cluster has them, and a cluster with no zone labels still schedules (ScheduleAnyway).
*/}}
{{- define "port49.placement" -}}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              {{- include "port49.selector" . | nindent 14 }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "port49.selector" . | nindent 8 }}
{{- end }}

{{/* The container hardening both components share. */}}
{{- define "port49.containerSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
allowPrivilegeEscalation: false
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
A data directory's initContainer: root, making a 0700 subdirectory owned by 65532 (the fence
refuses a group-writable one, and the volume's root may be group-writable). Called with
(dict "root" . "dir" "/var/lib/port49-broker/state").
*/}}
{{- /*
The kubelet applies fsGroup to the PVC's root (setgid, group-writable), and the fence refuses a
group-writable non-sticky directory above a file it reads (the kept CRL, the bundle). The kubelet
sets it at mount, before this container runs, so this container takes the group write bit off the
root again; with OnRootMismatch the kubelet puts it back at the next mount and this runs again
before the process starts. Unverified against a real kubelet until the kind smoke and L82.
*/ -}}
{{- define "port49.dataInit" -}}
name: data-dir
image: {{ .root.Values.initImage }}
command: [sh, -c, {{ printf "install -d -m 0700 -o 65532 -g 65532 %s && chmod g-w %s" .dir .mount | quote }}]
securityContext:
  runAsNonRoot: false
  runAsUser: 0
  runAsGroup: 0
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
    add: [CHOWN, FOWNER, DAC_OVERRIDE]
  seccompProfile:
    type: RuntimeDefault
volumeMounts:
  - {name: data, mountPath: {{ .mount }}}
{{- end }}

{{/*
Both components' liveness: /healthz is unbound for seconds between runs after a store loss
(internal/port49d/main.go:727-731), so Kubernetes' default 10 s x 3 would let the kubelet kill
a process mid etcd outage: 10 s x 6 is 60 s. Called with the metrics port's name.
*/}}
{{- define "port49.probes" -}}
readinessProbe:
  httpGet: {path: /readyz, port: metrics, scheme: HTTP}
  periodSeconds: 5
  failureThreshold: 3
livenessProbe:
  httpGet: {path: /healthz, port: metrics, scheme: HTTP}
  periodSeconds: 10
  failureThreshold: 6
{{- end }}
