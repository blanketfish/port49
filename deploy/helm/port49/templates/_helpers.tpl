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
Why the root is made 3770 and the directory repaired (fsgroup-analysis.md, kubelet v1.33.1
pkg/volume/volume_linux.go:192-233). With fsGroup and OnRootMismatch the kubelet skips its recursive
walk only while the volume root has gid = fsGroup, perms including 0770, and setgid. A root left
2755 (group write removed) is a mismatch at every later mount: the walk then makes the data
directory 2770 and its files 0660, and the fence refuses the directory. So this container, as root
before the process starts: sets the root to root:65532 3770 (setgid for the kubelet's test, sticky
so the fence excuses a group-writable ancestor, fence_linux.go:403-405), makes the directory with an
explicit chmod (BusyBox install -d leaves an existing one alone), and repairs the tree below it to
owner-only whatever a walk did. CAP_FSETID keeps the setgid bit when chmod runs as root outside the
directory's group. UNVERIFIED against a real kubelet until the kind smoke's two-generation cell.
*/ -}}
{{- define "port49.dataInit" -}}
name: data-dir
image: {{ .root.Values.initImage }}
command: [sh, -c, {{ printf "chown 0:65532 %s && chmod 3770 %s && install -d -m 0700 -o 65532 -g 65532 %s && chown -R 65532:65532 %s && chmod -R go-rwx %s && chmod -R g-s %s && chmod 0700 %s" .mount .mount .dir .dir .dir .dir .dir | quote }}]
securityContext:
  runAsNonRoot: false
  runAsUser: 0
  runAsGroup: 0
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
    add: [CHOWN, FOWNER, FSETID, DAC_OVERRIDE]
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
