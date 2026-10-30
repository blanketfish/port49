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
privileged: false
allowPrivilegeEscalation: false
# Neither process writes outside its volumes (no temporary files: none in the code); the kind smoke
# is the check, and an emptyDir at /tmp is the fix if it finds one.
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
A data directory's two initContainers, in this order: data-dir (root, the inodes) and data-dir-owner
(65532, the descent). Each is called with (dict "root" . "dir" "/var/lib/port49-broker/state"
"mount" "/var/lib/port49-broker").
*/}}
{{- /*
Why the root is made 3770 and the directory repaired (fsgroup-analysis.md, kubelet v1.33.1
pkg/volume/volume_linux.go:192-233). With fsGroup and OnRootMismatch the kubelet skips its recursive
walk only while the volume root has gid = fsGroup, perms including 0770, and setgid. A root left
2755 (group write removed) is a mismatch at every later mount: the walk then makes the data
directory 2770 and its files 0660, and the fence refuses the directory. So the root init, before the
process starts: sets the root to root:65532 3770 (setgid for the kubelet's test, sticky so the fence
excuses a group-writable ancestor, fence_linux.go:403-405) and makes the data directory with an
explicit chmod (BusyBox install -d leaves an existing one alone); it refuses a data directory that is
a symlink (65532 may rename its own entry in the sticky root) and uses chown -h. It touches inodes only (the root,
the directory), never descends, so it needs CHOWN, FOWNER and FSETID and nothing else: all three are
in Pod Security baseline's list, DAC_READ_SEARCH (what a descent into a 0700 directory it does not
own would need) is not, and the chart must run in a baseline namespace. The tree below the directory
is repaired by the second init, as 65532 with no capability: it owns those files, so it needs none.
If a file there belongs to another uid (a restore done as root), it cannot chown it; it stops and
names the path and the one command that fixes it, instead of leaving the fence to crash-loop later.
CAP_FSETID keeps the setgid bit when chmod runs as root outside the directory's group. UNVERIFIED
against a real kubelet until the kind smoke's two-generation cell.
*/ -}}
{{- define "port49.dataInit" -}}
name: data-dir
image: {{ .root.Values.initImage }}
command: [sh, -c, {{ printf "chown 0:65532 %s && chmod 3770 %s && { [ ! -L %s ] || { echo \"data-dir: %s is a symlink; refusing\" >&2; exit 1; }; } && install -d -m 0700 -o 65532 -g 65532 %s && chown -h 65532:65532 %s && chmod 0700 %s && chmod g-s %s" .mount .mount .dir .dir .dir .dir .dir .dir | quote }}]
securityContext:
  runAsNonRoot: false
  runAsUser: 0
  runAsGroup: 0
  privileged: false
  allowPrivilegeEscalation: false
  # Writes only to the PVC; every command changes owner, mode or bits, never file contents.
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
    # CHOWN: chown 0:65532 and chown 65532:65532. FOWNER: chmod on the directory once it is 65532's.
    # FSETID: keeps setgid on the root's chmod. No DAC_READ_SEARCH and no DAC_OVERRIDE: root owns the
    # mount root, so creating the directory in it is the owner's write, and nothing here descends.
    add: [CHOWN, FOWNER, FSETID]
  seccompProfile:
    type: RuntimeDefault
volumeMounts:
  - {name: data, mountPath: {{ .mount }}}
{{- end }}

{{- define "port49.dataInitOwner" -}}
name: data-dir-owner
image: {{ .root.Values.initImage }}
command: [sh, -c, {{ printf "set -o pipefail; { bad=$(find %s ! -user 65532 | head -n 1); if [ -n \"$bad\" ]; then echo \"data-dir-owner: $bad is not owned by uid 65532 (a restore done as root?), so the fence would refuse it. As root on the volume run: chown -R 65532:65532 %s\"; exit 1; fi; chmod -R go-rwx %s && chmod -R g-s %s || { echo \"data-dir-owner: chmod failed inside %s; a directory there may be mode 0000 (find or chmod named it above): chmod u+rwx it, then restart\"; exit 1; }; } 2>&1 | sed 's/[^[:print:]]/?/g' >&2" .dir .dir .dir .dir .dir | quote }}]
securityContext:
  {{- include "port49.containerSecurity" .root | nindent 2 }}
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

{{/*
The broker's mounts and volumes but its data volume: the StatefulSet and the enrollments CronJob
render them from here, so a mount added for one reaches the other (the config load fences each file
the config names, so a drift would fail loudly, not silently). Called with the root context.
*/}}
{{- define "port49.brokerMounts" -}}
- {name: config, mountPath: /etc/port49/config, readOnly: true}
- {name: encryption, mountPath: /etc/port49/secrets, readOnly: true}
- {name: etcd-ca, mountPath: /etc/port49/etcd-ca, readOnly: true}
- {name: etcd-client, mountPath: /etc/port49/etcd, readOnly: true}
- {name: broker-tls, mountPath: /etc/port49/broker, readOnly: true}
{{- if .Values.broker.attestationRootsConfigMap }}
- {name: attestation-roots, mountPath: /etc/port49/attestation, readOnly: true}
{{- end }}
{{- if .Values.broker.directory.keytabSecret }}
- {name: directory, mountPath: /etc/port49/directory, readOnly: true}
{{- end }}
{{- end }}

{{- define "port49.brokerVolumes" -}}
- name: config
  configMap: {name: {{ .Release.Name }}-broker}
- name: encryption
  secret: {secretName: {{ .Values.encryption.existingSecret }}, defaultMode: 0440}
- name: etcd-ca
  secret: {secretName: {{ .Values.etcd.caSecret }}, defaultMode: 0440}
- name: etcd-client
  secret: {secretName: {{ .Values.etcd.broker.existingSecret }}, defaultMode: 0440}
- name: broker-tls
  secret: {secretName: {{ .Values.broker.tls.existingSecret }}, defaultMode: 0440}
{{- if .Values.broker.attestationRootsConfigMap }}
- name: attestation-roots
  configMap: {name: {{ .Values.broker.attestationRootsConfigMap }}}
{{- end }}
{{- if .Values.broker.directory.keytabSecret }}
- name: directory
  secret: {secretName: {{ .Values.broker.directory.keytabSecret }}, defaultMode: 0440}
{{- end }}
{{- end }}
