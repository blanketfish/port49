# Kubernetes ConfigMap and Secret volume mounts — on-disk modes

- **Date measured:** 2026-09-24
- **Host:** beehive, kernel 7.0.0-31-generic, Docker 29.1.3
- **Cluster:** kind v0.33.0 (go1.26.0), one node `cmlab-control-plane`, deleted after the run
- **Kubernetes:** v1.37.0 (server and kubelet), containerd 2.3.4, node OS Debian 13 (trixie)
- **Node image:** `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`
- **Pod image:** `docker.io/library/debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251` (bookworm-slim)
- **Capture:** none; the stat, `namei -l` and `ls -la` output below is the evidence, quoted exactly
- **Method:** by hand. A ConfigMap `policy` and a Secret `policy`, each with one key
  `policy.yaml` (content `version: 1`, a placeholder, not a secret), mounted at `/cfg`. Each
  pod ran a probe script: `id`; `stat -c '%U:%G (%u:%g) %a %A %F %n'` on `/cfg`, `/cfg/..data`,
  the timestamped dir, `/cfg/policy.yaml` and the file through each link; a readlink loop;
  `namei -l /cfg/policy.yaml`; `ls -la /cfg`; the `/proc/mounts` line. Then `touch`/`ln -s`
  into `/cfg` and `/cfg/..data/` to test real writability.

## Claim

Whether port49d's policy-file safety check — file owned by the daemon's euid or root and not
group- or world-writable; the holding directory of every symlink in the chain owned by euid
or root and not group- or world-writable — passes on a real ConfigMap or Secret mount
(plan `2026-09-24-04b-live-policy.md` §1 asserts that a ConfigMap mount passes).

## Answer

**It depends on which directories the check looks at.**

- **The file actually read, and the directory holding it** (the timestamped dir): **passes in
  every case.** The file is always `root`-owned, mode 0644 or the `defaultMode`; the timestamped
  dir is always `root`-owned 0755, or 02755 with `fsGroup`. `fsGroup` sets the group to 10049 and
  the setgid bit but adds no group write.
- **Also the directory holding each symlink** (`/cfg`, which holds both `policy.yaml ->
  ..data/policy.yaml` and `..data -> ..<timestamp>`): **fails in every case.** The mount root is
  mode 0777 for a ConfigMap, 01777 for a Secret (tmpfs), 02777 / 03777 with `fsGroup`. It is
  world-writable by mode bits in every configuration measured, including `readOnly: true`
  and every `defaultMode`.
- The mode bits overstate it: the mount is `ro` in `/proc/mounts` in every pod, with or
  without `readOnly: true`, and even uid 0 in the container gets `Read-only file system` on
  `touch /cfg/x`, `ln -s ... /cfg/..data2` and `touch /cfg/..data/y`. Only the kubelet, from
  the node, writes there. A check that reads mode bits alone cannot see that.

| Case | Pod | Mount root `/cfg` | Timestamped dir | File | Check: file + its dir | Check: + every symlink's dir |
|---|---|---|---|---|---|---|
| CM (a) root, no securityContext | `cm-a` | root:root 0777 | root:root 0755 | root:root 0644 | pass | **fail** — `/cfg` 0777 |
| CM (b) 10049:10049, no fsGroup | `cm-b` | root:root 0777 | root:root 0755 | root:root 0644 | pass | **fail** — `/cfg` 0777 |
| CM (c) 10049 + fsGroup 10049 | `cm-c` | root:10049 2777 | root:10049 2755 | root:10049 0644 | pass | **fail** — `/cfg` 2777 |
| CM (d) defaultMode 0400 | `cm-d400` | root:root 0777 | root:root 0755 | root:root 0400 | pass | **fail** — `/cfg` 0777 |
| CM (d) defaultMode 0440 | `cm-d440` | root:root 0777 | root:root 0755 | root:root 0440 | pass | **fail** — `/cfg` 0777 |
| CM (d) defaultMode 0400 + fsGroup | `cm-d400f` | root:10049 2777 | root:10049 2755 | root:10049 **0440** | pass | **fail** — `/cfg` 2777 |
| CM (d) defaultMode 0440 + fsGroup | `cm-d440f` | root:10049 2777 | root:10049 2755 | root:10049 0440 | pass | **fail** — `/cfg` 2777 |
| CM (e) readOnly: true (10049) | `cm-e` | root:root 0777 | root:root 0755 | root:root 0644 | pass | **fail** — `/cfg` 0777 |
| Secret (a) root | `sec-a` | root:root 1777 | root:root 0755 | root:root 0644 | pass | **fail** — `/cfg` 1777 |
| Secret (b) 10049:10049 | `sec-b` | root:root 1777 | root:root 0755 | root:root 0644 | pass | **fail** — `/cfg` 1777 |
| Secret (c) 10049 + fsGroup | `sec-c` | root:10049 3777 | root:10049 2755 | root:10049 0644 | pass | **fail** — `/cfg` 3777 |

Other findings:

- With `fsGroup`, `defaultMode: 0400` came out as **0440**: the kubelet adds group read for the
  fsGroup. The file is still not group-writable.
- The chain is always two links deep: `/cfg/policy.yaml -> ..data/policy.yaml` (relative),
  then `/cfg/..data -> ..<YYYY_MM_DD_HH_MM_SS.N>` (relative). Both links live in `/cfg`.
- ConfigMaps mount on the node's ext4 (the kubelet pod dir); Secrets mount on tmpfs.
- Symlinks carry the `fsGroup` group too (`lrwxrwxrwx root 10049`); link modes are always 0777
  on Linux and carry no meaning.

## Observation

### ConfigMap (a) root, no securityContext — `cm-a`

```
id: uid=0(root) gid=0(root) groups=0(root)
root:root (0:0) 777 drwxrwxrwx directory /cfg
root:root (0:0) 777 lrwxrwxrwx symbolic link /cfg/..data
root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.2241008412
root:root (0:0) 777 lrwxrwxrwx symbolic link /cfg/policy.yaml
root:root (0:0) 644 -rw-r--r-- regular file /cfg/..data/policy.yaml
root:root (0:0) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.2241008412/policy.yaml
-- readlink chain
/cfg/policy.yaml -> ..data/policy.yaml
-- namei
f: /cfg/policy.yaml
drwxr-xr-x root root /
drwxrwxrwx root root cfg
lrwxrwxrwx root root policy.yaml -> ..data/policy.yaml
lrwxrwxrwx root root   ..data -> ..2026_09_24_07_09_38.2241008412
drwxr-xr-x root root     ..2026_09_24_07_09_38.2241008412
-rw-r--r-- root root   policy.yaml
-- ls -la
total 12
drwxrwxrwx 3 root root 4096  .
drwxr-xr-x 1 root root 4096  ..
drwxr-xr-x 2 root root 4096  ..2026_09_24_07_09_38.2241008412
lrwxrwxrwx 1 root root   32  ..data -> ..2026_09_24_07_09_38.2241008412
lrwxrwxrwx 1 root root   18  policy.yaml -> ..data/policy.yaml
-- mount
/dev/mapper/ubuntu--vg-ubuntu--lv /cfg ext4 ro,relatime 0 0
```

(The readlink loop stops at `..data/policy.yaml` because the shell `[ -L ]` test on the
resolved path is false once `..data` is followed; `namei` shows the full chain.)

### ConfigMap (b) runAsUser/runAsGroup 10049, no fsGroup — `cm-b`

```
id: uid=10049 gid=10049 groups=10049
root:root (0:0) 777 drwxrwxrwx directory /cfg
root:root (0:0) 777 lrwxrwxrwx symbolic link /cfg/..data
root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.1135991474
root:root (0:0) 777 lrwxrwxrwx symbolic link /cfg/policy.yaml
root:root (0:0) 644 -rw-r--r-- regular file /cfg/..data/policy.yaml
root:root (0:0) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.1135991474/policy.yaml
-- namei
f: /cfg/policy.yaml
drwxr-xr-x root root /
drwxrwxrwx root root cfg
lrwxrwxrwx root root policy.yaml -> ..data/policy.yaml
lrwxrwxrwx root root   ..data -> ..2026_09_24_07_09_38.1135991474
drwxr-xr-x root root     ..2026_09_24_07_09_38.1135991474
-rw-r--r-- root root   policy.yaml
-- mount
/dev/mapper/ubuntu--vg-ubuntu--lv /cfg ext4 ro,relatime 0 0
```

### ConfigMap (c) runAsUser 10049 with fsGroup 10049 — `cm-c`

```
id: uid=10049 gid=10049 groups=10049
root:UNKNOWN (0:10049) 2777 drwxrwsrwx directory /cfg
root:UNKNOWN (0:10049) 777 lrwxrwxrwx symbolic link /cfg/..data
root:UNKNOWN (0:10049) 2755 drwxr-sr-x directory /cfg/..2026_09_24_07_09_38.1722227772
root:UNKNOWN (0:10049) 777 lrwxrwxrwx symbolic link /cfg/policy.yaml
root:UNKNOWN (0:10049) 644 -rw-r--r-- regular file /cfg/..data/policy.yaml
root:UNKNOWN (0:10049) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.1722227772/policy.yaml
-- namei
f: /cfg/policy.yaml
drwxr-xr-x root root  /
drwxrwsrwx root 10049 cfg
lrwxrwxrwx root 10049 policy.yaml -> ..data/policy.yaml
lrwxrwxrwx root 10049   ..data -> ..2026_09_24_07_09_38.1722227772
drwxr-sr-x root 10049     ..2026_09_24_07_09_38.1722227772
-rw-r--r-- root 10049   policy.yaml
-- mount
/dev/mapper/ubuntu--vg-ubuntu--lv /cfg ext4 ro,relatime 0 0
```

### ConfigMap (d) defaultMode 0400 / 0440, runAsUser 10049 — `cm-d400`, `cm-d440`

```
cm-d400: root:root (0:0) 777 drwxrwxrwx directory /cfg
cm-d400: root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.4048522296
cm-d400: root:root (0:0) 400 -r-------- regular file /cfg/..2026_09_24_07_09_38.4048522296/policy.yaml
cm-d440: root:root (0:0) 777 drwxrwxrwx directory /cfg
cm-d440: root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.116201077
cm-d440: root:root (0:0) 440 -r--r----- regular file /cfg/..2026_09_24_07_09_38.116201077/policy.yaml
```

With mode 0400 or 0440 and owner root, uid 10049 without fsGroup **cannot read the file**:
`cat /cfg/policy.yaml` gave `Permission denied` in both pods (and succeeded in `cm-d400f`,
where fsGroup made it 0440 group 10049). The check passes; the open then fails.

### ConfigMap (d) defaultMode 0400 / 0440 with fsGroup 10049 — `cm-d400f`, `cm-d440f`

```
cm-d400f: root:UNKNOWN (0:10049) 2777 drwxrwsrwx directory /cfg
cm-d400f: root:UNKNOWN (0:10049) 2755 drwxr-sr-x directory /cfg/..2026_09_24_07_09_38.1250899669
cm-d400f: root:UNKNOWN (0:10049) 440 -r--r----- regular file /cfg/..2026_09_24_07_09_38.1250899669/policy.yaml
cm-d440f: root:UNKNOWN (0:10049) 2777 drwxrwsrwx directory /cfg
cm-d440f: root:UNKNOWN (0:10049) 2755 drwxr-sr-x directory /cfg/..2026_09_24_07_09_38.1054281393
cm-d440f: root:UNKNOWN (0:10049) 440 -r--r----- regular file /cfg/..2026_09_24_07_09_38.1054281393/policy.yaml
```

### ConfigMap (e) readOnly: true, runAsUser 10049 — `cm-e`

Identical to (b): `/cfg` root:root 0777, timestamped dir 0755, file 0644, mount `ro`.
`readOnly: true` changes nothing on disk; the mount is already `ro` without it.

```
root:root (0:0) 777 drwxrwxrwx directory /cfg
root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.1490958144
root:root (0:0) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.1490958144/policy.yaml
/dev/mapper/ubuntu--vg-ubuntu--lv /cfg ext4 ro,relatime 0 0
```

### Secret (a) root / (b) 10049 / (c) 10049 + fsGroup — `sec-a`, `sec-b`, `sec-c`

```
sec-a: root:root (0:0) 1777 drwxrwxrwt directory /cfg
sec-a: root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.3182132853
sec-a: root:root (0:0) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.3182132853/policy.yaml
sec-b: root:root (0:0) 1777 drwxrwxrwt directory /cfg
sec-b: root:root (0:0) 755 drwxr-xr-x directory /cfg/..2026_09_24_07_09_38.2613102549
sec-b: root:root (0:0) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.2613102549/policy.yaml
sec-c: root:UNKNOWN (0:10049) 3777 drwxrwsrwt directory /cfg
sec-c: root:UNKNOWN (0:10049) 2755 drwxr-sr-x directory /cfg/..2026_09_24_07_09_38.663991708
sec-c: root:UNKNOWN (0:10049) 644 -rw-r--r-- regular file /cfg/..2026_09_24_07_09_38.663991708/policy.yaml
```

`namei -l /cfg/policy.yaml` in `sec-c`:

```
drwxr-xr-x root root  /
drwxrwsrwt root 10049 cfg
lrwxrwxrwx root 10049 policy.yaml -> ..data/policy.yaml
lrwxrwxrwx root 10049   ..data -> ..2026_09_24_07_09_38.663991708
drwxr-sr-x root 10049     ..2026_09_24_07_09_38.663991708
-rw-r--r-- root 10049   policy.yaml
```

Secret mounts: `tmpfs /cfg tmpfs ro,relatime,size=31558472k,inode64,noswap 0 0`.

### Writability, despite the mode bits

In `cm-a` (uid 0), `cm-b`, `cm-e`, `sec-a` (uid 0) and `sec-c`, each gave:

```
touch: cannot touch '/cfg/x': Read-only file system
ln: failed to create symbolic link '/cfg/..data2': Read-only file system
touch: cannot touch '/cfg/..data/y': Read-only file system
```

### ConfigMap update — the atomic swap (`cm-c`)

Before (`ls -lai`, inode first):

```
558777 drwxrwsrwx 3 root 10049 4096 07:09:38 .
558816 drwxr-sr-x 2 root 10049 4096 07:09:38 ..2026_09_24_07_09_38.1722227772
558825 lrwxrwxrwx 1 root 10049   32 07:09:38 ..data -> ..2026_09_24_07_09_38.1722227772
558827 lrwxrwxrwx 1 root 10049   18 07:09:38 policy.yaml -> ..data/policy.yaml
```

`kubectl apply` of the changed ConfigMap at 07:10:09 UTC; the pod saw the swap at 07:11:04
(55 s, the kubelet sync period). After:

```
558777 drwxrwsrwx 3 root 10049 4096 07:11:04 .
558807 drwxr-sr-x 2 root 10049 4096 07:11:04 ..2026_09_24_07_11_04.1581705238
558815 lrwxrwxrwx 1 root 10049   32 07:11:04 ..data -> ..2026_09_24_07_11_04.1581705238
558827 lrwxrwxrwx 1 root 10049   18 07:09:38 policy.yaml -> ..data/policy.yaml
```

- A new timestamped dir is written (new inode, same owner and mode: root:10049 02755).
- `..data` is a **new symlink inode** (558825 → 558815): the kubelet creates `..data_tmp`
  and renames it over `..data`, so the swap is one `rename(2)` in `/cfg`.
- The old timestamped dir is removed.
- `policy.yaml` is untouched (same inode, same mtime); it resolves to the new file through
  the re-pointed `..data`.
- `/cfg` mtime changes (07:09:38 → 07:11:04) — the swap is a write to the mount root.

A 50 ms `ls -a /cfg` poll in the pod across the swap saw only the two steady states (1074
samples with the old dir, 1926 with the new); no `..data_tmp` or two-timestamped-dir state
was caught.

```
   1074 . .. ..2026_09_24_07_09_38.1722227772 ..data policy.yaml
   1926 . .. ..2026_09_24_07_11_04.1581705238 ..data policy.yaml
```

## What this means for the check

The plan's sentence "a Kubernetes ConfigMap mount, whose files and the directory holding them
are root's and not group- or world-writable, passes" is true of the file and its timestamped
dir, and false of the mount root that holds the two symlinks. A check that walks the holding
directory of each symlink refuses every ConfigMap and Secret mount measured here, and no pod
setting (`securityContext`, `fsGroup`, `defaultMode`, `readOnly`) changes that. The mount root
is not actually writable from inside the pod — the mount is read-only — so refusing it is a
false positive from mode bits, not a real exposure. Resolving that (checking only the final
file and its dir, or treating a read-only mount as safe via `statfs` `ST_RDONLY`) is a design
call, not settled here.
