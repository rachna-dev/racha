#!/bin/sh
# The guest's init. Real services: Postgres, then a Node app on top.
export PATH=/bin:/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
hostname rachna 2>/dev/null || true

# Loopback UP. Without it the app's own HTTP client gets ENETUNREACH on
# 127.0.0.1 — found by running it. A guest with no network still needs lo,
# because that is how its processes talk to each other.
ip link set lo up 2>/dev/null || ifconfig lo 127.0.0.1 up 2>/dev/null || true

echo "RACHNA-GUEST-ALIVE"

# The state volume. THE guest formats it on first use: an unformatted
# disk is what `provision_state` hands us (a sparse file), because mke2fs
# is a guest-side tool and running the host's would put the host
# toolchain in the boot path.
#
# A tmpfs fallback only when there is NO disk — and it is loud, because a
# silent fallback is how data loss hides: an earlier version mounted
# tmpfs whenever vdb was missing, so Postgres ran initdb on every boot and
# the todos looked persistent while being recreated each time.
mkdir -p /data
# ext2 AND ext4 are tried, in that order, because busybox's `mke2fs`
# makes an **ext2** filesystem and ships no `mkfs.ext4` at all — so a
# `mount -t ext4` after formatting fails, which is exactly what happened:
# "RACHNA-STATE-FORMATTING" followed by "cannot use /dev/vdb". ext2 is
# fine for a state volume; the journal is what ext4 adds, and a snapshot
# of a paused guest is consistent without it.
mount_state() {
  mount -t ext4 /dev/vdb /data 2>/dev/null
}
if [ -b /dev/vdb ]; then
  if ! mount_state; then
    # FORMATTED WITH REAL ext4, from e2fsprogs shipped in the image.
    #
    # busybox's `mke2fs` writes **ext2** and ships no `mkfs.ext4`, and this
    # kernel has no ext2 driver at all. So the guest could not mount the
    # filesystem it had just created:
    #
    #   ext4 = mount: /dev/vdb on /data failed: Invalid argument
    #   ext2 = mount: /dev/vdb on /data failed: No such device
    #
    # It concluded the volume was unformatted and reformatted it — on every
    # boot. The boot counter reset to 1, Postgres re-ran initdb, and the
    # database was silently recreated each `rachna start`. A persistent
    # volume that is wiped every boot is worse than no volume, because
    # nothing says so.
    echo "RACHNA-STATE-FORMATTING"
    @E2FS@/bin/mke2fs -t ext4 -q -F /dev/vdb
    mount_state || {
      echo "RACHNA-STATE-EPHEMERAL: cannot use /dev/vdb, data will NOT persist"
      mount -t tmpfs tmpfs /data
    }
  fi
else
  echo "RACHNA-STATE-EPHEMERAL: no state volume attached, data will NOT persist"
  mount -t tmpfs tmpfs /data
fi
mkdir -p /data/pgdata /data/run
chown -R postgres:postgres /data
echo "RACHNA-STATE-READY"
echo "RACHNA-UNAME: $(uname -a)"

# THE WORKSPACE is mounted by the initramfs, before switch_root — virtiofs
# after the pivot serves an empty tree (`02` §6.12). So this reports; it
# does not mount. Listed with the shell's own glob, because `find` and
# `ls` are busybox applets that enumerate with getdents, which returns
# nothing on this mount while reads and stat work.
if grep -q " /workspace " /proc/mounts 2>/dev/null; then
  echo "RACHNA-WORKSPACE-MOUNTED"
  echo "RACHNA-WORKSPACE-FILES: $(cd /workspace && echo *)"

  # WORKSPACE THROUGHPUT, because nothing had ever measured it.
  #
  # `02` §6 is explicit that the macOS benchmarks were RAM-only with "no
  # disk images attached", and `01` §3 names filesystem performance — not
  # the hypervisor — as the deciding risk for a backend. Every claim about
  # whether you can compile over this mount rested on nothing.
  #
  # Two shapes, because they fail differently and a build does both:
  #
  #   BULK      one 32 MiB file. Shows the streaming ceiling — reading a
  #             big artefact, writing a binary.
  #   MANY      200 small files created then stat'd. This is the
  #             `node_modules` / `target/` shape, and `06` §215 calls it
  #             "exactly the pathological case" for a shared filesystem,
  #             because every operation is a round trip rather than a
  #             stream.
  #
  # Written under /workspace/.rachna-probe and REMOVED, so a user's project
  # does not grow files it did not ask for. `|| echo` on every step: a
  # probe that fails silently reports a number nobody can distinguish from
  # a measurement (`15` §244's false-negative lesson).
  probe=/workspace/.rachna-probe
  if mkdir -p "$probe" 2>/dev/null; then
    # ENOUGH WORK THAT A ONE-SECOND CLOCK CAN RESOLVE IT.
    #
    # Two earlier versions measured nothing, each for its own reason, and
    # both are worth recording because the failures look like results:
    #
    #   `date +%s` arithmetic over 32 MiB — one-second granularity, so
    #   anything faster than 32 MiB/s reported exactly "32 MiB/s". A
    #   number that is an artefact of the clock, not of the mount.
    #
    #   `dd`'s own `bytes/sec` line — busybox's dd does NOT print one.
    #   Measured: `RACHNA-FS-BULK-WRITE: 32MiB (unreported)`. GNU dd does,
    #   and the host's dd does, which is how the assumption survived.
    #
    # So the work is scaled until the clock resolves it, and the figures are
    # labelled `>=` because at 1 s granularity a reported 3 s span could be
    # 2.01 s. 256 MiB and 2000 files BOTH still finished inside one tick —
    #
    #   RACHNA-FS-BULK-WRITE: 256MiB in 1s (>=256 MiB/s)
    #   RACHNA-FS-MANY-CREATE: 2000 files in 1s (>=2000/s)
    #
    # which is a real result (the mount is not slow) and still not a
    # measurement.
    #
    # 1 GiB, deliberately NOT more: the guest has 2048 MiB of RAM
    # (`resources.memory` default), so a 2 GiB file would measure page-cache
    # eviction and host swap rather than the share. Half of RAM is the
    # largest size where the number still means what it claims to.
    bulk_mib=1024
    t0=$(date +%s)
    dd if=/dev/zero of="$probe/bulk" bs=1M count=$bulk_mib 2>/dev/null
    sync
    t1=$(date +%s)
    if [ -s "$probe/bulk" ]; then
      secs=$((t1 - t0)); [ "$secs" -lt 1 ] && secs=1
      echo "RACHNA-FS-BULK-WRITE: ${bulk_mib}MiB in ${secs}s (>=$((bulk_mib / secs)) MiB/s)"
      t0=$(date +%s)
      dd if="$probe/bulk" of=/dev/null bs=1M 2>/dev/null
      t1=$(date +%s)
      secs=$((t1 - t0)); [ "$secs" -lt 1 ] && secs=1
      echo "RACHNA-FS-BULK-READ: ${bulk_mib}MiB in ${secs}s (>=$((bulk_mib / secs)) MiB/s)"
    else
      echo "RACHNA-FS-BULK: FAILED to write — mount may be read-only"
    fi

    # THE METADATA SHAPE, and the number that actually decides whether a
    # build over this mount is usable: `06` §215 calls `node_modules`-shaped
    # trees "exactly the pathological case", because every operation is a
    # round trip rather than a stream.
    #
    # 20000. Two scalings: 200, then 2000, both of which finished inside
    # one tick. 20k small files is also the right ORDER for the workload
    # being modelled — a `node_modules` tree is tens of thousands of files
    # — so this is realistic rather than merely slow enough to time.
    #
    # The first version used 200 and reported
    #
    #   RACHNA-FS-MANY-CREATE: 200 files in 1s (~200/s)
    #   RACHNA-FS-MANY-STAT:   200 files in 1s (~200/s)
    #
    # — identical figures, both of which are just "200 ÷ the clock's
    # smallest unit". Two different operations cannot plausibly cost the
    # same to the digit; that was the tell. Any workload finishing inside
    # one tick measures the clock.
    #
    # The shell loop's own overhead is included and not subtracted, so
    # these are a floor on the mount's cost rather than an isolated figure
    # for it. Named `>=` for that reason.
    many=20000
    t0=$(date +%s)
    i=0
    while [ $i -lt $many ]; do
      echo x > "$probe/f$i" 2>/dev/null || break
      i=$((i + 1))
    done
    sync
    t1=$(date +%s)
    secs=$((t1 - t0)); [ "$secs" -lt 1 ] && secs=1
    echo "RACHNA-FS-MANY-CREATE: $i files in ${secs}s (>=$((i / secs))/s)"

    t0=$(date +%s)
    j=0
    while [ $j -lt "$i" ]; do
      stat "$probe/f$j" >/dev/null 2>&1 || break
      j=$((j + 1))
    done
    t1=$(date +%s)
    secs=$((t1 - t0)); [ "$secs" -lt 1 ] && secs=1
    echo "RACHNA-FS-MANY-STAT: $j files in ${secs}s (>=$((j / secs))/s)"

    # A BASELINE ON THE STATE VOLUME, so the virtiofs figures mean
    # something. `/data` is ext4 on a virtio-blk disk — the same guest, the
    # same shell loop, a different filesystem — so the RATIO isolates what
    # the share costs. Without it a slow number could be the mount, the
    # kernel, busybox's shell, or this probe.
    t0=$(date +%s)
    k=0
    mkdir -p /data/probe 2>/dev/null
    while [ $k -lt $many ]; do
      echo x > "/data/probe/f$k" 2>/dev/null || break
      k=$((k + 1))
    done
    sync
    t1=$(date +%s)
    secs=$((t1 - t0)); [ "$secs" -lt 1 ] && secs=1
    echo "RACHNA-FS-BASELINE-CREATE: $k files on ext4 in ${secs}s (>=$((k / secs))/s)"
    rm -rf /data/probe 2>/dev/null

    # IS THE METADATA GAP STRUCTURAL, OR IS THE MOUNT JUST UNTUNED?
    #
    # The workspace is mounted with `options = [ "nofail" ]` and nothing
    # else — no caching at all. virtiofs supports attribute and dentry
    # caching (`cache=`, `dax`), and without them every `stat` is a
    # guest->host round trip while a local `stat` is a page-cache hit.
    # That alone could explain the ~10x gap, so it has to be measured
    # before anyone concludes the share is inherently slow.
    #
    # The same host directory is mounted a SECOND time with caching on,
    # and the identical loop runs against it. Two mounts of one share is
    # exactly what `shares_for` refuses for policy reasons — here it is
    # deliberate and read-only, inside a diagnostic.
    #
    # Reported whatever happens: an option the kernel rejects is a result
    # ("this knob does not exist on this build"), not a reason to print
    # nothing.
    mkdir -p /mnt/ws-cached 2>/dev/null
    for opt in "cache=always" "cache=auto" "dax=always"; do
      if mount -t virtiofs -o "$opt" workspace /mnt/ws-cached 2>/dev/null; then
        t0=$(date +%s)
        m=0
        while [ $m -lt "$i" ]; do
          stat "/mnt/ws-cached/.rachna-probe/f$m" >/dev/null 2>&1 || break
          m=$((m + 1))
        done
        t1=$(date +%s)
        secs=$((t1 - t0)); [ "$secs" -lt 1 ] && secs=1
        echo "RACHNA-FS-TUNED-STAT[$opt]: $m files in ${secs}s (>=$((m / secs))/s)"
        umount /mnt/ws-cached 2>/dev/null
      else
        echo "RACHNA-FS-TUNED-STAT[$opt]: mount refused — option unsupported"
      fi
    done

    rm -rf "$probe" 2>/dev/null \
      || echo "RACHNA-FS-PROBE-LEFTOVER: could not remove $probe"
  else
    echo "RACHNA-FS-PROBE: cannot write to /workspace, skipping"
  fi
else
  echo "RACHNA-WORKSPACE-MISSING: no virtiofs share tagged 'workspace'"
fi

# Postgres. `12`-era finding: nothing creates the data dir, so do it here.
if [ ! -f /data/pgdata/PG_VERSION ]; then
  su postgres -c "@POSTGRES@/bin/initdb -D /data/pgdata -A trust" >/data/initdb.log 2>&1
  echo "RACHNA-PG-INITDB-DONE"
fi
su postgres -c "@POSTGRES@/bin/postgres -D /data/pgdata -k /data/run -c listen_addresses=''" \
  >/data/postgres.log 2>&1 &

# Wait for ACCEPTING CONNECTIONS, not for the socket to exist. The two
# differ and the gap is exactly where a restart lands: on the second boot
# Postgres creates its socket and then runs recovery, so a socket-only
# check let the app connect and get
#
#   FATAL: the database system is starting up
#
# `pg_isready` asks the question that matters. Found by restarting a
# project whose database already had data — the first boot never showed
# it, because initdb leaves nothing to recover.
i=0
until @POSTGRES@/bin/pg_isready -h /data/run -q 2>/dev/null; do
  i=$((i+1))
  if [ $i -ge 120 ]; then
    echo "RACHNA-PG-FAILED"
    tail -5 /data/postgres.log
    break
  fi
  sleep 0.5
done
if @POSTGRES@/bin/pg_isready -h /data/run -q 2>/dev/null; then
  echo "RACHNA-PG-READY"
fi

# The todos app.
# `|| exit` because running the app from the wrong directory would
# look like a missing file rather than a failed cd.
# `/opt/rachna`, NOT `/workspace`. The demo app ships in the image and
# `/workspace` is the user's real project over virtiofs — running from
# there would mean the app vanishes the moment a real project appears,
# which is the normal case rather than an edge one.
cd /opt/rachna || exit 1
@NODE@/bin/node todos.js >/data/todos.log 2>&1 &
i=0
while [ $i -lt 60 ]; do
  grep -q "TODOS: listening" /data/todos.log 2>/dev/null && break
  grep -q "TODOS-FAILED" /data/todos.log 2>/dev/null && break
  sleep 0.5; i=$((i+1))
done
cat /data/todos.log
echo "RACHNA-SERVICES-UP"

# No control channel: a second virtio console would mean changing
# `Launch`, and the demo does not need one. The guest exercises its own
# services and reports to the console, which is what a host can read.
#
# Each boot appends, so a resumed or restored guest shows its history —
# which is exactly how we prove data survived a snapshot.
BOOT=$(cat /data/boot-count 2>/dev/null || echo 0)
BOOT=$((BOOT+1))
echo $BOOT > /data/boot-count
echo "RACHNA-BOOT-NUMBER: $BOOT"

# BOUNDED WITH A BACKGROUND JOB AND `kill`, not with `timeout`.
#
# `timeout` KILLS THIS INIT. Measured with a two-part probe, because the
# one-line version died before printing anything and so could not
# distinguish "timeout is broken" from "the probe is broken":
#
#   RACHNA-PROBE-1: before timeout      <- printed
#   timeout 1 sleep 5                   <- init dies here
#   RACHNA-PROBE-2: ...                 <- never printed
#
# The applet exists in the image, so this is not a missing-command error;
# busybox's `timeout` as PID 1's child does something this shell does not
# survive. Three earlier attempts at bounding these calls each made things
# worse — node's `setTimeout` keeps the event loop alive past the response,
# and `process.exit` from a callback left the init with nothing after it —
# so this one is built from pieces already proven to work here: `&`, `$!`,
# `sleep` and `kill`.
#
# The bound matters because the init BLOCKS on these calls: a hung request
# silences the console, stops the tick loop, and leaves `rachna status`
# reporting a booted environment as though nothing were wrong.
run_bounded() {
  limit=$1; shift
  "$@" &
  job=$!
  i=0
  while [ $i -lt "$limit" ]; do
    kill -0 "$job" 2>/dev/null || break
    sleep 1
    i=$((i+1))
  done
  if kill -0 "$job" 2>/dev/null; then
    echo "RACHNA-CALL-TIMEOUT after ${limit}s"
    kill -9 "$job" 2>/dev/null
  fi
  wait "$job" 2>/dev/null
}

add_todo() {
  run_bounded 15 @NODE@/bin/node -e "
    const http=require('http');
    const body=JSON.stringify({title:process.argv[1]});
    const r=http.request({host:'127.0.0.1',port:3000,path:'/todos',method:'POST',
      headers:{'content-type':'application/json','content-length':body.length}},(res)=>{
      let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log('ADDED '+d));});
    r.on('error',e=>console.log('ADD-FAILED '+e.message));r.end(body);
  " "$1"
}
list_todos() {
  run_bounded 15 @NODE@/bin/node -e "
    require('http').get({host:'127.0.0.1',port:3000,path:'/todos'},(res)=>{
      let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log('TODOS '+d));
    }).on('error',e=>console.log('LIST-FAILED '+e.message));
  "
}

# On the FIRST boot, write some todos. On later boots, only read — so a
# list that still has them proves the data survived.
# THE APP'S OWN LOG, on the console, BEFORE the first request. It was
# going to /data/todos.log, which nothing ever read — so every error the
# app produced was invisible, and a POST that hung looked like a guest
# problem for most of a session. A log nobody reads is not a log.
#
# Printed here rather than after the requests, because the hang happens
# DURING them: a probe placed afterwards never runs, which is the mistake
# that cost the previous build.
echo "RACHNA-APP-LOG: $(tail -5 /data/todos.log 2>&1 | tr '\n' '|')"

# DOES `timeout` ACTUALLY WORK HERE? The demo hung on a build where the
# applet was present and the wrapper was in place, which means the wrapper
# did not fire — so the applet itself is the thing to doubt. busybox builds
# can omit applets even when the symlink exists, and an absent applet
# prints nothing and returns success-ish, which is indistinguishable from
# working.

if [ "$BOOT" = "1" ]; then
  add_todo "write the VZ backend"; sleep 1
  add_todo "boot a guest with postgres"; sleep 1
  add_todo "snapshot and restore it"; sleep 2
fi
list_todos
sleep 2
list_todos
echo "RACHNA-TODOS-CHECKED"

# NO SHUTDOWN TRAP, deliberately — and this is worth stating because the
# obvious thing does not work. `trap shutdown TERM` was tried: a busybox
# `sh` acting as init does not act on VZ's ACPI power event, because a
# trap fires only after the current command returns and this loop spends
# essentially all its time inside `sleep`. The console showed ticks
# continuing through a stop that was supposed to be graceful.
#
# So durability does not depend on the guest cooperating. The host pauses
# the VM before stopping it, which drains the virtio-blk queue with
# memory and devices intact (`02` §6.10) — the writes land whether or not
# anything in here is listening. A guest that keeps its filesystem
# without a shutdown handler is a better guarantee than one that needs
# one.
#
# `sync` on every tick is the cheap half of the same belt: it costs
# nothing on an idle guest and bounds how much can be in flight.
i=0
while [ $i -lt 900 ]; do
  echo "RACHNA-TICK-$i"
  sync
  sleep 1
  i=$((i+1))
done
