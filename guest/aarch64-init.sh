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

# A SHELL-LEVEL TIMEOUT around each node call, because the init BLOCKS on
# them and a hung request stops the whole guest: the console goes silent,
# no ticks appear, and `rachna status` reports a booted environment as
# though nothing is wrong.
#
# `timeout` rather than node's own `setTimeout`. Both were tried: a bare
# setTimeout keeps node's event loop alive past the response, and calling
# process.exit from inside a callback left the init with nothing after it.
# A timeout outside the process cannot be defeated by anything inside it.
add_todo() {
  timeout 15 @NODE@/bin/node -e "
    const http=require('http');
    const body=JSON.stringify({title:process.argv[1]});
    const r=http.request({host:'127.0.0.1',port:3000,path:'/todos',method:'POST',
      headers:{'content-type':'application/json','content-length':body.length}},(res)=>{
      let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log('ADDED '+d));});
    r.on('error',e=>console.log('ADD-FAILED '+e.message));r.end(body);
  " "$1"
}
list_todos() {
  timeout 15 @NODE@/bin/node -e "
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
