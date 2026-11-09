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

# The state volume: /dev/vdb if attached, else tmpfs so a cold boot works.
mkdir -p /data
if [ -b /dev/vdb ]; then
  mount /dev/vdb /data 2>/dev/null || mount -t tmpfs tmpfs /data
else
  mount -t tmpfs tmpfs /data
fi
mkdir -p /data/pgdata /data/run
chown -R postgres:postgres /data
echo "RACHNA-STATE-READY"

# Postgres. `12`-era finding: nothing creates the data dir, so do it here.
if [ ! -f /data/pgdata/PG_VERSION ]; then
  su postgres -c "@POSTGRES@/bin/initdb -D /data/pgdata -A trust" >/data/initdb.log 2>&1
  echo "RACHNA-PG-INITDB-DONE"
fi
su postgres -c "@POSTGRES@/bin/postgres -D /data/pgdata -k /data/run -c listen_addresses=''" \
  >/data/postgres.log 2>&1 &

# Wait for the socket, not a fixed sleep.
i=0
while [ $i -lt 60 ]; do
  [ -S /data/run/.s.PGSQL.5432 ] && break
  sleep 0.5; i=$((i+1))
done
if [ -S /data/run/.s.PGSQL.5432 ]; then
  echo "RACHNA-PG-READY"
else
  echo "RACHNA-PG-FAILED"
  tail -5 /data/postgres.log
fi

# The todos app.
# `|| exit` because running the app from the wrong directory would
# look like a missing file rather than a failed cd.
cd /workspace || exit 1
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

add_todo() {
  @NODE@/bin/node -e "
    const http=require('http');
    const body=JSON.stringify({title:process.argv[1]});
    const r=http.request({host:'127.0.0.1',port:3000,path:'/todos',method:'POST',
      headers:{'content-type':'application/json','content-length':body.length}},(res)=>{
      let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log('ADDED '+d));});
    r.on('error',e=>console.log('ADD-FAILED '+e.message));r.end(body);
  " "$1"
}
list_todos() {
  @NODE@/bin/node -e "
    require('http').get({host:'127.0.0.1',port:3000,path:'/todos'},(res)=>{
      let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log('TODOS '+d));
    }).on('error',e=>console.log('LIST-FAILED '+e.message));
  "
}

# On the FIRST boot, write some todos. On later boots, only read — so a
# list that still has them proves the data survived.
if [ "$BOOT" = "1" ]; then
  add_todo "write the VZ backend"; sleep 1
  add_todo "boot a guest with postgres"; sleep 1
  add_todo "snapshot and restore it"; sleep 2
fi
list_todos
sleep 2
list_todos
echo "RACHNA-TODOS-CHECKED"

# Stay alive so the host can pause, snapshot and restore us.
i=0
while [ $i -lt 900 ]; do
  echo "RACHNA-TICK-$i"
  sleep 1
  i=$((i+1))
done
