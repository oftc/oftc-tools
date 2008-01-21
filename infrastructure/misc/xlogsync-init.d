#! /bin/sh

set -e

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DESC="Postgres xlog syncer"
NAME=xlogsync
PIDFILE=/var/run/xlogsync.pid
DAEMON=/usr/local/bin/xlogsync

# Gracefully exit if the package has been removed.
test -x $DAEMON || exit 0

d_start() {
	if start-stop-daemon \
		--signal 0 \
		--stop \
		--quiet \
		--pidfile $PIDFILE \
		--user postgres \
		--group postgres \
		--name "$NAME"; then
		echo "ABORTED: already running." >&2
		exit 0;
	fi

	env -i PATH=$PATH \
	    start-stop-daemon \
		--start \
		--quiet \
		--pidfile "$PIDFILE" \
		--background \
		--make-pidfile \
		--user postgres \
		--group postgres \
		--chuid postgres \
		--exec "$DAEMON"
}

#
#	Function that stops the daemon/service.
#
d_stop() {
	if ! start-stop-daemon --oknodo \
		--stop \
		--retry 10 \
		--quiet \
		--pidfile $PIDFILE \
		--user postgres \
		--group postgres \
		--name "$NAME"; then
		echo -n "FAILED" >&2
	fi
}

case "$1" in
  start)
	echo -n "Starting $DESC: $NAME"
	d_start
	echo "."
	;;
  stop)
	echo -n "Stopping $DESC: $NAME"
	d_stop
	echo "."
	;;
  restart|force-reload)
	echo -n "Restarting $DESC: $NAME"
	d_stop
	sleep 1
	d_start
	echo "."
	;;
  *)
	echo "Usage: $0 {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
