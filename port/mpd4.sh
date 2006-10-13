#!/bin/sh

# PROVIDE: mpd
# REQUIRE: NETWORKING

#
# Add the following lines to /etc/rc.conf to enable mpd4:
#
# mpd_enable="YES"	# YES or NO (default)
#
mpd_enable=${mpd_enable-"NO"}

. %%RC_SUBR%%

name=mpd4
rcvar=`set_rcvar mpd`
prefix=%%PREFIX%%
pidfile=/var/run/${name}.pid
command="${prefix}/sbin/${name}"
command_args="-b -p ${pidfile}"
required_files="${prefix}/etc/${name}/mpd.conf ${prefix}/etc/${name}/mpd.links"

load_rc_config $name

run_rc_command "$1"
