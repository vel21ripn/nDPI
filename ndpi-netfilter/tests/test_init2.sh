

grep -q iptable_filter /proc/modules || /etc/init.d/ipt_modules start

[ -e /sys/module/xt_ndpi ] || insmod ../src/xt_ndpi.ko lib_trace=0 xt_debug=3

echo "add_custom TEST" >/proc/net/xt_ndpi/proto

echo "reset" >/proc/net/xt_ndpi/host_proto

for i in `seq 1 5`; do
	[ -f "p$i" ] || continue
	if cat p$i >/proc/net/xt_ndpi/host_proto 2>/dev/zero ; then
		if [ -e "p$i.err" ]; then echo ERROR; else echo OK ; fi
	else
		if [ -e "p$i.err" ]; then echo OK; else echo ERROR ; fi
	fi
	diff -u /proc/net/xt_ndpi/host_proto p$i.res
done

#iptables-restore <.iptables.cmd
#rmmod xt_ndpi
