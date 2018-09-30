#!/usr/bin/perl -w

use strict;

my %P;

my $st = 0;
my $cmmnt = '';

die "open ndpi_content_match.c.inc" if !open(F,'<ndpi_content_match.c.inc');
die "create ndpi_content_match.c.inc.new" if !open(R,'>ndpi_content_match.c.inc.new');
while(<F>) {
	chomp();

	if(!$st) {
		if(/ndpi_network\s+host_protocol_list/) {
			print R "#if 0\n";
			print R "$_\n";
			$st = 1;
			next;
		}
		print R "$_\n";
		next;
	}
#	print "# ${st}: $_\n" if $st < 3;
	print R "$_\n" if $st != 4;
	if($st == 1) {
		if(/^\s*$/) {
			next;
		}
		if(m,^\s*/\*,) {
			$cmmnt = '';
			if(m,/\*\s*(.*)\s*\*/,) {
				$cmmnt .= $1."\n";
#print "# ${st}: short comment $1\n";
			} else {
				$st = 2;
			}
			next;
		}
		if(/^\s*\{/) { # No comments. Start network address
			if(add_net(\$cmmnt,$_)) {
				$st = 3;
				next;
			}
			next;
		}
		if(/^#if 0/) {
			while(<F>) {
				print R $_;
				last if /^#endif/;
			}
			next;
		}
		die "?: ".$_;
	}
	if($st == 2) {
		if(m,\*/,) {
			$st = 1;
			next;
		}
		s/^\s*(.*)\s*$/$1/;
		$cmmnt .= $_."\n";
		next;
	}
	if($st == 3) {
		if(/\};/) {
			$st = 4;
#			print R "$_\n";
			print R "#endif\n";
			next;
		}
		next;
	}
	if($st == 4) {
		print R "$_\n";
	}
}
close(R);
close(F);
my $f = 'ndpi_network_list_std.yaml';

if(! -f $f) {
	die "create file $f" if !open(F,'>'.$f);
	foreach (sort keys %P) {
		print_proto(*F,$P{$_}) if $_ ne 'TOR';
	}
	close(F);
}
$f = 'ndpi_network_list_tor.yaml';
if(! -f $f) {
	die "create file $f" if !open(F,'>'.$f);
	print_proto(*F,$P{'TOR'});
	close(F);
}

exit(0);

sub print_proto {
	my ($f,$r) = @_;

	print $f "$r->{n}:\n";
	if($#{$r->{s}} >= 0) {
		print	$f "\tsource:\n\t  - ",join("\n\t  - ",@{$r->{s}}),"\n";
	}
	print	$f "\tip:\n\t  - ",join("\n\t  - ",@{$r->{ip}}),"\n";
}

sub add_net {
	my ($cmmnt,$str) = @_;
	$str =~ s,/\*.*\*/,,;
	$str =~ s,\s+,,g;
	$str =~ s,^\{(.*)\}.*$,$1,;
#	print "# $str\n";
	my @s = split /,/,$str;
	return 1 if $str eq '0x0,0,0';
	die "Bad string $str" if $#s != 2 || $s[0] !~ /^0x/i;
	die "Bad proto $s[2]" if $s[2] !~ /NDPI_(PROTOCOL|CONTENT|SERVICE)_(.*)$/;
	$s[2] = $2;
	$s[0] =~ s/0x//i;
	my $ip = join('.',unpack('C4',pack('H8',$s[0])));

	if( !defined $P{$s[2]} ) {
		$P{$s[2]} = {s=>[],ip=>[],n=>$s[2]} if !defined $P{$s[2]};
#		print "# start $s[2]\n";
	}
	my $r = $P{$s[2]};
	if(${$cmmnt}) {
#		print "#Add comment ${$cmmnt}\n";
		push @{$r->{s}}, split /\n/,${$cmmnt};
		${$cmmnt} = '';
	}
	push @{$r->{ip}}, "$ip/$s[1]";
	return 0;
}


#
# vim: set ts=4:
#
