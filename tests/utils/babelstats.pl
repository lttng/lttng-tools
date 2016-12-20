#!/usr/bin/perl

# Copyright (C) - 2012 Christian Babeux <christian.babeux@efficios.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License, version 2 only, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use strict;
use warnings;

use Getopt::Long;

my $opt_tracepoint;

GetOptions('tracepoint=s' => \$opt_tracepoint)
	or die("Invalid command-line option\n");

defined($opt_tracepoint)
	or die("Missing tracepoint, use --tracepoint <name>");

# Parse an array string.
# The format is as follow: [ [index] = value, ... ]
sub parse_array
{
	my ($arr_str) = @_;
	my @array = ();

	# Strip leading and ending brackets, remove whitespace
	$arr_str =~ s/^\[//;
	$arr_str =~ s/\]$//;
	$arr_str =~ s/\s//g;

	my @entries = split(',', $arr_str);

	foreach my $entry (@entries) {
		if ($entry =~ /^\[(\d+)\]=(\d+)$/) {
			my $index = $1;
			my $value = $2;
			splice @array, $index, 0, $value;
		}
	}

	return \@array;
}

# Parse fields values.
# Format can either be a name = array or a name = value pair.
sub parse_fields
{
	my ($fields_str) = @_;
	my %fields_hash;

	my $field_name = '[\w\d_]+';
	my $field_value = '[\w\d_\\\*"]+';
	my $array = '\[(?:\s\[\d+\]\s=\s\d+,)*\s\[\d+\]\s=\s\d+\s\]';

	# Split the various fields
	my @fields = ($fields_str =~ /$field_name\s=\s(?:$array|$field_value)/g);

	foreach my $field (@fields) {
		if ($field =~ /($field_name)\s=\s($array)/) {
			my $name  = $1;
			my $value = parse_array($2);
			$fields_hash{$name} = $value;
		}

		if ($field =~ /($field_name)\s=\s($field_value)/) {
			my $name  = $1;
			my $value = $2;
			$fields_hash{$name} = $value;
		}
	}

	return \%fields_hash;
}

# Using an event array, merge all the fields
# of a particular tracepoint.
sub merge_fields
{
	my ($events_ref) = @_;
	my %merged;

	foreach my $event (@{$events_ref}) {
		my $tp_event     = $event->{'tp_event'};
		my $tracepoint  = "${tp_event}";

		foreach my $key (keys %{$event->{'fields'}}) {
			my $val = $event->{'fields'}->{$key};

			# TODO: Merge of array is not implemented.
			next if (ref($val) eq 'ARRAY');
			$merged{$tracepoint}{$key}{$val} = undef;
		}
	}

	return \%merged;
}

# Print the minimum and maximum of each fields
# for a particular tracepoint.
sub print_fields_stats
{
	my ($merged_ref, $tracepoint) = @_;

	return unless ($tracepoint && exists $merged_ref->{$tracepoint});

	foreach my $field (keys %{$merged_ref->{$tracepoint}}) {
		my @sorted;
		my @val = keys %{$merged_ref->{$tracepoint}->{$field}};

		if ($val[0] =~ /^\d+$/) {
			# Sort numerically
			@sorted = sort { $a <=> $b } @val;
		} elsif ($val[0] =~ /^0x[\da-f]+$/i) {
			# Convert the hex values and sort numerically
			@sorted = sort { hex($a) <=> hex($b) } @val;
		} else {
			# Fallback, alphabetical sort
			@sorted = sort { lc($a) cmp lc($b) } @val;
		}

		my $min = $sorted[0];
		my $max = $sorted[-1];

		print "$field $min $max\n";
	}
}

my @events;

while (<>)
{
	my $timestamp   = '\[(?:.*)\]';
	my $elapsed     = '\((?:.*)\)';
	my $hostname    = '(?:.*)';
	my $tp_event    = '(.*)';
	my $pkt_context = '(?:\{[^}]*\},\s)*';
	my $fields      = '\{(.*)\}$';

	# Parse babeltrace text output format
	if (/$timestamp\s$elapsed\s$hostname\s$tp_event:\s$pkt_context$fields/) {
		my %event_hash;
		$event_hash{'tp_event'}    = $1;
		$event_hash{'fields'}      = parse_fields($2);

		push @events, \%event_hash;
	}
}

my %merged_fields = %{merge_fields(\@{events})};
print_fields_stats(\%merged_fields, $opt_tracepoint);
