#-----------------------------------------------------------
# featureusage.pl
# Plugin for RegRipper 2.8/3.0 
#
# This plugin parses the following keys and sorts data by frequency in descending order:
#    - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated
#    - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch
#    - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
#    - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
#
# Please consider this plugin as an alternative to the one developed by H. Carvey
#
# Change history
#   20200601 - First release
#
# References
#  - Reconstructing User Activity for Forensics with FeatureUsage (by Oleg Skulkin)
#    https://www.group-ib.com/blog/featureusage
#
# Author : Gabriele Zambelli
# Email  : forensenellanebbia at gmail.com
# Blog   : https://forensenellanebbia.blogspot.it
# Twitter: @gazambelli
#-----------------------------------------------------------

package featureusage;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200601);

sub getShortDescr { return "Extracts FeatureUsage entries"; }
	
sub getDescr   {}
sub getRefs    {}
sub getHive    {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my @arr;

sub print_kv {
	my ($key, $key_path) = @_;
	::rptMsg($key_path);
	::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
	my %vals = getKeyValues($key);
	if (scalar(keys %vals) > 0) {
		foreach my $v (keys %vals) {
			push @arr, ($vals{$v}."\t| ".$v);
		}
	}
	if (scalar(@arr) > 0) {
		foreach my $arrval (sort {$b <=> $a} @arr){
			::rptMsg($arrval);
		}
	}
		@arr = ();
}

sub pluginmain {
	my $class = shift;
	my $hive  = shift;
	::rptMsg("featureusage v.".$VERSION); 
	::rptMsg("(".getHive().") ".getShortDescr()."\n");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	
	# Check if FeatureUsage is present
	my $version;
	my $tag = 0;
	my @globalitems = ();
	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage";
	if (defined($root_key->get_subkey($key_path))) {
		$tag = 1;
	}
	else {
		::rptMsg($key_path." not found.");
	}

	if ($tag) {
		my $key;
		if ($key = $root_key->get_subkey($key_path."\\AppBadgeUpdated")) {
			::rptMsg("** AppBadgeUpdated = badge updates for applications on taskbar **");
			print_kv($key, $key_path);
		}
		
		if ($key = $root_key->get_subkey($key_path."\\AppLaunch")) {
			::rptMsg("\n** AppLaunch = number of launches of applications that are pinned to taskbar **");
			print_kv($key, $key_path);
		}

		if ($key = $root_key->get_subkey($key_path."\\AppSwitched")) {
			::rptMsg("\n** AppSwitched = number of left clicks on taskbar applications when a user wants to switch from one to another **");
			print_kv($key, $key_path);
		}

		if ($key = $root_key->get_subkey($key_path."\\ShowJumpView")) {
			::rptMsg("\n** ShowJumpView = number of right clicks on taskbar applications **");
			print_kv($key, $key_path);
		}
	}
}

sub getKeyValues {
	my $key = shift;
	my %vals;       
	my @vk = $key->get_list_of_values();
	if (scalar(@vk) > 0) {
		foreach my $v (@vk) {
			next if ($v->get_name() eq "" && $v->get_data() eq "");
			$vals{$v->get_name()} = $v->get_data();
		}
	}
	else {  
	}
	return %vals;
}

1;