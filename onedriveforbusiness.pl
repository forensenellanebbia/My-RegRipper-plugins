#-----------------------------------------------------------
# onedriveforbusiness.pl
# Plugin for RegRipper 2.8/3.0
#
# This plugin parses the following keys:
#    - HKCU\Software\Microsoft\OneDrive\Accounts\Business1
#    - HKCU\Software\SyncEngines\Providers\OneDrive
#
# Change history
#   20200601 - First release
#
#
# Author : Gabriele Zambelli
# Email  : forensenellanebbia at gmail.com
# Blog   : https://forensenellanebbia.blogspot.it
# Twitter: @gazambelli
#-----------------------------------------------------------

package onedriveforbusiness;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20200601);

sub getShortDescr { return "Extracts OneDrive for Business entries"; }
	
sub getDescr   {}
sub getRefs    {}
sub getHive    {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive  = shift;
	::rptMsg("onedriveforbusiness v.".$VERSION); 
	::rptMsg("(".getHive().") ".getShortDescr()."\n");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	
	# Check if OneDrive for Business is used
	my $version;
	my $tag = 0;
	my @globalitems = ();
	my $key_path = "Software\\Microsoft\\OneDrive\\Accounts\\Business1";
	if (defined($root_key->get_subkey($key_path))) {
		$tag = 1;
	}
	else {
		::rptMsg($key_path." not found.");
	}

	if ($tag) {
		::rptMsg("** Account and settings **");
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
			my %vals = getKeyValues($key);
			if (scalar(keys %vals) > 0) {
				foreach my $v (keys %vals) {
					if ($v =~ m/^ClientFirstSignInTimestamp/
						|| $v =~ m/^NextMigrationScan/
						|| $v =~ m/^SPOLastUpdate/
						|| $v =~ m/^ECSConfigurationExpires/
						|| $v =~ m/^ShareTimeStamp/
						|| $v =~ m/^LastSignInTime/
						|| $v =~ m/^NextOneRmUpdateTime/) {
						my $ts = unpack("VV", $key->get_value($v)->get_data());
						::rptMsg("\t".$v." -> ".gmtime($ts)." (UTC)");
					}
					else {
						::rptMsg("\t".$v." -> ".$vals{$v});
					}
				}
			}
		}
		if ($key = $root_key->get_subkey($key_path."\\ScopeIdToMountPointPathCache")) {
			::rptMsg("");
			::rptMsg("** OneDrive folders synced to the computer (Personal and 'Shared with me' folders) **");
			::rptMsg($key_path."\\ScopeIdToMountPointPathCache");
			::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
			my %vals = getKeyValues($key);
			if (scalar(keys %vals) > 0) {
				foreach my $v (keys %vals) {
					::rptMsg("\t".$v." -> ".$vals{$v});
				}
			}
		}
		my $key_path = "Software\\SyncEngines\\Providers\\OneDrive";
		my $key = $root_key->get_subkey($key_path);
		my @sk = $key->get_list_of_subkeys();
		if (scalar(@sk) > 0) {
			foreach my $s (@sk) {
				::rptMsg("");
				::rptMsg($key_path."\\".$s->get_name());
				::rptMsg("LastWrite Time ".gmtime($s->get_timestamp())." (UTC)");
				my %vals = getKeyValues($s);
				foreach my $v (keys %vals) {
						::rptMsg("\t".$v." -> ".$vals{$v});
				}
			}
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