# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Network-Tor.t'

#########################

use strict;
use warnings;

#use EV; # need libev-perl for testing
use Test::More tests => 1;
BEGIN { use_ok('Network::Tor') };




__END__

use strict;
use warnings;

use EV; # need libev-perl for testing
use Test::More tests => 1;
BEGIN { use_ok('Network::Tor') };

#########################

# create tor control object
my $torcontrol = Network::Tor->new($ENV{'TorControlPassword'},$ENV{'TorControlAddress'});
$torcontrol->connect();

# create event loop
my $loop = EV::default_loop();

# add watchers
my $sock = $torcontrol->socket();
my $w = $loop->io($sock, EV::READ || EV::WRITE, sub {
	my ($w, $revents) = @_; # all callbacks receive the watcher and event mask
	if($revents & EV::READ){
		# do read
		warn "stdin is readable, you entered: ", <$sock>;
	}
	elsif($revents & EV::WRITE){
		# do write
		
	}
	
});
