# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Network-Tor.t'

#########################

use strict;
use warnings;

use EV; # need libev-perl for testing
use Test::More tests => 4;
BEGIN { use_ok('Network::Tor') };

######################### set up event loop #######################

# create tor control object
my $torcontrol = Network::Tor->new($ENV{'TorControlPassword'},$ENV{'TorControlAddress'});
$torcontrol->connect();

# create event loop
my $loop = EV::default_loop();

# add watchers
my $sock = $torcontrol->socket();

my $w = $loop->io(fileno($sock), EV::READ | EV::WRITE, sub {
	my ($watcher, $revents) = @_; # all callbacks receive the watcher and event mask
	
	if($revents & EV::READ){
		# do read
		#warn "do read\n";
		$torcontrol->read_socket();
	}
	elsif($revents & EV::WRITE){
		# do write
		$torcontrol->write_socket();
	}
	else{
		#warn "should not be here";
		$loop->break();
	}
});

$torcontrol->setwrite(sub{
	my ($l1,$w2) = ($loop,$w);
	#warn "set to write";
	$w2->set(fileno($sock),EV::READ | EV::WRITE);
});

$torcontrol->setread(sub{
	my ($l1,$w2) = ($loop,$w);
	#warn "no cmd, set to read only";
	$w2->set(fileno($sock),EV::READ);
});

# my timeout , because we only want the test to last 5 seconds
my $wtimer = $loop->timer(5,0,sub{
	my ($l1) = ($loop);
	#warn "finishing loop";
	$l1->break(EV::BREAK_ALL);
});


######################### create tests #######################
$torcontrol->sendauth(sub{
	ok(1,'successful authentication');
	require Data::Dumper;
	# create a hidden service
	my $tc = $torcontrol;
	$tc->getinfo(
		sub{
			my ($this,$status,$status_msg,$dataref) = @_;
			warn "cb($status,$status_msg)\n...".Data::Dumper::Dumper($dataref)."\n";
			ok(
				$dataref->{'version'} =~ m/^0\.2/
				,'checking version'
			);
		}
		,'version'
	);
	
	$tc->getinfo(
		sub{
			my ($this,$status,$status_msg,$dataref) = @_;
			warn "cb($status,$status_msg)\n...".Data::Dumper::Dumper($dataref)."\n";
			ok(
				$dataref->{'status/version/current'} eq 'recommended'
				,'checking status/version/current'
			);
		}
		,'status/version/current'
	);
	
	
	$tc->getinfo(
		sub{
			my ($this,$status,$status_msg,$dataref) = @_;
			warn "cb($status,$status_msg)\n...".Data::Dumper::Dumper($dataref)."\n";
		}
		,'onions/detached'
	);
	
	$tc->onion_add(
		sub{
			my ($this,$status,$status_msg,$dataref) = @_;
			warn "hiddenssh=".Data::Dumper::Dumper($dataref);		
		}
		,'hiddenssh',4222,'ssh-gateway:22'
	);
	
});


######################### run loop #######################
$loop->run();



