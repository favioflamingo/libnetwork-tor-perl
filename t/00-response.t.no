use strict;
use warnings;

#use EV; # need libev-perl for testing
use Test::More tests => 1;
BEGIN { use_ok('Network::Tor') };

my $torcontrol = Network::Tor->new("thesuperpassword","127.0.0.1:9051");

my $response = '';
my @lines;

# single line response
$response = '250 OK';
@lines = split("\n",$response);
while(my $l1 = shift(@lines)){
	$torcontrol->read_line($l1);	
}

# double line response
$response = '250-version=0.2.5.12 (git-6350e21f2de7272f)
250 OK';
@lines = split("\n",$response);
while(my $l1 = shift(@lines)){
	$torcontrol->read_line($l1);	
}


# multi line response
$response = '250+circuit-status=
373 BUILT $4A0E54E69343B7CF6138C118843CE860E8511F78~yoshihisa BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2017-04-28T12:04:26.619127
372 BUILT $B204DE75B37064EF6A4C6BAF955C5724578D0B32~cry BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2017-04-28T11:59:21.622452
371 BUILT $C4AEA05CF380BAD2230F193E083B8869B4A29937~bakunin4 BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2017-04-28T11:59:21.620241
.
250 OK';
@lines = split("\n",$response);
while(my $l1 = shift(@lines)){
	$torcontrol->read_line($l1);	
}



__END__
