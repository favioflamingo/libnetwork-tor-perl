package Network::Tor;

use 5.020002;
use utf8;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Network::Tor ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Network::Tor::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Network::Tor', $VERSION);

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

=pod

---+ constructors

   * [[https://gitweb.torproject.org/torspec.git/tree/control-spec.txt][Control Spec]]

=cut

=pod

---++ new

=cut

sub new {
	my ($package,$password,$address) = @_;
	
	
}


=pod

---+ getters/setters

=cut

sub authenticated{
	return shift->{'authenticated'};
}

=pod

---++ password

=cut

sub password{
	my ($this,$x) = @_;
	if(!defined $x){
		return $this->{'password'};
	}
	elsif($x =~ m/^([0-9a-zA-Z]+)$/){
		$this->{'password'} = $1;
		return $this->{'password'};
	}
	else{
		die "bad password";
	}
}

=pod

---++ address("192.168.0.23:9051")

=cut

sub address{
	my ($this,$x) = @_;
	if(!defined $x){
		return ($this->{'address'},$this->{'port'});
	}
	elsif($x =~ m/^([0-9a-zA-Z\.]+)(?:\:(\d+))?$/){
		$this->{'address'} = $1;
		$this->{'port'} = $2;
		return ($this->{'address'},$this->{'port'});
	}
	else{
		die "bad address";
	}
}

=pod

---+ utilities

=cut

=pod

---++ connect()

=cut

sub connect{
	my ($this,$evloopsub) = @_; 
	my ($addr,$port) = ($this->{'address'},$this->{'port'});
	use IO::Socket::INET;
	
	my $socket = IO::Socket::INET->new(
		PeerHost => $addr,
		PeerPort => $port,
		Proto => 'tcp',
	) or die "ERROR in Socket Creation : $!\n";

	print $socket 'AUTHENTICATE "'.$this->password.'"'."\n";

	$this->{'authenticated'} = 0;

	$this->{'socket'} = $socket;
	
	my $line = <$socket>;
	chomp($line);
	if($line =~ m/^(250 OK)$/){
		$this->{'authenticated'} = 1;
	}
	else{
		die "bad authentication";
	}
	
}

=pod

---++ sendcmd

=cut

sub sendcmd {
	my ($this,$cmd) = @_;
	my $socket = $this->{'socket'};
	print $socket "$cmd\n";
	
	
}

=pod

---+ commands

=cut

=pod

---++ getinfo('version')

=cut

sub getinfo{
	my ($this,$keyword) = @_;
	
}

=pod

---++ onion_add('version')

  Examples:
     C: ADD_ONION NEW:BEST Flags=DiscardPK Port=80
     S: 250-ServiceID=exampleonion1234
     S: 250 OK

     C: ADD_ONION RSA1024:[Blob Redacted] Port=80,192.168.1.1:8080
     S: 250-ServiceID=sampleonion12456
     S: 250 OK

     C: ADD_ONION NEW:BEST Port=22 Port=80,8080
     S: 250-ServiceID=testonion1234567
     S: 250-PrivateKey=RSA1024:[Blob Redacted]
     S: 250 OK

     C: ADD_ONION NEW:BEST Flags=DiscardPK,BasicAuth Port=22
        ClientAuth=alice:[Blob Redacted] ClientAuth=bob
     S: 250-ServiceID=testonion1234567
     S: 250-ClientAuth=bob:[Blob Redacted]
     S: 250 OK

=cut

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Network::Tor - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Network::Tor;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Network::Tor, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Joel De Jesus, E<lt>joel@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 by Joel De Jesus

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.20.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
