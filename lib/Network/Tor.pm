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

my $multilineregex = qr/^(\d{3})\+([0-9a-zA-Z\-\/\*]+)\=$/;
my $multiline_middle_regex = qr/^(\d{3})\s(.*)$/;
my $doublelineregex = qr/^(\d{3})\-([0-9a-zA-Z\-\/\*]+)\=(.*)$/;
my $singlelineregex = qr/^(\d{3})\s(.*)$/;

=pod

---+ constructors

   * [[https://gitweb.torproject.org/torspec.git/tree/control-spec.txt][Control Spec]]

=cut

=pod

---++ new("thesuperpassword","127.0.0.1:9051")

=cut

sub new {
	my ($package,$password,$address) = @_;
	
	my $this = {
		'commands' => []
		,'callbacks' => []
		,'authenticated' => 0
		,'current' => {'type' => 0,'data' => [],'prestopped' => 0}
	};
		
	bless($this,$package);
	
	$this->password($password);
	$this->address($address);
	
	return $this;
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

Include the port.  Returns only the address.

=cut

sub address{
	my ($this,$x) = @_;
	if(!defined $x){
		return $this->{'address'};
	}
	elsif($x =~ m/^([0-9a-zA-Z\.]+)(?:\:(\d+))?$/){
		$this->{'address'} = $1;
		$this->{'port'} = $2;
		return $this->{'address'};
	}
	else{
		die "bad address";
	}
}

=pod

---++ port

=cut

sub port{
	return shift->{'port'};
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

	$this->sendcmd(
		'AUTHENTICATE "'.$this->password.'"'
		,sub{
			my $response = shift;
			my $t1 = $this;
			$response =~ s/[\n\r]*$//;
			if($response =~ m/^250 OK$/){
				warn "Authenticated";
				$t1->{'authenticated'} = 1;
			}
			else{
				die "bad authentication";
			}
		}
	);
	$this->{'socket'} = $socket;
	
}

=pod

---++ sendcmd($cmd,$callback)

=cut

sub sendcmd {
	my ($this,$cmd,$callback) = @_;
	die "no command" unless defined && 0 < length($cmd);
	$callback //= sub{};
	push(@{$this->{'commands'}},[$cmd,$callback]);		
}

=pod

---++ dequeue()->$cmd

=cut

sub dequeue {
	my ($this) = @_;
	return undef unless 0 < scalar(@{$this->{'commands'}});
	my $x = shift(@{$this->{'commands'}});
	push(@{$this->{'callbacks'}},$x->[1]);
	return $x->[0];
}

=pod

---++ read_line($line)

2.3. Replies from Tor to the controller

    Reply = SyncReply / AsyncReply
    SyncReply = *(MidReplyLine / DataReplyLine) EndReplyLine
    AsyncReply = *(MidReplyLine / DataReplyLine) EndReplyLine

    MidReplyLine = StatusCode "-" ReplyLine
    DataReplyLine = StatusCode "+" ReplyLine CmdData
    EndReplyLine = StatusCode SP ReplyLine
    ReplyLine = [ReplyText] CRLF
    ReplyText = XXXX
    StatusCode = 3DIGIT

  Multiple lines in a single reply from Tor to the controller are guaranteed to
  share the same status code. Specific replies are mentioned below in section 3,
  and described more fully in section 4.

  [Compatibility note:  versions of Tor before 0.2.0.3-alpha sometimes
  generate AsyncReplies of the form "*(MidReplyLine / DataReplyLine)".
  This is incorrect, but controllers that need to work with these
  versions of Tor should be prepared to get multi-line AsyncReplies with
  the final line (usually "650 OK") omitted.]
  
250+circuit-status=
373 BUILT $4A0E54E69343B7CF6138C118843CE860E8511F78~yoshihisa BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2017-04-28T12:04:26.619127
372 BUILT $B204DE75B37064EF6A4C6BAF955C5724578D0B32~cry BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2017-04-28T11:59:21.622452
371 BUILT $C4AEA05CF380BAD2230F193E083B8869B4A29937~bakunin4 BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2017-04-28T11:59:21.620241
.
250 OK

250-address-mappings/all=
250 OK

250-version=0.2.5.12 (git-6350e21f2de7272f)
250 OK


=cut

sub read_line{
	my $this = shift;
	my $current = $this->{'current'};
	my $line = shift;
	$line =~ s/[\n\r]*$//;
	
	#warn "...Line=[$line]\n";
	
	
	
	if($current->{'type'} == 1 && $line =~ m/$multiline_middle_regex/ && !$current->{'prestopped'}){
		# keep going
		push(@{$current->{'data'}},$2);
		#warn "pushing data=$2";
		return undef;
	}
	elsif($current->{'type'} == 1 && $line =~ m/^\.$/){
		#warn "prestopping multiline\n";
		$current->{'prestopped'} = 1;
		return undef;
	}
	elsif($current->{'type'} == 1 && $line =~ m/$singlelineregex/){
		#warn "stopping multiline\n";
		$current->{'status'} = $1;
		$current->{'status message'} = $2;
		$this->reset_current();
		return undef;
	}
	elsif($current->{'type'} == 1){
		die "bad data";
	}
	elsif($current->{'type'} == 2 && $line =~ m/$singlelineregex/){
		$current->{'status'} = $1;
		$current->{'status message'} = $2;
		#warn "stopping doubleline\n";
		$this->reset_current();
		# got all the data
		
		return undef;
	}
	elsif($current->{'type'} == 2){
		die "bad data";
	}
	
	
	
	my ($status,$keyword,$data);
	if($line =~ m/$multilineregex/){
		# starting multiline
		($status,$keyword,$data) = ($1,$2,'');
		#warn "($status,$keyword,$data)";
		#warn "setting type=1\n";
		$current->{'keyword'} = $keyword;
		$current->{'type'} = 1;
	}
	elsif($line =~ m/$doublelineregex/){
		# starting double line
		($status,$keyword,$data) = ($1,$2,$3);
		#warn "($status,$keyword,$data)";
		$current->{'keyword'} = $keyword;
		push(@{$current->{'data'}},$data);
		$current->{'type'} = 2;
	}
	elsif($line =~ m/$singlelineregex/){
		#warn "($status,$keyword,$data)";
		# done, so type=0
		$current->{'status'} = $1;
		$current->{'status message'} = $2;
		$this->reset_current();
		#warn "stopping singleline\n";
		
	}
	else{
		die "Got line=$line with type=".$current->{'type'};
	}
	return;
	
}


# used only in read_line
sub reset_current{
	my $this = shift;	
	$this->read_data();
	
	my $current = $this->{'current'};
	#warn "resetting from type=".$c1->{'type'}."\n";
	$current->{'type'} = 0;
	$current->{'data'} = [];
	$current->{'prestopped'} = 0;
	$current->{'keyword'} = '';
	$current->{'status'} = 0;
	$current->{'status message'} = '';
};

=pod

---++ read_data

After reading lines and getting a 250 OK response, then feed the data to the callback.

=cut

sub read_data{
	my $this = shift;
	my $current = $this->{'current'};
	my ($status,$status_message,$keyword,$data) = (
		$current->{'status'},$current->{'status message'},
		$current->{'keyword'},$current->{'data'}
	);
	
	warn "($status,$status_message,$keyword)\n";
	warn "..data=\n...".join("\n...",@{$data});
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
