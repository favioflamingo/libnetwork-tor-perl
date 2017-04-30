package Network::Tor;

use 5.020002;
use utf8;
use strict;
use warnings;
use Carp;
use Convert::Base32; # libconvert-base32-perl
use MIME::Base64; # libmime-base64-perl
use Crypt::OpenSSL::RSA; # libcrypt-openssl-rsa-perl
use Encode qw(decode encode);
use Data::Dumper;

require Exporter;


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

our $VERSION = '0.1';
# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

my $multilineregex = qr/^(\d{3})\+([0-9a-zA-Z\-\/\*]+)\=$/;
my $multiline_middle_regex = qr/^(.*)$/;
my $doublelineregex = qr/^(\d{3})\-([0-9a-zA-Z\-\/\*\:]+)\=(.*)$/;
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
		,'bytes read' => 0
		,'buffer' => ''
		,'write buffer' => ''
	};
		
	bless($this,$package);
	
	$this->password($password);
	$this->address($address);
	
	$this->reset_current();
	
	return $this;
}


=pod

---+ getters/setters

=cut

=pod

---++ socket

Return the IO socket.

=cut

sub socket{
	return shift->{'socket'};
}


=pod

---++ authenticated->0/1

Have we authenticated yet?

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

---++ onion_calculate()->($private_key,$hostname)

Generate an onion url usable on tor.

=cut

sub onion_calculate{
	my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
	#my $rsa = Crypt::OpenSSL::RSA->new_private_key($PRIVKEY);
	
	my $pub = $rsa->get_public_key_string();
	my @p = split(/\n/,$pub);
	shift(@p); pop(@p);
	$pub = join('',@p);
	#warn "Got pub=$pub\n";
	
	my $onion = Convert::Base32::encode_base32(Digest::SHA::sha1(MIME::Base64::decode_base64($pub)));
	$onion = substr($onion,0,16).'.onion';
	#warn "Got onion=$onion\n";
	
	return ($rsa->get_private_key_string(),$onion);
}

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
	$socket->autoflush(1);
	binmode($socket);

	$this->{'socket'} = $socket;
	
}

=pod

---++ sendauth($onsuccauth)

Send authentication to tor control port.  Runs callback on success.

=cut

sub sendauth{
	my ($this,$callback) = @_;
	$callback //= sub{};
	$this->sendcmd(
		'AUTHENTICATE "'.$this->password.'"'
		,sub{
			my ($cb) = ($callback);
			my ($t1,$status,$status_msg,$dataref) = @_;
			if($status == 250){
				#warn "successfully authenticated";
				$t1->{'authenticated'} = 1;
				$cb->();
			}
			else{
				die "authentication failed";
			}
		}
	);
}


=pod

---++ sendcmd($cmd,$callback)

Send a command to tor and then get a response back.

=cut

sub sendcmd {
	my ($this,$cmd,$callback) = @_;
	die "no command" unless defined $cmd && 0 < length($cmd);
	$callback //= sub{};
	#warn "appending command=[$cmd]";
	push(@{$this->{'commands'}},[$cmd,$callback]);	
	
	# add this to flush the last line of the response to $cmd
	#push(@{$this->{'commands'}},["GETINFO dormant",sub{}]);
	
	if($this->{'socket read only'}){
		$this->setwrite();
	}
}

=pod

---++ dequeue()->$cmd

=cut

sub dequeue {
	my ($this) = @_;
	return undef unless 0 < scalar(@{$this->{'commands'}});
	my $x = shift(@{$this->{'commands'}});
	#warn "coderef=".ref($x->[1]);
	push(@{$this->{'callbacks'}},$x->[1]);
	
	return $x->[0];
}

=pod

---++ setwrite($sub)

If we need to write to the socket, use this sub to set the socket (event loop event mask) to write.

To add a setwrite sub, just put in the sub reference as an argument.

=cut

sub setwrite{
	my ($this,$x) = @_;
	#warn "setwrite";
	if(defined $x && ref($x) eq 'CODE'){
		$this->{'setwrite'} = $x;
	}
	elsif(defined $x){
		die "bad setwrite sub";
	}
	elsif(!defined $this->{'setwrite'}){
		die "no setwrite sub";
	}
	else{
		$this->{'socket read only'} = 0;
		$this->{'setwrite'}->();
	}
}

=pod

---++ setread($sub)

If there is nothing in the queue, then just set the socket to read only.

=cut

sub setread {
	my ($this,$x) = @_;
	if(defined $x && ref($x) eq 'CODE'){
		$this->{'setread'} = $x;
	}
	elsif(defined $x){
		die "bad setread sub";
	}
	elsif(!defined $this->{'setread'}){
		die "no setread sub";
	}
	else{
		$this->{'socket read only'} = 1;
		$this->{'setread'}->();
	}
}


=pod

---++ write_socket

=cut

sub write_socket{
	my $this = shift;
	
	my $socket = $this->socket();
	
	if(0 < length($this->{'write buffer'})){
		my $buf = $this->{'write buffer'};
		$this->{'write buffer'} = '';
		my $n = syswrite($socket,$buf,8192);
		$this->{'write buffer'} = substr($buf,$n);
		return undef;
	}
	
	my $cmd = $this->dequeue();
	
	#warn "do write";
	if(defined $cmd){
		#warn "Printing cmd=[$cmd]";
		$cmd = encode('UTF-8', "$cmd\n", Encode::FB_CROAK);
		my $n = syswrite($socket,$cmd,8192);
		$this->{'write buffer'} = substr($cmd,$n);
	}
	else{
		$this->setread();
	}
}

=pod

---++ read_socket

=cut

sub read_socket{
	my $this = shift;
	my $socket = $this->socket();
	my ($m,$n,$buf) = (0,$this->{'bytes read'},'');
	# read in via socket
	$m += sysread($socket,$buf,4*8192);
	$this->{'bytes read'} += $m;
	$buf = decode('UTF-8', $buf,     Encode::FB_CROAK);
	$this->{'buffer'} .= $buf;
	
	#warn "Buffer=".$this->{'buffer'};
	
	my @lines;
	my $x = $this->{'buffer'};
	while(0 < length($x)){
		if($x =~ m/^([^\n\r]+)[\n\r]*(.*)$/s){
			my $y = $1;
			push(@lines,$y) if 0 < length($y);
			$x = $2;
		}
		else{
			warn "What?";
			last;
		}
	}
	if(0 < length($x)){
#		warn "left over=$x";
		$this->{'buffer'} = $x;
	}
	else{
#		warn "nothing left";
		$this->{'buffer'} = '';
	}
	
	#warn "Lines=[".join('|',@lines)."]";

	if(0 < scalar(@lines)){
		while(my $line = shift(@lines)){
			$this->read_line($line);
		}		
		$this->{'buffer'} = '';
		$this->{'bytes read'} = 0;
	}

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
	my $line = shift;
	
	
	my $current = $this->{'current'};
	
	$line =~ s/[\n\r]*$//;
	
	#warn "type=".$current->{'type'}."...Line=[$line]\n";
	
	if($current->{'type'} == 1 && $line =~ m/$multiline_middle_regex/ && $line ne '.'){
		#warn "multiline middle";
		# keep going
		push(@{$current->{'key value data'}},$1);

		return undef;
	}
	elsif($current->{'type'} == 1 && $line eq '.'){
		#warn "stopping multiline\n";
		$current->{'type'} = 0;
		$current->{'data'}->{$current->{'keyword'}} = $current->{'key value data'};
		return undef;
	}
	elsif($current->{'type'} == 1){
		die "bad data with line=[$line]";
	}
	
	my ($status,$keyword,$data);
	if($line =~ m/$multilineregex/){
		# starting multiline
		($status,$keyword,$data) = ($1,$2,'');
		#warn "($status,$keyword,$data)";
		#warn "setting type=1\n";
		$current->{'keyword'} = $keyword;
		$current->{'key value data'} = [];
		# data gets picked up until we read a '.'
		$current->{'type'} = 1;
		#warn "starting multiline";
	}
	elsif($line =~ m/$doublelineregex/){
		# starting double line
		($status,$keyword,$data) = ($1,$2,$3);
		#warn "($status,$keyword,$data)";
		$current->{'data'}->{$keyword} = $data;
		#$current->{'type'} = 0;
		#warn "starting double line";
	}
	elsif($line =~ m/$singlelineregex/){
		#warn "($status,$keyword,$data)";
		# done, so type=0
		$current->{'status'} = $1;
		$current->{'status message'} = $2;
		#warn "stopping singleline\n";
		$this->read_data();
	}
	else{
		die "Got line=$line with type=".$current->{'type'};
	}
	return;
	
}


# used only in read_line
sub reset_current{
	my $this = shift;	
	my $current = $this->{'current'};
	#warn "resetting from type=".$current->{'type'}."\n";

	$current->{'type'} = 0;
	$current->{'data'} = {};
	$current->{'prestopped'} = 0;
	$current->{'keyword'} = '';
	$current->{'status'} = 0;
	$current->{'status message'} = '';
	$current->{'key value data'} = [];
};

=pod

---++ read_data

After reading lines and getting a 250 OK response, then feed the data to the callback.

Callback args=($status,$status_message,$keyword,$data)

where $data is an array ref.

=cut

sub read_data{
	my $this = shift;
	my $current = $this->{'current'};

	#warn "($status,$status_message,$keyword)\n";
	#warn "..data=\n...".join("\n...",@{$data});
	my $callback = shift(@{$this->{'callbacks'}});
	die "no callback" unless defined $callback && ref($callback) eq 'CODE';
	
	#warn "data=".Data::Dumper::Dumper($current->{'data'});
	# do a deep copy of data?
	
	$callback->(
		$this
		,$current->{'status'}
		,$current->{'status message'},
		,$current->{'data'}
	);
	
	$this->reset_current();
}


=pod

---+ commands

=cut

=pod

---++ getinfo($callback,'version')

	# desc/id/$ORID
	# md/id/<OR identity>
	# desc-annotations/id/<OR identity>
	# ns/id/<OR identity>

=cut

my $getinfo_cb;

BEGIN{
	 $getinfo_cb = {
		'version' => \&getinfo_default
		,'config-file' => \&getinfo_default
		,'config-default-file' => \&getinfo_default
		,'config-text' => \&getinfo_default
		,'exit-policy/default' => \&getinfo_default
		,'exit-policy/reject-private/default' => \&getinfo_default
		,'exit-policy/reject-private/relay' => \&getinfo_default
		,'exit-policy/ipv4' => \&getinfo_default
		,'exit-policy/ipv6' => \&getinfo_default
		,'exit-policy/full' => \&getinfo_default
		,'dormant' => \&getinfo_default
		,'desc/all-recent' => \&getinfo_default
		,'ns/all' => \&getinfo_default
		,'onions/current' => \&getinfo_default
		,'onions/detached' => \&getinfo_default
	};
}

sub getinfo{
	my ($this,$callback,$keyword) = @_;
	
	$callback //= $getinfo_cb->{$keyword};
	die "bad keyword for GETINFO" unless defined $callback && ref($callback) eq 'CODE';
	
	$this->sendcmd(
		"GETINFO $keyword",
		$callback
	);

}


sub getinfo_default{
	#my ($this,$keyword,$data) = @_;
	my ($this,$status,$status_msg,$dataref) = @_;
	warn "Got [$status,$status_msg]\n".Data::Dumper::Dumper($dataref);
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

sub onion_add{
	my ($this,$callback,$hiddenport,$target,$options) = @_;
	$callback //= sub{};
	$options //= {};
	
	my ($taddr,$tport);
	if($target =~ m/^([^\:]+)\:(\d+)$/){
		$taddr = $1;
		$tport = $2;
	}
	else{
		die "bad onion target";
	}
	
	if($hiddenport =~ m/^(\d+)$/){
		$hiddenport = $1;
	}
	else{
		die "bad hidden port";
	}
	
	my $flag = '';
	if(defined $options->{'Flag'}){
		$flag = "Flags=".$options->{'Flag'};
	}
	
	$this->sendcmd(
		"ADD_ONION NEW:BEST $flag Port=$hiddenport,$taddr:$tport"
		,$callback
	);
	
	
}

=pod

---++ onion_del(sub{},'djf94fnlkdnsl')

=cut

sub onion_del{
	my ($this,$callback,$onionurl) = @_;
	if($onionurl =~ m/^([0-9a-zA-Z\-\.]+)(?:\.onion)?$/){
		$onionurl = $1;
	}
	else{
		die "bad onion url";
	}
	$callback //= sub{};
	$this->sendcmd("DEL_ONION $onionurl",$callback);
}

=pod

---++ onion_current

onions/current

=cut

sub onion_current{
	

}


=pod

---++ onion_detached

=cut

sub onion_detached{
	my ($this,$callback) = @_;
	
	$callback //= sub{};
	
	$this->sendcmd("");
}

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
