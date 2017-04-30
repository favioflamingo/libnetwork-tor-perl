use 5.020002;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Network::Tor',
    VERSION_FROM      => 'lib/Network/Tor.pm', # finds $VERSION, requires EU::MM from perl >= 5.5
    PREREQ_PM         => {
    	'Carp' => 0
    	,'Convert::Base32' => 0
    	,'MIME::Base64' => 0
    	,'Crypt::OpenSSL::RSA' => 0
    	,'Encode' => 0
    }, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/Network/Tor.pm', # retrieve abstract from module
    AUTHOR            => 'Joel De Jesus <dejesus.joel@e-flamingo.net>',
    #LICENSE           => 'perl',
    #Value must be from legacy list of licenses here
    #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);
