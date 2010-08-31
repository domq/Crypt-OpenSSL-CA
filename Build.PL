# -*- coding: utf-8; -*-
# Build.PL, (C) Dominique Quatravaux 2007 (See README for license details)

# This script automatically builds a "Build" file in the current
# directory (using a custom-made subclass to Module::Build), which in
# turn builds the Crypt-OpenSSL-CA package.

use strict;
use warnings;
use FindBin; use lib "$FindBin::Bin/inc";
use Module::Build 0.29;  # For configure_requires
use My::Module::Build;

require 5.008; # Only tested as such.  Advanced features that are
# actually required include full UTF-8 support (ruling out 5.6) and
# exception objects.
my $class = My::Module::Build->subclass(code => join('', <DATA>));

my $builder = $class->new
    ( module_name         => 'Crypt::OpenSSL::CA',
      license             => 'perl',
      dist_author         => 'Dominique Quatravaux <domq@cpan.org>',
      requires            =>
      {
       "XSLoader"        => 0,
      },
      configure_requires =>
      {
       "Module::Build"    => 0.29,
       "Inline"           => 0.40,
       "Inline::C"        => 0,
      },
      build_requires      =>
      {
       "Convert::ASN1"    => 0.20, # 0.20 brings needed utf8 bugfixes
       "Inline"           => 0.40,
       "Inline::C"        => 0,
       # Packages below are needed for the test suite. (And yes,
       # running the test suite *is* a requirement of the build
       # process)
        My::Module::Build->requires_for_build(),
        "Test::Builder"         => 0,
        "Test::More"            => 0,
        "Test::Group"           => 0,
        "IPC::Run"              => 0,
        "File::Find"            => 0,
        "File::Path"            => 0,
        "File::Spec"            => 0,
        "File::Spec::Functions" => 0,
	"File::Slurp"		=> 0,
        "Devel::Leak"           => 0,
        "Devel::Mallinfo"       => 0,
        "Net::SSLeay"           => 1.25, # For access to ERR_ in tests
        "MIME::Base64"          => 0,
        "POSIX"                 => 0,
      },
    add_to_cleanup      => [ 'Crypt-OpenSSL-CA-*', "_Inline" ],
    add_to_no_index     =>
      { namespace => [ "Crypt::OpenSSL::CA::Inline" ] },
    create_makefile_pl  => 'passthrough',
);

if (! $builder->prereq_failures()) {
    $builder->check_openssl_version_number ;
} else {
    warn <<SAME_PLAYER_SHOOTS_AGAIN;

I need some of the above Perl dependencies (most notably, Inline::C)
so as to check that the OpenSSL development kit works.  Therefore,

   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
   !!  Please re-run ./Build.PL  !!
   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

once all the Perl dependencies have been satisfied.

SAME_PLAYER_SHOOTS_AGAIN
    # Unfortunately CPAN.pm cannot read instructions in natural
    # language off STDERR yet, so in order to cater for hands-free
    # installs we need to ->check_openssl_version_number() again at
    # "./Build" time just to be sure.  See L</resume> for discussion.
}

$builder->create_build_script();

1;

__END__

use strict;
use warnings;
use File::Spec::Functions qw(catdir catfile);
use File::Spec::Unix;
use IO::File;
use FindBin qw($Bin);
use My::Module::Build;

=head1 CUSTOM BUILD OPTIONS

=head2 --openssl-cflags=I<string>

Provides the CFLAGS to pass to the compiler so that it finds OpenSSL
header files etc.  Default is to query C<pkg-config>, or failing that,
to use no particular CFLAGS.

=cut

sub openssl_cflags : Config_Option(type="string") {
    (default => scalar(`pkg-config --cflags openssl 2>/dev/null`));
}

=head2 --openssl-ldflags=I<string>

Provides the LDFLAGS to pass to the linker so that it finds OpenSSL
libraries etc.  Default is to query C<pkg-config>, or failing that, to
use only C<-lcrypto -lssl>.

=cut

sub openssl_ldflags : Config_Option(type="string") {
    (default => scalar(`pkg-config --libs openssl 2>/dev/null`));
}

=head2 --full_debugging=1

Enables L<Crypt::OpenSSL::CA::Inline::C/full_debugging> while running
C<./Build test>.  Setting the FULL_DEBUGGING environment variable to 1
has the same effect, however the latter is not possible eg from the
Perl debugger.  Implies C<use_blib=0> (see L<My::Module::Build>).

=cut

sub ACTION_test {
    my $self = shift;

    local $self->{args} = {%{$self->{args}}};
    my %env = $self->customize_env(%ENV);
    delete $env{FULL_DEBUGGING};
    if ($self->{args}->{full_debugging}) {
        $env{FULL_DEBUGGING} = 1;
        $self->use_blib(0);
    }

    $self->depends_on("buildXS") if $self->use_blib;

    local %ENV = %env;
    return $self->SUPER::ACTION_test;
}

=head1 CUSTOM CONSTRUCTOR AND BUILD METHODS

=head2 resume ()

Overloaded so as to set a flag indicating that we are running from
C<./Build> and not C<Build.PL>, for the benefit of
L</fail_because_of_openssl_libs> which can thereafter act coy on
L<CPAN::Reporter>.

=cut

sub resume {
    my $class = shift;
    my $self = $class->SUPER::resume(@_);
    $self->{running_from_build_script} = 1;
    return $self;
}

=head2 ACTION_build ()

Overloaded so as to also call L</ACTION_buildXS>.

=head2 ACTION_buildXS ()

Builds the XS modules for distribution into L<blib/arch>.  Calls
L</check_openssl_version_number>.

=cut

sub ACTION_build {
    my $self = shift;
    $self->depends_on("buildXS");
    $self->SUPER::ACTION_build(@_);
}

sub ACTION_buildXS {
    my ($self) = @_;

    $self->check_openssl_version_number();

    do { unlink($_) or die "Cannot unlink($_): $!" } for glob("*.inl");

    my @sofiles = glob(catfile(qw(blib arch auto Crypt OpenSSL CA * *.so)));
    my @sources = (catfile(qw(lib Crypt OpenSSL CA.pm)),
                   catfile(qw(lib Crypt OpenSSL CA Inline C.pm)));

    return if (@sofiles && $self->up_to_date (\@sources, \@sofiles));

    unlink @sofiles;

    my $version = $self->dist_version;
    # And now some ugly kludge to make everything hold together.
    # Inline::C wants to use MakeMaker; we don't.  So let's call it in
    # a sub-Perl.
    local $ENV{PERL_INLINE_BUILD_NOISY} = 1;
    $self->run_subscript(<<"SCRIPT", $version, catdir(qw(blib arch)));
BEGIN { \$Crypt::OpenSSL::CA::VERSION = '$version' ; }
use Crypt::OpenSSL::CA::Inline::C;
use Inline qw(_INSTALL_);
use Crypt::OpenSSL::CA;
SCRIPT

    do { unlink or die "Cannot unlink($_): $!" } for glob("*.inl");
}

=begin internals

=head1 OVERLOADED METHODS

=head2 process_pm_files ()

Overloaded from parent class so as to reserve a special treatment to
L<Crypt::OpenSSL::CA::Inline::C> (see its POD).

=cut

sub process_pm_files {
    my $self = shift;
    $self->SUPER::process_pm_files(@_);

    $self->require("Crypt::OpenSSL::CA::Inline::C");

    my $out = catfile(qw(blib lib Crypt OpenSSL CA Inline C.pm));
    unlink($out);
    my $outfd = new IO::File($out, ">") or
        die "Cannot open $out for writing: $!";
    ($outfd->print(Crypt::OpenSSL::CA::Inline::C->installed_version) &&
     $outfd->close()) or
         die "Cannot write to $out: $!\n";
}

=head1 ADDITIONAL METHODS

=head2 topdir ()

Returns the directory in which C<Build.PL> resides.

=cut

sub topdir {
    # May not be good enough in some cases, but as long as the tests
    # do pass...
    require FindBin;
    return $FindBin::Bin;
}

=head2 customize_env (%env)

Takes %env as an environment hash and returns a modified copy of it
where the L<Crypt::OpenSSL::CA/ENVIRONMENT VARIABLES> are set.  To be
used typically as

   local %ENV = $self->customize_env(%ENV);

right before doing anything that might result in the inline C code
being recompiled.

=cut

sub customize_env {
    my ($self, %env) = @_;
    foreach my $item (qw(openssl_ldflags openssl_cflags)) {
        my $varname = "BUILD_" . uc($item);
        delete $env{$varname};
        $env{$varname} = $self->option_value("$item")
            if $self->option_value("$item");
    }
    return %env;
}

=head2 run_subscript ($script_text, @argv)

Runs $script_text, a (possibly multi-line) script, in a sub-Perl with
the environment appropriately set up so that it can invoke code in
this package.  @argv is passed on the command line.  Dies upon errors.

=cut

sub run_subscript {
    my ($self, $script, @argv) = @_;
    chomp($script); $script =~ s/\n/ /g;
    my @cmdline = ($^X, "-I" => catdir($self->topdir, "lib"),
                   -e => $script, @argv);
    warn(join(" ", @cmdline, "\n"));
    local %ENV = $self->customize_env(%ENV);
    system(@cmdline);
    die "Command exited with status " . ($? >> 8) if $?;
}

=head2 check_openssl_version_number ()

Checks that the OpenSSL development kit is working (ie, include files
available + libraries that one can link a .so with) and additionally
that the version thereof is 0.9.7 or later.  If successful, encaches
that information (persistently) so that subsequent calls to
I<check_openssl_version_number> return immediately (even from another
invocation of C<Build.PL> or C<Build>).  If not, terminates with
L</fail_because_of_openssl_libs>.

=cut

sub check_openssl_version_number {
    my ($self) = @_;

    my $cachekey = "checked_openssl_version_number";
    return if ($self->notes($cachekey));

    $self->require("Crypt::OpenSSL::CA::Inline::C");

    warn <<"MESSAGE";

Checking OpenSSL version number...

MESSAGE

    my $test_c_program = <<"SOME_C_BONDAGE";
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

static
long from_include_files() {
  return OPENSSL_VERSION_NUMBER;
}

static
long from_linked_library() {
  return SSLeay();
}

SOME_C_BONDAGE

    my $target_package = "Crypt::OpenSSL::CA::ExtractVersionNumber";
    local %ENV = $self->customize_env(%ENV);
    eval {
        Crypt::OpenSSL::CA::Inline::C->
          compile_into($target_package, $test_c_program);
        1;
    } or do {
        # Bummer, C compilation went bang.  Retry it with debugging on
        # so that the user gets a clue:
        my $error = $@;
        $target_package .= "Problem";
        local $ENV{PERL_INLINE_BUILD_NOISY} = 1;
        eval {
            Crypt::OpenSSL::CA::Inline::C->
              compile_into($target_package, $test_c_program);
        };
        $error ||= $@;
        $self->fail_because_of_openssl_libs(<<"MESSAGE");
$error

Compiling and linking a test OpenSSL program failed; please examine
the errors above.  You may have to install OpenSSL's development kit
according to your distribution's instructions.
MESSAGE
    };

    my ($incversion, $libversion) = map
          { sprintf("0x%xd", $target_package->can($_)->()) }
            (qw(from_include_files from_linked_library));

    unless ($incversion eq $libversion) {
        $self->fail_because_of_openssl_libs(<<"VERSION_MISMATCH");

*** VERSION MISMATCH in OpenSSL test program! ***

The version number extracted from OpenSSL's header files ($incversion)
differs from the one returned by a call to OpenSSL's SSLeay() ($libversion).

This means that several versions of the OpenSSL development kit are
present (in whole or in part) on your system.
VERSION_MISMATCH
    }

    if (hex($libversion) < 0x00907000) {
        $self->fail_because_of_openssl_libs(<<"MESSAGE");
OpenSSL version 0.9.7 expected; I found only version $libversion.
MESSAGE
    }

    warn <<"MESSAGE";
Found $libversion.  Good.

MESSAGE

    $self->notes($cachekey, 1);
    return;
}

=head2 require ($modulename)

Like L<perlfunc/require>; demands that $modulename, a module bundled
with this CPAN distribution, be loaded in the current Perl process.

=cut

sub require {
    my ($self, $modulename) = @_;
    local @INC = (scalar(catdir($self->topdir, "lib")), @INC);
    eval "require $modulename; 1" or die $@;
}

=head2 fail_because_of_openssl_libs ($message)

Like L</fail>, but wriggles me out of getting CPAN testers blame mail.

Called by L</check_openssl_version_number> upon any mishap.  Explain
to the user what to do about it, namely set --openssl-cflags and/or
--openssl-ldflags on the Build.PL command line.  If run from the
C<./Build> script instead (see L</resume>), acts coy and say "OS not
supported", thereby tricking L<CPAN::Reporter> into B<not> reporting
this failure.

Okay, I'm not really proud about this quirk but it's the best I could
come up under the current CPAN.pm design; here's why.  When installing
using CPAN.pm's automatic dependency-chasing feature (eg C<perl -MCPAN
-e 'install "Crypt::OpenSSL::CA"'> including, but not limited to, the
case of some CPAN tester smoke-testing my module automatically), the
dance happens thusly:

=over

=item 1.

CPAN.pm runs my module's C<Build.PL> and collects the standard output
and error.  If a C<Build> file is not created when C<Build.PL>
terminates, the game is over no matter what (and at this stage we can
tell CPAN::Reporter to not send a report simply by exiting with code
0, see L<http://cpantest.grango.org/wiki/CPANAuthorNotes>).  Otherwise
CPAN.pm parses the standard output / error to find out the missing
modules to install (!!).

=item 2.

CPAN.pm does whatever it takes to satisfy the dependencies, then turns
around and runs the C<Build> file created at step 1.  Now we are
I<expected to succeed> in building the module and running the tests,
and the only way to bail out without CPAN::Reporter yelling at us is
to say "OS not supported" (op cit,
L<http://cpantest.grango.org/wiki/CPANAuthorNotes>).

=back

The trouble is best summarized by saying that the upcall API from
C<Build.PL> to CPAN.pm is too narrow.  I<Crypt::OpenSSL::CA> obviously
wants a working set of header files and development libraries for
OpenSSL; unfortunately we are unable to check for these until
L<Inline::C> is available, which typically occurs between steps 1. and
2. above, outside of our control.  (And no, kludges such as
backticking /usr/bin/openssl don't cut it, we really want to check for
a working development kit because that's what we'll need at build
time.)  In an ideal world we would tell CPAN.pm "please install
Inline::C right now" and then L</check_openssl_version_number>
immediately, all from within C<Build.PL>.  But we can't, and therefore
the OpenSSL libs availability and version check typically has to wait
until the C<Build> stage under hands-free installs; and in case the
OpenSSL installation is no good there's no getting out from that
pickle without upsetting CPAN-testers, save from lying with "OS not
supported".  The only alternative would be to not have a chained
dependency problem, eg distribute L<Inline::C> along with
L<Crypt::OpenSSL::CA> in the C<inc/> sub-directory, but that would be
both bloaty and fragile.

=cut

sub fail_because_of_openssl_libs {
    my ($self, $message) = @_;

    my $exitcode = 0;

    $message =~ s/\s*$//gs; $message .= "\n" if $message;
    $message .= <<"SUGGEST_COMMAND_LINE_SWITCHES";

Maybe you could try re-running Build.PL with appropriate values for
--openssl-cflags and --openssl-ldflags, for instance:

  perl Build.PL --openssl-cflags=-I/usr/local/lib/openssl/include \\
        --openssl-libs=-L/usr/local/lib/openssl/lib

Hint: don't sprinkle spaces where not necessary, as they are known to
confuse the GNU linker!

SUGGEST_COMMAND_LINE_SWITCHES

    if ($self->{running_from_build_script}) {
        $exitcode = 1;
        $message .= <<"CPAN_REPORTER_FODDER";
OS unsupported. Yes, this is a bald-faced lie, but I *really* don't
want CPAN::Reporter to report this failure to me.  (If you are running
this interactively, well I'm sorry but didn't I tell you to re-run
Build.PL after the Perl dependencies were fulfilled?)

CPAN_REPORTER_FODDER
    }

    warn($message);
    exit($exitcode);
}

=end internals

=cut

1;
