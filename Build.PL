# Build.PL, (C) Dominique Quatravaux 2007 (See README for license details)

# This script automatically builds a "Build" file in the current
# directory (using a custom-made subclass to Module::Build), which in
# turn builds the Crypt-OpenSSL-CA package.

use strict;
use warnings;
use FindBin; use lib "$FindBin::Bin/inc";
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
        "Devel::Leak"           => 0,
        "Proc::ProcessTable"    => 0,
        "Net::SSLeay"           => 1.25, # For access to ERR_ in tests
        "MIME::Base64"          => 0,
        "POSIX"                 => 0,
      },
    add_to_cleanup      => [ 'Crypt-OpenSSL-CA-*', "_Inline" ],
    add_to_no_index     =>
      { namespace => [ "Crypt::OpenSSL::CA::Inline" ] },
    create_makefile_pl  => 'passthrough',
);

$builder->create_build_script();

1;

__END__

use File::Spec::Functions qw(catdir catfile);
use IO::File;
use FindBin qw($Bin);
use My::Module::Build;

=head1 CUSTOM BUILD OPTIONS

=item I<< --openssl-includedir=<path> >>

Provides the path where the OpenSSL header files are to be found.
Default is to query C<pkg-config>, or failing that, to use the
compiler-provided system defaults.

=cut

sub openssl_includedir : Config_Option(type="string") {
    (default => (`pkg-config --cflags-only-I openssl 2>/dev/null`));
}

=item I<< --openssl-libdir=<path> >>

Provides the path where the OpenSSL libraries are to be found.
Default is to query C<pkg-config>, or failing that, to use the
compiler-provided system defaults.

=cut

sub openssl_libdir : Config_Option(type="string") {
    (default => (`pkg-config --libs-only-L openssl 2>/dev/null`));
}

=head1 CUSTOM COMMAND-LINE SWITCHES

=over

=item I<full_debugging=1>

Enables L<Crypt::OpenSSL::CA::Inline::C/full_debugging> while running
C<./Build test>.  This is only intended for situations where setting
an environment variable is inconvenient (e.g. the Perl debugger).
Implies C<use_blib=0> (see L<My::Module::Build>).

=cut

sub ACTION_test {
    my $self = shift;

    local $self->{args} = {%{$self->{args}}};
    local %ENV = $self->_customize_env(%ENV);
    # And then customize some more:
    delete $ENV{FULL_DEBUGGING};

    if ($self->{args}->{full_debugging}) {
        $ENV{FULL_DEBUGGING} = 1;
        $self->use_blib(0);
    }

    $self->depends_on("buildXS") if $self->use_blib;

    return $self->SUPER::ACTION_test;
}

=back

=head1 CUSTOM BUILD METHODS

=over

=item I<ACTION_build()>

Overloaded so as to also call L</ACTION_buildXS>.

=item I<ACTION_buildXS()>

Builds the XS modules for distribution into L<blib/arch>.

=cut

sub ACTION_build {
    my $self = shift;
    $self->depends_on("buildXS");
    $self->SUPER::ACTION_build(@_);
}

sub ACTION_buildXS {
    my ($self) = @_;

    do { unlink($_) or die "Cannot unlink($_): $!" } for glob("*.inl");

    my @sofiles = glob(catfile(qw(blib arch auto Crypt OpenSSL CA * *.so)));
    my @sources = (catfile(qw(lib Crypt OpenSSL CA.pm)),
                   catfile(qw(lib Crypt OpenSSL CA Inline C.pm)));

    return if (@sofiles && $self->up_to_date (\@sources, \@sofiles));

    unlink @sofiles;

    # And now some ugly kludge to make everything hold together.
    # Inline::C wants to use MakeMaker; we don't.  So let's call it in
    # a sub-Perl.
    my $version = $self->dist_version;
    my $script = <<"SCRIPT";
BEGIN { \$Crypt::OpenSSL::CA::VERSION = '$version' ; }
use Crypt::OpenSSL::CA::Inline::C;
use Inline qw(_INSTALL_);
use Crypt::OpenSSL::CA;
SCRIPT

    chomp($script); $script =~ s/\n/ /g;
    my @cmdline = ($^X, "-I" => catdir($self->topdir, "lib"),
                   -e => $script, $version, catdir(qw(blib arch)));
    warn(join(" ", @cmdline, "\n"));
    local %ENV = $self->_customize_env(%ENV);
    $ENV{PERL_INLINE_BUILD_NOISY} = 1;
    system(@cmdline);
    die "Command exited with status " . ($? >> 8) if $?;
    do { unlink or die "Cannot unlink($_): $!" } for glob("*.inl");
}

=item I<process_pm_files>

Overloaded from parent class so as to reserve a special treatment to
L<Crypt::OpenSSL::CA::Inline::C> (see its POD).

=cut

sub process_pm_files {
    my $self = shift;
    $self->SUPER::process_pm_files(@_);

    local $_ = catdir($self->topdir, qw(lib Crypt OpenSSL CA Inline C.pm));
    require;

    my $out = catfile(qw(blib lib Crypt OpenSSL CA Inline C.pm));
    unlink($out);
    my $outfd = new IO::File($out, ">") or
        die "Cannot open $out for writing: $!";
    ($outfd->print(Crypt::OpenSSL::CA::Inline::C->installed_version) &&
     $outfd->close()) or
         die "Cannot write to $out: $!\n";
}

=item I<topir>

Returns the directory in which C<Build.PL> resides.

=cut

sub topdir {
    # FIXME: probably not good enough in some cases.
    require FindBin;
    return $FindBin::Bin;
}

=back

=begin internals

=head1 INTERNAL METHODS

=head2 _customize_env(%env)

Takes %env as an environment hash and returns a modified copy of it
where the L<Crypt::OpenSSL::CA/ENVIRONMENT VARIABLES> are set.  To be
used typically as

   local %ENV = $self->_customize_env(%ENV);

right before doing anything that might result in the inline C code
being recompiled.

=cut

sub _customize_env {
    my ($self, %env) = @_;
    foreach my $item (qw(openssl_libdir openssl_includedir)) {
        my $varname = "BUILD_" . uc($item);
        delete $env{$varname};
        $env{$varname} = $self->option_value("$item")
            if $self->option_value("$item");
    }
    return %env;
}

=end internals

=cut

1;
