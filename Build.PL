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
        "Convert::ASN1" => 0.20, # 0.20 brings needed utf8 bugfixes
      },
      build_requires      =>
      {
       "Sub::Uplevel"     => 0.09, # In Crypt::OpenSSL::CA::Inline::C
       "Inline"           => 0.40,
       # Packages below are needed for the test suite. (And yes,
       # running the test suite *is* a requirement of the build
       # process)
        My::Module::Build->requires_for_tests(),
        "IPC::Run"         => 0,
        "File::Spec::Functions" => 0,
        "Devel::Leak" => 0,
        "Memchmark"   => 0,
        "Net::SSLeay"   => 1.25, # For access to ERR_ in tests
      },
    add_to_cleanup      => [ 'Crypt-OpenSSL-CA-*', "_Inline" ],
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

FIXME: auto-detect libcrypto version (0.9.5 required, see
L<Crypt::OpenSSL::CA::Inline::C>), find out include and library path,
etc.

=cut

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

    my $orig = $ENV{FULL_DEBUGGING};
    local $ENV{FULL_DEBUGGING};
    $ENV{FULL_DEBUGGING} = $orig if defined $orig;

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
    local $ENV{PERL_INLINE_BUILD_NOISY} = 1;
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

    push @INC, catdir($self->topdir, "lib");
    require Crypt::OpenSSL::CA::Inline::C;

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

=cut

1;
