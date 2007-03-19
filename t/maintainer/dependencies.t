#!perl -w
use strict;
use warnings;

=head1 NAME

dependencies.t - Checks that B<Build.PL> lists all required CPAN modules.

=head1 DESCRIPTION

The implementation is plenty quirky, but OTOH this test is only
intended for running on the maintainer's system.

=cut

BEGIN {
    my $prerequisites = join("", map {"use $_;\n"}
                             (qw(Test::More File::Spec File::Slurp
                                 File::Find Module::ScanDeps)));

    unless (eval "$prerequisites\n1;") {
        plan(skip_all => "Some modules are missing "
             . "in order to run this test");
        warn $@ if $ENV{DEBUG};
        exit;
    }
}

plan tests => 3;

=pod

=head1 TWEAKABLES

=head2 @pervasives

The list of modules that can be assumed to always be present
regardless of the version of Perl, and need not be checked for.

=cut

our @pervasives = qw(base warnings strict overload utf8 vars
                     Data::Dumper File::Glob File::Spec::Unix);

=head2 @ignore

Put any modules that cause false positives in there.  Consider adding
them to Build.PL instead.  By default, only the modules that are
required by maintainer tests are listed here.

=cut

our @ignore = qw(Pod::Text Test::Pod Test::Pod::Coverage
                 Test::NoBreakpoints);

=head1 IMPLEMENTATION

We load the C<Build> script so as to be able to enumerate the
dependencies and call I<<find_pm_files()> and I<<find_test_files()>>
on it.

=cut

my $buildcode = read_file("Build");
die "Cannot read Build: $!" if ! defined $buildcode;
$buildcode =~ s|\$build->dispatch|\$build|g;
our $build = eval $buildcode; die $@ if $@;
ok($build->isa("Module::Build"));

=pod

The run-time dependencies are examined in the C<blib> directory, as
the Build script will often muck around with .pm files e.g. to remove
the test suites.

=cut

{
    my @blib_files; find({no_chdir => 1, wanted => sub {
        return unless m|\.pm$|; # Also excludes /.svn/ files
        push @blib_files, $_;
    }}, "blib");

    my @got_depends_main = list_deps(@blib_files);
    my @expected_depends_main = keys %{$build->requires};

    compare_dependencies_ok(\@got_depends_main, \@expected_depends_main);
}

=pod

On the other hand, we look for test dependencies everywhere, including
in the footer of .pm files after the __END__ block (see details in
inc/My/Tests/Below.pm)

=cut

{
    our $scan_after_END = 1;

    my @got_depends_tests = list_deps(keys %{$build->find_pm_files},
                                      @{$build->find_test_files});
    my @expected_depends_tests = (keys(%{$build->requires}),
                                  keys(%{$build->build_requires}));

    compare_dependencies_ok(\@got_depends_tests, \@expected_depends_tests);
}

exit; ##############################################################

=head1 TEST LIBRARY

=head2 file2mod($filename)

Turns $filename into a module name (e.g. C<Foo/Bar.pm> becomes
C<Foo::Bar>) and returns it.

=cut

sub file2mod {
    local $_ = shift;
    s|/|::|g; s|\.pm$||;
    return $_;
}

=head2 write_to_temp_file($string)

Writes $string into a newly created temporary file, and return its
path.

=cut

sub write_to_temp_file {
    use File::Temp;
    my ($fh, $filename) = File::Temp::tempfile( UNLINK => 1 );
    unless ($fh->print(shift) &&
            $fh->close()) {
        die "cannot write to $filename: $!\n";
    }
    return $filename;
}

=head2 list_deps(@files)

List dependencies found in @files, and returns them as a list of
module names.  Only C<.pm> files are listed.

=cut

sub list_deps {
    my @files = @_;
    my %files = map { ($_ => 1) } @files;
    my %pervasives = map { ($_ => 1) } @pervasives;
    my $list = scan_deps(files => \@files, recurse => 0);
    return map { $_ = file2mod($_); $pervasives{$_} ? () : ($_) }
        (grep { (! m/^(auto|unicore)/) &&
                (m/\.pm$/) &&
                    # recurse => 0 doesn't seem to do jack:
                (! $list->{$_}->{used_by}) &&
                (! is_our_own_file($list->{$_}->{file}))
            } (keys %$list));
}

=head2 is_our_own_file($path)

Returns true iff $path is one of the files in this package, and
therefore should not be counted as a dependency.

=cut

sub is_our_own_file {
    my ($filename) = @_;
    index($filename, $build->base_dir) == 0;
}

=head2 Module::ScanDeps::scan_line

This function is modified in-place so as to also scan after the
__END__ block if so directed by the $scan_after_END global variable.

=cut

BEGIN {
    no warnings "redefine";
    my $scan_line_orig = \&Module::ScanDeps::scan_line;
    *Module::ScanDeps::scan_line = sub {
        map { s|^__END__$|__CONTINUE__| if our $scan_after_END; $_ }
            ($scan_line_orig->(@_))
        };
}

=head2 Module::ScanDeps::scan_chunk

This function is modified in-place so as to record into global
variable $chunks the chunks of Perl that cause a dependency to be
recorded.  This allows one to track false positives using C<grep>.
Granted, a filename and line number would be better, but
L<Module::ScanDeps> doesn't provide this.

=cut

BEGIN {
    no warnings "redefine";
    my $scan_chunk_orig = \&Module::ScanDeps::scan_chunk;
    *Module::ScanDeps::scan_chunk = sub {
        my $chunk = shift;
        my @retval = $scan_chunk_orig->($chunk);
        our $chunks;
        $chunks->{file2mod($_)}->{$chunk}++ foreach (@retval);
        return @retval;
    };
}

=head2 compare_dependencies_ok($gotlistref, $expectedlistref)

As the name implies.  For each entry in $gotlistref which is not in
$expectedlistref, shows the chunk that caused the dependency to be
added as a piece of text.

=cut

sub compare_dependencies_ok {
    my ($gotlistref, $expectedlistref) = @_;

    my %bogus_ok = map { ($_ => 1) }
        (@pervasives, @ignore, $build->requires_for_tests());
    my @got = grep { !$bogus_ok{$_} } @$gotlistref;
    my @expected = grep { !$bogus_ok{$_} } @$expectedlistref;
    @expected = sort @expected; @got = sort @got;
    return if is(join(" ", @got), join(" ", @expected));

    my %found = map { ($_ => 1) } @expected;
    our $chunks;
    foreach my $notfound (grep {! $found{$_}} @got) {
        next if ! defined(my $chunklist = $chunks->{$notfound});
        diag "$notfound may be referenced in:\n" .
            join("", map { <<"EXCERPT" } (keys %$chunklist));
=========
$_
=========
EXCERPT
    }
}
