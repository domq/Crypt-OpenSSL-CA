#!perl -w

use strict;
use warnings;

=head1 NAME

acceptance-delta-crl.t - Make a delta CRL as per RFC3280 section 5.2.4

=head1 DESCRIPTION

This test walks the reader through using L<Crypt::OpenSSL::CA> to
issue a delta CRL.  The resulting delta CRL will be compatible with
the CRL created by acceptance-crlv2.t in the same directory.

=cut

use Test::More no_plan => 1;
use Crypt::OpenSSL::CA;

=head1 TEST DATA

=head2 CA private key and certificate

Provided by L<Crypt::OpenSSL::CA::Test>.  See
acceptance-make-x509-cert.t for details.

=cut

use Crypt::OpenSSL::CA::Test
    qw(%test_rootca_certs %test_keys_password %test_public_keys);

our $ca_certificate = Crypt::OpenSSL::CA::X509->parse
    ($test_rootca_certs{rsa1024});
our $ca_privatekey  = Crypt::OpenSSL::CA::PrivateKey->parse
    ($test_keys_password{rsa1024}, -password => "secret");

=head2 Issuer coordinates

=head2  Global CRL settings

See details in C<acceptance-crlv2.t>

=cut

our $issuer_dn = $ca_certificate->get_subject_DN;
ok($issuer_dn->isa("Crypt::OpenSSL::CA::X509_NAME"));
our $keyid     = $ca_certificate->get_subject_keyid;
like($keyid, qr/^[0-9a-f]{2}(:[0-9a-f]{2})*$/i);

my $crl = new Crypt::OpenSSL::CA::X509_CRL;
$crl->set_issuer_DN($issuer_dn);
$crl->set_lastUpdate("20070212150000Z");
$crl->set_nextUpdate("20570101000000Z");
$crl->set_extension("authorityKeyIdentifier_keyid", $keyid);
our $crlnumber = "deadbeef";
$crl->set_extension("crlNumber", "0x$crlnumber", -critical => 1);

=pod

Additionally, this CRL is marked as a delta CRL whose base CRL is the
one issued by C<acceptance-crlv2.t> . The corresponding extension is
critical, as per RFC3280 section 5.2.4.

=cut

$crl->set_extension("deltaCRLIndicator", "0x$crlnumber", -critical => 1);

=head2 Revoked Certificates List

We add a revoked certificate to the CRL, and remove the hold
instruction from certificate 0x42.

=cut

$crl->add_entry("0x42", "20070212150900Z", -reason => "removeFromCRL");
$crl->add_entry("0xdeadbeefdeaff00f", "20070212151000Z");

=head2 All done

Now we just have to sign the CRL.

=cut

our $crlpem = $crl->sign($ca_privatekey, "sha1");

=head1 CHECKING THE RESULT

In order for this test to succeed, the various decorations we set up
for the CRL must show up in C<openssl crl> or C<dumpasn1>.

=cut

use Crypt::OpenSSL::CA::Test qw(run_thru_openssl);
our ($crldump, $err) =
        run_thru_openssl($crlpem, qw(crl -noout -text));
is($?, 0, "``openssl crl'' ran successfully")
    or die $err;

like($crldump, qr/last update:.*2007/i);
like($crldump, qr/next update:.*2057/i);
# For some reason, OpenSSL displays the delta CRL indicator in decimal.
my $crlnumber_decimal = hex($crlnumber);
like($crldump, qr/delta CRL.*critical.*\n.*$crlnumber_decimal/i);

my @crlentries = split m/Serial Number: /, $crldump;
shift(@crlentries); # Leading garbage
my %crlentries;
for(@crlentries) {
    if (! m/^([0-9A-F]+)(.*)$/si) {
        fail("Incorrect CRL entry\n$_\n");
        next;
    }
    $crlentries{uc($1)} = $2;
}
# As of version 0.9.8c, OpenSSL doesn't know about
# reason "remove" (which is 8 in RFC3280 section 5.3.1)
like($crlentries{"42"}, qr/remove|8/i);
like($crlentries{"DEADBEEFDEAFF00F"}, qr/2007/i);



