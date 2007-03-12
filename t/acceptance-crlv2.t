#!perl -w

use strict;
use warnings;

=head1 NAME

acceptance-crlv2.t - Make an RFC3280-compliant CRLv2

=head1 DESCRIPTION

This test walks the reader through using L<Crypt::OpenSSL::CA> to
issue a standards-compliant CRLv2.

=cut

use Test::More no_plan => 1;
use Crypt::OpenSSL::CA;

=head1 TEST DATA

=head2 CA private key and certificate

Provided by L<Crypt::OpenSSL::CA::Test>.  See
C<acceptance-make-x509-cert.t> for details.

=cut

use Crypt::OpenSSL::CA::Test
    qw(%test_rootca_certs %test_keys_password %test_public_keys);

our $ca_certificate = Crypt::OpenSSL::CA::X509->parse
    ($test_rootca_certs{rsa1024});
our $ca_privatekey  = Crypt::OpenSSL::CA::PrivateKey->parse
    ($test_keys_password{rsa1024}, -password => "secret");

=head2 Issuer coordinates

The issuer DN and key identifiers are taken directly from the CA
certificate.

=cut

our $issuer_dn = $ca_certificate->get_subject_DN;
ok($issuer_dn->isa("Crypt::OpenSSL::CA::X509_NAME"));
our $keyid     = $ca_certificate->get_subject_keyid;
like($keyid, qr/^[0-9a-f]{2}(:[0-9a-f]{2})*$/i);

=head2 Global CRL settings

CRL dates are supported using the dual ASN.1 date format in
conformance with RFC3280 sections 5.1.2.4 and 5.1.2.5.

RFC3280 section 5.1.2.1 now makes v2 for CRLs mandatory; not
coincidentally, this is the default in L<Crypt::OpenSSL::CA>.  The
C<authorityKeyIdentifier> and C<crlNumber> extensions are also
mandatory.  C<authorityKeyIdentifier> MUST NOT be critical as per
section 4.2.1.1, while C<crlNumber> MUST be as per 5.1.2.1.

=cut

my $crl = new Crypt::OpenSSL::CA::X509_CRL;
$crl->set_issuer_DN($issuer_dn);
$crl->set_lastUpdate("20070101000000Z");
$crl->set_nextUpdate("20570101000000Z");

$crl->set_extension("authorityKeyIdentifier", { keyid => $keyid });
our $crlnumber = "deadbeef";
$crl->set_extension("crlNumber", "0x$crlnumber", -critical => 1);

=pod

Just for fun, we add a C<freshestCRL> extension as per RFC3280 section
5.2.6; the corresponding delta CRL is issued by C<acceptance-delta-crl.t>

=cut

$crl->set_extension("freshestCRL",
                    "URI:http://www.example.com/deltacrl.crl",
                    -critical => 0);

=head2 Revoked Certificates List

In order of appearance: a CRLv1-like unadorned entry, an entry with
C<unspecified> revocation reason, an entry for a certificate that was
put on hold (that is removed by the delta-CRL, see
C<acceptance-delta-crl.t>), and an entry for a certificate whose key
was compromised (with a compromiseTime set).  Notice that the CRL
entries are in no particular order.

=cut

$crl->add_entry("0x10", "20070212100000Z");
$crl->add_entry("0x11", "20070212100100Z", -reason => "unspecified");
$crl->add_entry("0x42", "20070212090100Z",
                -hold_instruction => "holdInstructionPickupToken");
$crl->add_entry("0x12", "20070212100200Z", -reason => "keyCompromise",
                -compromise_time => "20070210000000Z");

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
# For some reason, OpenSSL displays the CRL number in decimal.
my $crlnumber_decimal = hex($crlnumber);
like($crldump, qr/$crlnumber_decimal/);
like($crldump, qr/CRL Number.*critical/i);
# Right now OpenSSL cannot parse freshest CRL indicator:
like($crldump, qr/deltacrl\.crl/);

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
like($crlentries{"10"}, qr/Feb 12/, "revocation dates");
like($crlentries{"11"}, qr/unspecified/i);
like($crlentries{"12"}, qr/key.*compromise/i);
like($crlentries{"12"}, qr/Invalidity Date/i);
like($crlentries{"42"}, qr/hold/i);


