#!perl -w

use strict;
use warnings;

=head1 NAME

acceptance-make-x509-cert.t - Make an RSA X509 certificate using
L<Crypt::OpenSSL::CA>

=head1 DESCRIPTION

This test walks the reader through using L<Crypt::OpenSSL::CA> to
create X509 certificates using real-world cryptographic material:
namely, a CA certificate and private key (both PEM-encoded), and
either a PKCS#10 or a SPKAC request.  The private key is
password-protected.

=cut

use Test::More no_plan => 1;
use Crypt::OpenSSL::CA;

=head1 TEST DATA

=head2 CA private key and certificate

Provided by L<Crypt::OpenSSL::CA::Test> as standards-compliant PEM
strings.

=cut

use Crypt::OpenSSL::CA::Test
    qw(%test_rootca_certs %test_keys_password %test_public_keys);

our $ca_certificate = $test_rootca_certs   {rsa1024};
our $ca_privatekey  = $test_keys_password  {rsa1024};

like($ca_certificate, qr/BEGIN CERTIFICATE/,
     "\$ca_certificate looks standards-compliant");
like($ca_privatekey, qr/BEGIN RSA PRIVATE KEY/,
     "\$ca_privatekey looks standards-compliant");
like($ca_privatekey, qr/DEK-Info/,
     "\$ca_privatekey is encrypted");

=head2 Subject DN

The subject DN can be provided literally; simply be careful to the DN
order.  L<Crypt::OpenSSL::CA> enjoys full UTF-8 support.

=cut

use Crypt::OpenSSL::CA::Test qw(test_simple_utf8 test_bmp_utf8);

my $subject_dn = Crypt::OpenSSL::CA::X509_NAME->new_utf8
    (C => "fr", O => test_simple_utf8(),
     OU => test_bmp_utf8(), CN => "test subject");

=head2 Public Key

The subject public key is taken from a PKCS#10 request with a DN that
is B<not> the same as the L</Subject DN>, so as to demonstrate the
ability to alter the subject (like C</usr/bin/openssl>'s C<-subj>
command line switch in C<openssl ca>).  Also demonstrated is using a
SPKAC request, and an unadorned public key in PEM format.

=cut

my $pkcs10 = <<"PKCS10";
-----BEGIN CERTIFICATE REQUEST-----
MIH/MIGqAgEAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEw
HwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEAv9G34nsSLGFBBspdDmw6VXaIUhBFxfGEXyn6Iu+t5Jal9aJ6ASmN
8oNbqbhXGHPNG3zIWE1JXjM/J0dyL367LQIDAQABoAAwDQYJKoZIhvcNAQEFBQAD
QQBl40/oJEOO3dVuzA5/uhGAeuB5e+OJukFK+gaQ7AKan8LNzM+YZnsIXs6YRVsp
FKOaPNDw7MCMT7H6x7B/SoHa
-----END CERTIFICATE REQUEST-----
PKCS10

use Crypt::OpenSSL::CA::Test qw(run_thru_openssl);
my ($out, $err) = run_thru_openssl($pkcs10, qw(req -text -noout));
like($out, qr/certificate request/i, "test PKCS#10 parses OK");

my $spkac = "MIG0MGAwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAxhE/10bDNF3bod/LuZ73Arv/6nVAGCqCBP6IYGNoLsglKhpFi4udaQzcRIvBW9EcXc3Pfp9LyEWuOZ7NZSTLMwIDAQABFgAwDQYJKoZIhvcNAQEEBQADQQCHDsf5bO4akV1YuEShoBiXZKkzGpnKcCZj4eaq2Alw+pjI3PtWog6Wpfpm/jZV3xePe5WXzIzi5V5fVgQ/ZhRA";

use Crypt::OpenSSL::CA::Test qw(%test_public_keys);
my $plain_pubkey = $test_public_keys{rsa1024};
like($plain_pubkey, qr/BEGIN PUBLIC KEY/, "plain public key is in PEM");

=head2 Certificate Fields and Extensions

We use a rather Christmas-tree set of extensions to demonstrate the
possibilities of the API.

The X509 version is always X509v3.  The validity period (notBefore and
notAfter) can be of arbitrary size, and transition from utcTime to
generalizedTime is handled properly.  The signature algorithm is RSA
and the hash can be set to SHA1 or SHA256.  OpenSSL's algorithm for
RSA key fingerprints (also known as X509 KeyIDs) is used for the
subject and issuer unique identifiers.

=cut

sub sign_certificate {
    my ($pubkey) = @_;

    my $cert = Crypt::OpenSSL::CA::X509->new($pubkey);

    my $ca_privkey_obj = Crypt::OpenSSL::CA::PrivateKey
        ->parse($ca_privatekey, -password => "secret");
    my $ca_cert_obj = Crypt::OpenSSL::CA::X509
        ->parse($ca_certificate);

    $cert->set_serial("0x1234567890abcdef1234567890ABCDEF");
    $cert->set_subject_DN($subject_dn);
    $cert->set_issuer_DN($ca_cert_obj->get_subject_DN);

    $cert->set_notBefore("20060108000000Z");
    $cert->set_notAfter("21060108000000Z");
    $cert->set_extension("basicConstraints", "CA:FALSE",
                         -critical => 1);

    my $keyid = $ca_cert_obj->get_subject_keyid;
    die $ca_cert_obj->dump if ! defined $keyid;  # XXX
    $cert->set_extension("authorityKeyIdentifier_keyid", $keyid,
                         -critical => 0); # As per RFC3280 section 4.2.1.1
    $cert->set_extension( subjectKeyIdentifier => "00:DE:AD:BE:EF");

    $cert->set_extension(certificatePolicies =>
                          'ia5org,1.2.3.4,1.5.6.7.8,@polsect',
                         -critical => 0,
                         polsect => {
                            policyIdentifier => '1.3.5.8',
                            "CPS.1"        => 'http://my.host.name/',
                            "CPS.2"        => 'http://my.your.name/',
                            "userNotice.1" => '@notice',
                         },
                         notice => {
                            explicitText  => "Explicit Text Here",
                            organization  => "Organisation Name",
                            noticeNumbers => '1,2,3,4',
                         });


    $cert->set_extension
       (subjectAltName =>
        'email:johndoe@example.com,email:johndoe@example.net');

    return $cert->sign($ca_privkey_obj, "sha256");
}


=head1 CREATING THE CERTIFICATES

We run the CA three times, once for every supported format of public key
(PKCS#10, SPKAC and plain-PEM).

=cut

my $certificate = sign_certificate(Crypt::OpenSSL::CA::PublicKey
                                   ->validate_PKCS10($pkcs10));
ok_certificate($certificate);

$certificate = sign_certificate(Crypt::OpenSSL::CA::PublicKey
                                   ->validate_SPKAC($spkac));
ok_certificate($certificate);

$certificate = sign_certificate(Crypt::OpenSSL::CA::PublicKey
                                   ->parse_RSA($plain_pubkey));
ok_certificate($certificate);

exit(0);

=head1 CHECKING THE RESULTS

The C</usr/bin/openssl> command is used to verify the details of the
certificate.  We also check that the certification chain validates OK.
Both are done using L<Crypt::OpenSSL::CA/run_thru_openssl>.

=cut

use Crypt::OpenSSL::CA::Test qw(run_dumpasn1 certificate_chain_ok);
sub ok_certificate {
    my ($certpem) = @_;

    my ($certdump, $err) =
        run_thru_openssl($certpem, qw(x509 -noout -text));
    is($?, 0, "``openssl x509'' ran successfully")
        or die $err;

    like($certdump, qr/12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF/i,
         "big hex serial");
    like($certdump, qr/Issuer:.*Widgits/, "issuer DN");
    like($certdump, qr/Subject:.*test subject/, "subject DN");
    like($certdump, qr/basic.*constraints.*critical.*\n.*CA:FALSE/i,
         "Critical basicConstraints");
    like($certdump, qr/example.com/, "subjectAltName 1/2");
    like($certdump, qr/example.net/, "subjectAltName 2/2");
    like($certdump, qr/Subject Key Identifier.*\n.*DE.AD.BE.EF/i,
         "subject key ID");
    like($certdump, qr/Authority Key Identifier/i,
         "authority key ID");
    unlike($certdump,
           qr/Authority Key Identifier.*critical.*\n.*DE.AD.BE.EF/i,
           "authority key ID *must not* be the same as subject key ID");
    like($certdump, qr|Policy: 1.5.6.7.8|i, "policy identifiers 1/4");
    like($certdump, qr|CPS: http://my.host.name/|i,
         "policy identifiers 2/4");
    like($certdump, qr|Numbers: 1, 2, 3, 4|i,
         "policy identifiers 3/4");
    like($certdump, qr|Explicit Text: Explicit Text Here|i,
         "policy identifiers 4/4");

    my $dumpasn1 = run_dumpasn1
        (scalar run_thru_openssl($certpem, qw(x509 -outform der)));
    like($dumpasn1, qr/UTCTime.*2006.*\n.*GeneralizedTime.*2106/,
         "Proper detection of time format");

    certificate_chain_ok($certpem, [$ca_certificate]);
}

