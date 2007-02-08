#!perl -w

use strict;
use warnings;

package Crypt::OpenSSL::CA;

our $VERSION = 0.03;

=head1 NAME

Crypt::OpenSSL::CA - Model of an X509v3 Certification Authority

=head1 SYNOPSIS

=for My::Tests::Below "synopsis" begin

    use Crypt::OpenSSL::CA;

    my $dn = Crypt::OpenSSL::CA::X509_NAME->new
            (C => "fr", CN => "test");

    my $privkey = Crypt::OpenSSL::CA::PrivateKey
         ->parse($pem_private_key, -password => "secret");

=for My::Tests::Below "synopsis" end

=head1 DESCRIPTION

This package performs the cryptographic operations necessary to issue
X509 certificates and certificate revocation lists (CRLs).  It is
implemented as a Perl wrapper around the popular OpenSSL library.

Despite the name and unlike the C<openssl ca> command-line tool,
I<Crypt::OpenSSL::CA> is not designed as a full-fledged X509v3
Certification Authority (CA): some key features are missing, most
notably persistence (e.g. to remember issued and revoked certificates
from one call off L</sign_crl> to the next) and security-policy based
screening of certificate requests.  This is deliberate: OpenSSL's
features such as configuration file parsing, that are best implemented
in Perl, have been left out of I<Crypt::OpenSSL::CA> for maximum
flexibility.

To recap, I<Crypt::OpenSSL::CA> only does the crypto part of the work
of an X509v3 CA, and it does so using mostly OpenSSL and XS glue code.

=head2 Theory of operation

An X509v3 Certification Authority, a crucial part of an X509 Public
Key Infrastructure (PKI), is defined by RFC4210 and friends (see
L<Crypt::OpenSSL::CA::Resources>) as a piece of software that can
(among other things) issue and revoke X509v3 certificates.  To perform
the necessary cryptographic operations, it needs a private key
(currently only RSA is supported).

=head2 Error Management

All functions and methods in this module, including XS code, throws
exceptions as if by L<perlfunc/die> if anything goes wrong.  The
resulting exception is either a plain string (in case of memory
exhaustion problems, incorrect arguments, and so on) or an exception
blessed in class I<Crypt::OpenSSL::CA::Error> with the following
structure:


  {
    -message => $message,
    -openssl => [
                  $openssl_error_1,
                  $openssl_error_2,
                  ...
                ]
  }

where C<$message> is a message by I<Crypt::OpenSSL::CA> and the
C<-openssl> list is the contents of OpenSSL's error stack when the
exception was raised.

=begin internals

See also L</_sslcroak_callback>.

=end internals

=head1 CONSTRUCTOR AND METHODS

=over

=item I<new(-arg1 => $val1, ...)>

Object constructor. Available named arguments are:

=over

=item I<< -certificate => $pem_string >>

The X509 certificate (as a PEM string) that represents this CA in the
PKIX certification graph.  The public key inside $x509obj must match
the I<-key> parameter.  (For the record, I<Crypt::OpenSSL::CA> uses
the certificate only to get at the values of issuer-related fields in
the X509v3 structure of the certificates it creates, e.g. the issuer
DN and key ID)

=item I<< -key => $rsaobj >>

The private key to operate this CA, as a PEM string. Only RSA is
supported for now.

=item I<< -key_password => $pass >> (optional)

The password to decrypt the I<< -key >> argument with.  If none is
specified, the key is assumed to be in plain text.

Engine-backed private keys are not supported right now, see L</TODO>.

=back

=cut

sub new { die "UNIMPLEMENTED"; }

=item I<sign_certificate(-arg1 => $val1, ...)>

Certifies (creates) a new L<Crypt::X509> certificate and returns it
as a PEM string.  Available named arguments are:

=over

=item I<< -serial => $int >>

=item I<< -serial => "0x1234" >>

=item I<< -serial => $Math_BigInt >>

The serial number to use, either as a Perl integer, a hex string
starting with C<qr/^.x/>, or as a L<Math::BigInt> object.

=back

More X509 certificate extensions will be supported in the
future.  Patches welcome.

=item I<sign_crl(\@list_of_revocations, %named_options)>

Issues a new Certificate Revocation List and returns it as a PEM
string.  B<DESIGNME>: contents of \@list_of_revocations.

Available named options are:

=over

=item I<< -validity => $validity_period_in_seconds >>

The validity period to use for this CRL. Default is 7 days.

=back

=cut

=item I<set_current_time($time)>

=item I<set_current_time(undef)>

Sets this I<Crypt::OpenSSL::CA>'s idea of what time it is to $time, an
integer number of seconds in UNIX epoch format. If undef (the
default), the current system time is used.  By default, certificates
and CRLs will be marked as valid starting from this point of time.

=cut

sub set_current_time { die "UNIMPLEMENTED" }

=back

=begin internals

=head2 C glue code

The crypto in I<Crypt::OpenSSL::CA> is implemented using the OpenSSL
cryptographic library, which is lifted to Perl XS subs thanks to a
bunch of glue code in C and a lot of magic in
L<Crypt::OpenSSL::CA::Inline::C>.  Most of said glue code is
accessible as class and instance methods in the ancillary classes
described in L</ANCILLARY CLASSES THAT MAP OPENSSL CONCEPTS>.

=head2 Internal methods

=over

=item I<_sslcroak_callback(-message => $val)>

=item I<_sslcroak_callback(-openssl => $val)>

=item I<_sslcroak_callback("DONE")>

Callback that gets invoked one or several times whenever
L<Crypt::OpenSSL::CA::Inline::C/sslcroak> is run, in order to
implement L</Error Management>.  I<_sslcroak_callback> is expected to
accumulate the exception data in $@, but to not bless it until
C<<_sslcroak_callback("DONE")>> is called; in this way, I<_sslcroak>
will be able to tell that the sequence of callback invocations
terminated successfully.

A word of caution to hackers who wish to reimplement
I<_sslcroak_callback>, e.g. for testability purposes: if I<_sslcroak>
calls C<eval>, it will wipe out $@ which kind of defeats its purpose
(unless one is smart and sets $@ only at C<DONE> time); and if
I<_sslcroak_callback> throws an exception, the text thereof will end
up intermingled with the one from OpenSSL!

=cut

sub _sslcroak_callback {
    my ($key, $val) = @_;
    if ($key eq "-message") {
        $@ = { -message => $val };
    } elsif ( ($key eq "-openssl") && (ref($@) eq "HASH") ) {
        $@->{-openssl} ||= [];
        push(@{$@->{-openssl}}, $val);
    } elsif ( ($key eq "DONE") && (ref($@) eq "HASH") ) {
        bless($@, "Crypt::OpenSSL::CA::Error");
    } else {
        warn sprintf
            ("Bizarre callback state%s",
             (Data::Dumper->can("Dumper") ?
              " " . Data::Dumper::Dumper($@) : ""));
    }
}


=item I<_get_current_time()>

Returns the (assumed or real) current system time, in UNIX epoch
format.  See L</set_current_time> for how to lie to oneself about what
time it is.

=cut

sub _get_current_time { die "UNIMPLEMENTED"; }

=back

=end internals

=head1 ANCILLARY CLASSES THAT MAP OPENSSL CONCEPTS

Most of the functionality in I<Crypt::OpenSSL::CA> is provided by
ancillary classes, implemented in XS, that each wrap around OpenSSL's
"object class" with the same name
(e.g. L</Crypt::OpenSSL::CA::X509_NAME> corresponds to the
C<X509_NAME_foo> functions in libcrypto.so).  OpenSSL concepts are
therefore made available in an elegant object-oriented API; moreover,
they are subjugated to Perl's automatic garbage collection, which
allows the programmer to stop worrying about that.  The downside is
that this API looks like C, meaning that it is inhomogenous and quirky
at places.

Note that those ancillary OpenSSL-wrapping classes don't strive for
completeness of the exposed API in the least; rather, they export just
enough features to make them simultaneously testable and useful to the
main I<Crypt::OpenSSL::CA> class.  (However, please email the author
if you think that these classes lack functionnality.)

=head2 Crypt::OpenSSL::CA::X509_NAME

This Perl class wraps around the X509_NAME_* functions of OpenSSL,
that deal with X500 DNs.  Unlike OpenSSL's X509_NAME,
I<Crypt::OpenSSL::CA::X509_NAME> objects are immutable: only the
constructor can alter them.

=over

=cut

package Crypt::OpenSSL::CA::X509_NAME;

=item I<new($dnkey1, $dnval1, ...)>

Constructs and returns a new I<Crypt::OpenSSL::CA::X509_NAME> object;
implemented in terms of B<X509_NAME_add_entry_by_txt(3)>.  The RDN
elements are to be passed in the same order as they will appear in the
C<RDNSequence> ASN.1 object that will be constructed, that is, the
B<most-significant parts of the DN> (e.g. C<C>) must come B<first>.
Be warned that this is order is the I<reverse> of RFC4514-compliant
DNs such as those that appear in LDAP, as per section 2.1 of said
RFC4514.

Keys can be given either as uppercase short names (e.g. C<OU> - C<ou>
is not allowed), long names with the proper case
(C<organizationalUnitName>) or dotted-integer OIDs ("2.5.4.11").
Values are interpreted as strings.  Certain keys (especially
C<countryName>) limit the range of acceptable values.

I<new> supports UTF-8 DN values just fine, and will encode them using
the heuristics recommended by the L<Crypt::OpenSSL::CA::Resources/X509
Style Guide>: namely, by selecting the ``least wizz-bang'' character
set that will accomodate the data actually passed.

I<new> does not support multiple AVAs in a single RDN.  If you don't
understand this sentence, consider yourself a lucky programmer.

See also L</get_subject_DN> for an alternative way of constructing
instances of this class.

=item I<to_string()>

Returns a string representation of this DN object. Uses
B<X509_NAME_oneline(3)>.  The return value does not conform to any
standard; in particular it does B<not> comply with RFC4514, and
embedded Unicode characters will B<not> be dealt with elegantly.
I<to_string()> is therefore intended only for debugging.

=item I<to_asn1()>

Returns an ASN.1 DER representation of this DN object, as a string of
bytes.

=cut

use Crypt::OpenSSL::CA::Inline::C <<"X509_NAME_CODE";
#include <openssl/x509.h>

static
SV* new(char* class, ...) {
    Inline_Stack_Vars;
    int i=0;

    X509_NAME *retval = X509_NAME_new();
    if (!retval) { croak("not enough memory for X509_NAME_new"); }

    if (! (Inline_Stack_Items % 2)) {
       croak("odd number of arguments required");
    }

    for(i=1; i<Inline_Stack_Items; i += 2) {
        SV* perl_key; SV* perl_val;
        char* key; char* val;

        perl_key = Inline_Stack_Item(i);
        perl_val = Inline_Stack_Item(i+1);
        key = char0_value(perl_key);
        val = char0_value(perl_val);
        if (! X509_NAME_add_entry_by_txt
                      (retval, key,
                      (SvUTF8(perl_val) ? MBSTRING_UTF8 : MBSTRING_ASC),
                      (unsigned char*) val, -1, -1, 0)) {
             if (retval) { X509_NAME_free(retval); }
             sslcroak("X509_NAME_add_entry_by_txt"
                      " failed at argument %d", i);
        }
    }

    return perl_wrap("${\__PACKAGE__}", retval);
}

static
SV* to_string(SV* obj) {
    X509_NAME* self = perl_unwrap("${\__PACKAGE__}", X509_NAME *, obj);
    return openssl_string_to_SV(X509_NAME_oneline(self, NULL, 4096));
}

static
SV* to_asn1(SV* obj) {
    unsigned char* asn1buf = NULL;
    SV* retval = NULL;
    int length;
    X509_NAME* self = perl_unwrap("${\__PACKAGE__}", X509_NAME *, obj);
    length = i2d_X509_NAME(self, &asn1buf);
    if (length < 0) { croak("i2d_X509_NAME failed"); }
    retval = openssl_buf_to_SV((char *)asn1buf, length);
    SvUTF8_off(retval);
    return retval;
}

static
void DESTROY(SV* obj) {
    X509_NAME_free(perl_unwrap("${\__PACKAGE__}", X509_NAME *, obj));
}

X509_NAME_CODE

=back

=head2 Crypt::OpenSSL::CA::PublicKey

This Perl class wraps around the public key abstraction of OpenSSL.
I<Crypt::OpenSSL::CA::PublicKey> objects are immutable.

=over

=cut

package Crypt::OpenSSL::CA::PublicKey;

=item I<parse_RSA($pemstring)>

Parses an RSA public key from $pemstring and returns an
I<Crypt::OpenSSL::CA::PublicKey> instance.  See also
L</get_public_key> for an alternative way of creating instances of
this class.

=item I<validate_SPKAC($spkacstring)>

=item I<validate_PKCS10($pkcs10string)>

Validates a L<Crypt::OpenSSL::CA::AlphabetSoup/CSR> of the respective
type and returns the public key as an object of class
L<Crypt::OpenSSL::CA::PublicKey> if the signature is correct.  Throws
an error if the signature is invalid.  I<validate_SPKAC($spkacstring)>
wants the ``naked'' Base64 string, without a leading C<SPKAC=> marker,
URI escapes, newlines or any such thing.

Note that those methods are in I<Crypt::OpenSSL::CA> only by virtue of
them requiring cryptographic operations, best implemented using
OpenSSL.  We definitely do B<not> want to emulate the request validity
checking features of C<openssl ca>, which are extremely inflexible and
that a full-fledged PKI built on top of I<Crypt::OpenSSL::CA> would
have to reimplement anyway.  If one wants to parse other details of
the SPKAC or PKCS#10 messages (including the challenge password if
present), one should use other means such as L<Convert::ASN1>; ditto
if one just wants to extract the public key and doesn't care about the
signature.

=item I<to_PEM>

Returns the contents of the public key as a PEM string.

=item I<get_modulus()>

Returns the modulus of this I<Crypt::OpenSSL::CA::PublicKey> instance,
assuming that it is an RSA or DSA key.  This is similar to the output
of C<openssl x509 -modulus>, except that the leading C<Modulus=>
identifier is trimmed and the returned string is not
newline-terminated.

=item I<get_openssl_keyid()>

Returns a cryptographic hash over this public key, as OpenSSL's
C<subjectKeyIdentifier=hash> configuration directive to C<openssl ca>
would compute it for a certificate that contains this key.  The return
value is a string of colon-separated pairs of uppercase hex digits,
adequate e.g. for passing as the $value parameter to
L</set_extension>.

=cut

use Crypt::OpenSSL::CA::Inline::C <<"PUBLICKEY_CODE";
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>     /* For validate_SPKAC */
#include <openssl/x509v3.h>   /* For get_openssl_keyid() */
#include <openssl/objects.h>  /* For NID_subject_key_identifier
                                 in get_openssl_keyid() */

static
SV* validate_SPKAC(char *class, const char* base64_spkac) {
    NETSCAPE_SPKI* spkac;
    EVP_PKEY* retval;

    ensure_openssl_stuff_loaded();
    if (! (spkac = NETSCAPE_SPKI_b64_decode(base64_spkac, -1)) ) {
        sslcroak("Unable to load Netscape SPKAC structure");
    }
    if (! (retval=NETSCAPE_SPKI_get_pubkey(spkac)) ) {
        NETSCAPE_SPKI_free(spkac);
        sslcroak("Unable to extract public key from SPKAC structure");
    }
    if (NETSCAPE_SPKI_verify(spkac, retval) < 0) {
        EVP_PKEY_free(retval);
        NETSCAPE_SPKI_free(spkac);
        sslcroak("SPKAC signature verification failed");
    }
    NETSCAPE_SPKI_free(spkac);
    return perl_wrap("${\__PACKAGE__}", retval);
}

static
SV* validate_PKCS10(char *class, const char* pem_pkcs10) {
    BIO* pkcs10bio;
    X509_REQ* req;
    EVP_PKEY* retval;
    int status;

    ensure_openssl_stuff_loaded();
    pkcs10bio = BIO_new_mem_buf((void *) pem_pkcs10, -1);
    if (pkcs10bio == NULL) {
        croak("BIO_new_mem_buf failed");
    }

    req = PEM_read_bio_X509_REQ(pkcs10bio, NULL, NULL, NULL);
    BIO_free(pkcs10bio);
    if (! req) { sslcroak("Error parsing PKCS#10 request"); }

    if (! (retval = X509_REQ_get_pubkey(req))) {
        X509_REQ_free(req);
        sslcroak("Error extracting public key from PKCS#10 request");
    }
    status = X509_REQ_verify(req, retval);
    X509_REQ_free(req);
    if (status < 0) {
        sslcroak("PKCS#10 signature verification problems");
    } else if (status == 0) {
        sslcroak("PKCS#10 signature does not match the certificate");
    }
    return perl_wrap("${\__PACKAGE__}", retval);
}

static
SV* to_PEM(SV* sv_self) {
    EVP_PKEY* self = perl_unwrap("${\__PACKAGE__}", EVP_PKEY *, sv_self);
    BIO* mem;
    int printstatus;

    if (! (mem = BIO_new(BIO_s_mem()))) {
        croak("Cannot allocate BIO");
    }
    if (self->type == EVP_PKEY_RSA) {
        printstatus = PEM_write_bio_RSA_PUBKEY(mem, self->pkey.rsa);
    } else if (self->type == EVP_PKEY_DSA) {
        printstatus = PEM_write_bio_DSA_PUBKEY(mem, self->pkey.dsa);
    } else {
        BIO_free(mem);
        croak("Unknown public key type %d", self->type);
    }
    printstatus = printstatus && BIO_write(mem, "\\0", 1);
    if (! printstatus) {
        BIO_free(mem);
        sslcroak("Serializing public key failed");
    }
    return BIO_mem_to_SV(mem);
}

static
SV* parse_RSA(char *class, const char* pemkey) {
    BIO* keybio;
    RSA* pubkey;
    EVP_PKEY* retval;

    keybio = BIO_new_mem_buf((void *) pemkey, -1);
    if (keybio == NULL) {
        croak("BIO_new_mem_buf failed");
    }

    pubkey = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    BIO_free(keybio);
    if (pubkey == NULL) {
            sslcroak("unable to parse RSA public key");
    }

    retval = EVP_PKEY_new();
    if (! retval) {
        RSA_free(pubkey);
        croak("Not enough memory for EVP_PKEY_new");
    }

    if (! EVP_PKEY_assign_RSA(retval, pubkey)) {
        RSA_free(pubkey);
        EVP_PKEY_free(retval);
        sslcroak("EVP_PKEY_assign_RSA failed");
    }

    return perl_wrap("${\__PACKAGE__}", retval);
}

static
SV* get_modulus(SV* obj) {
    EVP_PKEY* self = perl_unwrap("${\__PACKAGE__}", EVP_PKEY *, obj);
    BIO* mem;
    SV* retval;
    int printstatus;

    if (! (mem = BIO_new(BIO_s_mem()))) {
        croak("Cannot allocate BIO");
    }

    if (self->type == EVP_PKEY_RSA) {
            printstatus = BN_print(mem,self->pkey.rsa->n);
    } else if (self->type == EVP_PKEY_DSA) {
            printstatus = BN_print(mem,self->pkey.rsa->n);
    } else {
            BIO_free(mem);
            croak("Unknown public key type %d", self->type);
    }

    printstatus = printstatus && BIO_write(mem, "\\0", 1);
    if (! printstatus) {
        BIO_free(mem);
        sslcroak("Serializing modulus failed");
    }
    return BIO_mem_to_SV(mem);
}

static
SV* get_openssl_keyid(SV* obj) {
    EVP_PKEY* self = perl_unwrap("${\__PACKAGE__}", EVP_PKEY *, obj);
    X509* fakecert = NULL;
    X509V3_EXT_METHOD* method = NULL;
    X509V3_CTX ctx;
    ASN1_OCTET_STRING* hash = NULL;
    char* hash_hex = NULL;
    char* err = NULL;

    /* Find OpenSSL's "object class" that deals with subject
     * key identifiers: */
    method = X509V3_EXT_get_nid(NID_subject_key_identifier);
    if (! method) {
        err = "X509V3_EXT_get_nid failed"; goto end;
    }

    /* Pass the public key as part of a fake certificate, itself
     * part of a mostly dummy X509V3_CTX, because that's what
     * X509V3_EXT_METHOD*'s want: */
    fakecert = X509_new();
    if (! fakecert) {
        err = "not enough memory for X509_new()"; goto end;
    }
    if (! X509_set_pubkey(fakecert, self)) {
        err = "X509_set_pubkey failed"; goto end;
    }
    X509V3_set_ctx(&ctx, NULL, fakecert, NULL, NULL, 0);

    /* Invoke the method */
    hash = (ASN1_OCTET_STRING*) method->s2i(method, &ctx, "hash");

    /* Convert the result to hex */
    hash_hex = i2s_ASN1_OCTET_STRING(method, hash);
    if (! hash_hex) {
        err = "i2s_ASN1_OCTET_STRING failed"; goto end;
    }

end:

    if (fakecert) { X509_free(fakecert); }
    /* method seems to be statically allocated (no X509V3_EXT_METHOD_free
       in sight) */
    /* ctx is on the stack */
    if (hash)     { ASN1_OCTET_STRING_free(hash); }
    /* hash_hex cannot be set (else we wouldn't have an error) */

    if (err) {
        sslcroak(err);
    }
    return openssl_string_to_SV(hash_hex);
}

static
void DESTROY(SV* obj) {
    EVP_PKEY_free(perl_unwrap("${\__PACKAGE__}", EVP_PKEY *, obj));
}

PUBLICKEY_CODE

=back

=head2 Crypt::OpenSSL::CA::PrivateKey

This Perl class wraps around the private key abstraction of OpenSSL.
I<Crypt::OpenSSL::CA::PrivateKey> objects are immutable.

=over

=cut

package Crypt::OpenSSL::CA::PrivateKey;
use Carp qw(croak);

=item I<parse($pemkey, %named_options)>

Parses a private key $pemkey and returns an instance of
I<Crypt::OpenSSL::CA::PrivateKey>.  Available named options are:

=over

=item I<-password => $password>

Tells that $pemkey is a software key encrypted with password
$password.

=back

Only software keys are supported for now (see L</TODO> about engine
support).

=cut

sub parse {
    croak("incorrect number of arguments to parse()")
        if (@_ % 2);
    my ($self, $keytext, %options) = @_;
    if (defined(my $pass = $options{-password})) {
        return $self->_parse($keytext, $pass, undef, undef);
    } else {
        return $self->_parse($keytext, undef, undef, undef);
    }
}

=begin internals

=item I<_parse($pemkey, $password, $engineobj, $use_engine_format)>

The XS counterpart of L</parse>, sans the syntactic sugar. Parses a
PEM-encoded private key and returns an instance of
I<Crypt::OpenSSL::CA::PrivateKey> wrapping a OpenSSL C<EVP_PKEY *>
handle.  All four arguments are mandatory. I<$engineobj> and
I<$use_engine_format> are B<UNIMPLEMENTED> and should both be passed
as undef.

=end internals

=item I<get_RSA_modulus()>

Returns the modulus of this I<Crypt::OpenSSL::CA::PrivateKey>
instance, assuming that it is an RSA key (the only kind of private key
supported by I<Crypt::OpenSSL::CA> for the time being).  This is
similar to the output of C<openssl rsa -modulus>, except that the
leading C<Modulus=> identifier is trimmed and the returned string is
not newline-terminated.

=cut

use Crypt::OpenSSL::CA::Inline::C <<"PRIVATEKEY_CODE";
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/ui.h>
#include <openssl/evp.h>

/* Returns a password stored in memory.  Callback invoked by
   PEM_read_bio_PrivateKey() when parsing a password-protected
   software private key */
static int gimme_password(char *buf, int bufsiz, int __unused_verify,
    void *cb_data) {
    int pwlength;
    const char *password = (const char *) cb_data;
    if (!password) { return -1; }
    pwlength = strlen(password);
    if (pwlength > bufsiz) { pwlength = bufsiz; }
    memcpy(buf, password, pwlength);
    return pwlength;
}

/* Ditto, but using the ui_method API.  Callback invoked by
   ENGINE_load_private_key when parsing an engine-based
   private key */
/* UNIMPLEMENTED */

static
SV* _parse(char *class, const char* pemkey, SV* svpass,
         SV* engine, SV* parse_using_engine_p) {
    /* UNIMPLEMENTED: engine and parse_using_engine don't work */
    BIO* keybio = NULL;
    EVP_PKEY* pkey = NULL;
    ENGINE* e;
    char* pass = NULL;

    ensure_openssl_stuff_loaded(); /* Needed by PEM_read_bio_PrivateKey */
    if (SvOK(svpass)) { pass = char0_value(svpass); }

    if (SvTRUE(parse_using_engine_p)) {
        static UI_METHOD *ui_method = NULL;

        croak("UNIMPLEMENTED, UNTESTED");

        if (! (engine &&
               (e = perl_unwrap("Crypt::OpenSSL::CA::ENGINE",
                                ENGINE*, engine)))) {
              croak("no engine specified");
        }

        /* UNIMPLEMENTED: must parse from memory not file; must coerce
        that wonky ui_method stuff into * passing C<pass> to the
        engine */
        /* pkey = (EVP_PKEY *)ENGINE_load_private_key
            (e, file, ui_method, (void *) pass); */
    } else {
            keybio = BIO_new_mem_buf((void *) pemkey, -1);
            if (keybio == NULL) {
                croak("BIO_new failed");
            }
            pkey=PEM_read_bio_PrivateKey(keybio, NULL,
                                         gimme_password, (void *) pass);
    }
    if (keybio != NULL) BIO_free(keybio);
    if (pkey == NULL) {
            sslcroak("unable to parse private key");
    }
    return perl_wrap("${\__PACKAGE__}", pkey);
}

static
SV* get_RSA_modulus(SV* obj) {
    EVP_PKEY* self = perl_unwrap("${\__PACKAGE__}", EVP_PKEY *, obj);
    RSA* rsa;
    BIO* mem;
    SV* retval;
    int printstatus;

    if (! (rsa = EVP_PKEY_get1_RSA(self))) { croak("Not an RSA key"); }

    if (! (mem = BIO_new(BIO_s_mem()))) {
          RSA_free(rsa);
          croak("Cannot allocate BIO");
    }

    printstatus = BN_print(mem, rsa->n) && BIO_write(mem, "\\0", 1);
    RSA_free(rsa);
    if (! printstatus) {
        BIO_free(mem);
        sslcroak("Serializing RSA modulus failed");
    }

    return BIO_mem_to_SV(mem);
}

static
void DESTROY(SV* obj) {
    EVP_PKEY_free(perl_unwrap("${\__PACKAGE__}", EVP_PKEY *, obj));
}

PRIVATEKEY_CODE

=back

=head2 Crypt::OpenSSL::CA::ENGINE (B<UNIMPLEMENTED>)

This package models the C<ENGINE_*> functions of OpenSSL.

=cut

package Crypt::OpenSSL::CA::ENGINE;

=over

=item I<setup_simple($engine, $debugp)>

Starts engine $engine (a string), optionally enabling debug if $debugp
(an integer) is true.  Returns a structural reference to same (see
B<engine(3)> to find out what that means).

The code is lifted from OpenSSL's C<setup_engine()> in C<apps.c>,
which despite falling short from C<engine.c> feature-wise (hence the
name, I<setup_simple>) proves sufficient in practice to have the
C</usr/bin/openssl> command-line tool perform all relevant RSA
operations with a variety of L<Crypt::OpenSSL::CA::AlphabetSoup/HSM>s.
Therefore, and despite I haven't tested that due to lack of
appropriate hardware, I am confident that I<Crypt::OpenSSL::CA> can be
make to work with the hardware OpenSSL engines with relatively little
fuss.

=cut

#use Crypt::OpenSSL::CA::Inline::C <<"ENGINE_CODE";
(undef) = <<"ENGINE_CODE";
#include <openssl/engine.h>

static
SV* setup_simple(const char *engine, int debug) {
    ENGINE *e = NULL;

    if (! engine) { croak("Expected engine name"); }

    if(strcmp(engine, "auto") == 0) {
            croak("engine \\"auto\\" is not supported.");
    }
    if((e = ENGINE_by_id(engine)) == NULL
       && (e = try_load_engine(err, engine, debug)) == NULL) {
            croak("invalid engine \\"%s\\", engine);
    }
    if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM,
                    0, err, 0);
    }
    ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
    if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            ENGINE_free(e);
            croak("can't use that engine");
    }

    return perl_wrap("${\__PACKAGE__}", e);
}

static
void DESTROY(SV* obj) {
        ENGINE_free(perl_unwrap("${\__PACKAGE__}", ENGINE *, obj));
}



ENGINE_CODE

=back

=begin internals

=head2 Crypt::OpenSSL::CA::CONF

A wrapper around an OpenSSL C<CONF *> data structure that contains the
OpenSSL configuration data.  Used by L</add_extension> and friends.

This POD is not made visible in the man pages (for now), as
L</add_extension> totally shadows the use of this class.

=over

=cut

package Crypt::OpenSSL::CA::CONF;

=item I<new($confighash)>

Creates the configuration file data structure.  The gnparameter is a
reference to a hash of hashes; the first-level keys are section names,
and the second-level keys are parameter names.  Returns an immutable
object of class I<Crypt::OpenSSL::CA::CONF>.

=item I<get_string($section, $key)>

Calls OpenSSL's C<CONF_get_string>.  Throws an exception as described
in L</Error Management> if the configuration entry is not found.
Unused in I<Crypt::OpenSSL::CA>, for test purposes only.

=item I<DESTROY()>

Deallocates the whole CONF structure, including all that it contains.

=cut

use Crypt::OpenSSL::CA::Inline::C <<"CONF_CODE";
#include <openssl/conf.h>
/* (Sigh) There appears to be no public way of filling out a CONF*
   structure, except using the contents of a config file (in memory
   or on disk): */
#include <openssl/conf_api.h>
#include <string.h>           /* for strlen */

static
SV* new(SV* class, SV* configref) {
    CONF* self;
    HV* hv_config;
    SV* sv_sectionref;
    HV* hv_section;
    CONF_VALUE* section;
    char* sectionname;
    char* key;
    SV* sv_value;
    CONF_VALUE* value_struct;
    char* value;
    I32 unused;

    if (! (self = NCONF_new(NULL))) {
        croak("NCONF_new failed");
    }

    if (! (_CONF_new_data(self))) {
        croak("_CONF_new_data failed");
    }

    if (! (SvOK(configref) && SvROK(configref) &&
           SvTYPE(SvRV(configref)) == SVt_PVHV)) {
        NCONF_free(self);
        croak("Incorrect data structure for configuration object");
    }
    hv_iterinit(hv_config = (HV*) SvRV(configref));
    while( (sv_sectionref =
            hv_iternextsv(hv_config, &sectionname, &unused)) ) {
        section = _CONF_new_section(self, sectionname);
        if (! section) {
            NCONF_free(self);
            sslcroak("_CONF_new_section failed");
        }

        if (! (SvOK(sv_sectionref) && SvROK(sv_sectionref) &&
               SvTYPE(SvRV(sv_sectionref)) == SVt_PVHV)) {
            NCONF_free(self);
            croak("Incorrect data structure for configuration section %s",
                  sectionname);
        }
        hv_iterinit(hv_section = (HV*) SvRV(sv_sectionref));
        while( (sv_value =
                hv_iternextsv(hv_section, &key, &unused)) ) {
            value = char0_value(sv_value);
            if (! strlen(value)) {
                NCONF_free(self);
                croak("bad structure: hash contains %s",
                      (SvPOK(sv_value) ? "a null-string value" :
                       "an undef value"));
            }

        if (!(value_struct =
                  (CONF_VALUE *)OPENSSL_malloc(sizeof(CONF_VALUE)))) {
                NCONF_free(self);
                croak("OPENSSL_malloc failed");
            }
            memset(value_struct, 0, sizeof(value_struct));
            if (! (value_struct->name = BUF_strdup(key))) {
                NCONF_free(self);
                croak("BUF_strdup()ing the key failed");
            }
            if (! (value_struct->value = BUF_strdup(value))) {
                NCONF_free(self);
                croak("BUF_strdup()ing the value failed");
            }
            _CONF_add_string(self, section, value_struct);
        }
    }

    return perl_wrap("${\__PACKAGE__}", self);
}

static
SV* get_string(SV* sv_self, char* section, char* key) {
    CONF* self = perl_unwrap("${\__PACKAGE__}", CONF *, sv_self);
    char* retval;

    retval = NCONF_get_string(self, section, key);
    if (! retval) { sslcroak("NCONF_get_string failed"); }
    return newSVpv(retval, 0);
}

static
void DESTROY(SV* sv_self) {
    NCONF_free(perl_unwrap("${\__PACKAGE__}", CONF *, sv_self));
}

CONF_CODE

=back

=head2 Crypt::OpenSSL::CA::X509V3_EXT

Instances of this class model OpenSSL's C<X509V3_EXT *> extensions
just before they get added to a certificate by L</add_extension>.
They are immutable.

Like L</Crypt::OpenSSL::CA::CONF>, this POD section is not made
visible in the man pages (for now), as L</add_extension> totally
shadows the use of this class.  Furthermore, the API of this class is
just gross from a Perl's hacker point of view.  Granted, the only
point of this class is to have several constructors, so as to
introduce polymorphism into ->_do_add_extension without overflowing
its argument list in an even more inelegant fashion.

=over

=cut

package Crypt::OpenSSL::CA::X509V3_EXT;

=item I<new_from_X509V3_EXT_METHOD($X509, $nid, $value, $CONF)>

Creates and returns an extension using OpenSSL's I<X509V3_EXT_METHOD>
mechanism, which is summarily described in
L<Crypt::OpenSSL::CA::Resources/openssl.txt>.  $X509, an instance of
L</Crypt::OpenSSL::CA::X509>, is the certificate we'll be adding the
extension to (we need it as part of the C<X509V3_CTX>, e.g. to resolve
constructs such as C<< ->add_extension(subjectKeyIdentifier => "hash")
>>).  $nid is the NID of the extension type to add, as returned by
L</extension_by_name>.  $value is the string value as it would be
found in OpenSSL's configuration file under the entry that defines
this extension (e.g. "critical;CA:FALSE").  $CONF is an instance of
L</Crypt::OpenSSL::CA::CONF> that provides additional configuration
for complex X509v3 extensions.

=item I<new_authorityKeyIdentifier_keyid($keyid)>

Creates an returns an X509V3 authorityKeyIdentifier extension
utilizing only the C<keyIdentifier> production of RFC3280 section
4.2.1.1, with the value set to $keyid, a string of colon-separated
pairs of uppercase hex digits typically obtained using
L</get_openssl_keyid>.  Optionally $keyid may be prefixed with the
string "critical,", just like $value in
L</new_from_X509V3_EXT_METHOD>.

Oddly enough, such a construct is not possible using
L</new_from_X509V3_EXT_METHOD>: OpenSSL does not support storing a
literal value in the configuration file for C<authorityKeyIdentifier>,
it only supports copying it from the CA certificate (whereas we don't
want to insist on the user of I<Crypt::OpenSSL::CA> having said CA
certificate at hand).

Also note that identifying the authority key by issuer name and serial
number (the other option discussed in RFC3280 section 4.2.1.1) is
frowned upon in L<Crypt::OpenSSL::CA::Resources/X509 Style Guide>, and
therefore not yet supported by I<Crypt::OpenSSL::CA> (patches welcome
though).

=cut

use Crypt::OpenSSL::CA::Inline::C <<"X509V3_EXT_CODE";
#include <openssl/x509v3.h>

static
SV* new_from_X509V3_EXT_METHOD(SV* class,
                     SV* sv_x509, int nid, char* value, SV* sv_config) {
    X509V3_CTX ctx;
    X509_EXTENSION* self;
    CONF* config = perl_unwrap("Crypt::OpenSSL::CA::CONF",
                                CONF *, sv_config);
    X509* x509 = perl_unwrap("Crypt::OpenSSL::CA::X509",
                                X509 *, sv_x509);

    if (! nid) { croak("Unknown extension specified"); }
    if (! value) { croak("No value specified"); }

    X509V3_set_ctx(&ctx, NULL, x509, NULL, NULL, 0);
    X509V3_set_nconf(&ctx, config);
    self = X509V3_EXT_nconf_nid(config, &ctx, nid, value);
    if (!self) { sslcroak("X509V3_EXT_conf_nid failed"); }

    return perl_wrap("${\__PACKAGE__}", self);
}

static
SV* new_authorityKeyIdentifier_keyid(SV* class, char* keyid) {
    X509V3_CTX ctx;
    X509_EXTENSION* self;
    X509_EXTENSION* tmp;
    X509* fake_issuer_cert = NULL;

    if (! keyid) { croak("keyid is mandatory"); }

    /* Constructing the X509_EXTENSION object by hand is just too
     * much of a PITA, so we fake having an issuer certificate :-P. */

    if (! (fake_issuer_cert = X509_new())) {
        croak("X509_new failed");
    }

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, fake_issuer_cert, fake_issuer_cert, NULL, NULL, 0);

    if (! (tmp = X509V3_EXT_nconf_nid
                   (NULL, &ctx, NID_subject_key_identifier, keyid)) ) {
        X509_free(fake_issuer_cert);
        sslcroak("failed to parse the key identifier");
    }
    if (! X509_add_ext(fake_issuer_cert, tmp, -1)) {
        X509_free(fake_issuer_cert);
        X509_EXTENSION_free(tmp);
        sslcroak("X509_add_ext failed");
    }

    self = X509V3_EXT_nconf_nid(NULL, &ctx, NID_authority_key_identifier,
                                (strstr(keyid, "critical,") == keyid ?
                                  "critical,keyid:always" :
                                  "keyid:always"));
    X509_free(fake_issuer_cert);
    X509_EXTENSION_free(tmp);

    if (!self) {
        sslcroak("failed to copy the key identifier as a new extension");
    }

    return perl_wrap("${\__PACKAGE__}", self);
}


static
void DESTROY(SV* sv_self) {
    X509_EXTENSION_free(perl_unwrap("${\__PACKAGE__}",
                                    X509_EXTENSION *, sv_self));
}

X509V3_EXT_CODE

=back

=end internals

=head2 Crypt::OpenSSL::CA::X509

This Perl class wraps around the X509 certificate creation routines of
OpenSSL.  I<Crypt::OpenSSL::CA::X509> objects are mutable; they
typically get constructed piecemeal, and signed once at the end with
L</sign>.

There is also limited support in this class for parsing certificates
using L</parse> and various read accessors, but only insofar as it
helps I<Crypt::OpenSSL::CA> be feature-compatible with OpenSSL's
command-line CA.  Namely, I<Crypt::OpenSSL::CA::X509> is currently
only able to extract the information that customarily gets copied over
from the CA's own certificate to the certificates it issues: the
issuer DN (with L</get_subject_DN> on the CA's certificate) and the
public key identifier (with L</get_subject_key_identifier>).  Patches
are of course welcome, but TIMTOWTDI: please consider using a
dedicated ASN.1 parser such as L<Convert::ASN1> or L<Crypt::X509>
instead.

=over

=cut

package Crypt::OpenSSL::CA::X509;
use Carp qw(croak);

=back

=head3 Support for OpenSSL-style extensions

L</set_extension>, L</add_extension>, L</set_complex_extension> and
L</add_complex_extension> work with OpenSSL's I<X509V3_EXT_METHOD>
mechanism, which is summarily described in
L<Crypt::OpenSSL::CA::Resources/openssl.txt>.  This means that most
X509v3 extensions that can be set through OpenSSL's configuration file
can be passed to this module as Perl strings in exactly the same way;
see L</set_extension> for details.

B<Warning:> the keyword in the previous sentence is ``most'', which is
not ``all''.  In particular, you should be aware that any extension
method that relies on the issuer certificate being known will B<not>
work, because unlike C<openssl ca> we don't insist on having the CA
certificate at hand in order to sign more certificates.  This means
that

=for My::Tests::Below "nice try with set_extension, no cigar" begin

   $cert->set_extension("authorityKeyIdentifier",
                               "keyid:always");          # WRONG!

=for My::Tests::Below "nice try with set_extension, no cigar" end

will B<not> work; here is the correct construct to replace it (don't
look for it in OpenSSL's documentation or lack thereof,
L</Crypt::OpenSSL::CA::X509> provides it in an ad-hoc manner):

=for My::Tests::Below "set_extension authorityKeyIdentifier" begin

  $cert->set_extension(authorityKeyIdentifier_keyid => "00:DE:AD:BE:EF");

=for My::Tests::Below "set_extension authorityKeyIdentifier" end

where the value can be obtained using L</get_openssl_keyid> on the
CA's public key.

On a related matter, identifying the authority key by issuer name and
serial number, an option that is discussed in RFC3280 section 4.2.1.1,
is frowned upon in L<Crypt::OpenSSL::CA::Resources/X509 Style Guide>,
and therefore not yet supported by I<Crypt::OpenSSL::CA>.  Patches
welcome though.

=head3 Constructors and Methods

=over

=item I<new($pubkey)>

Create an empty certificate shell waiting to be signed for public key
C<$pubkey>, an instance of L</Crypt::OpenSSL::CA::PublicKey>.  All
mandatory values in an X509 certificate are set to a dummy default
value, which the caller will probably want to alter using the various
I<set_*> methods in this class. Returns an instance of the class
I<Crypt::OpenSSL::CA::X509>, wrapping around an OpenSSL C<X509 *>
handle.

=item I<parse($pemcert)>

Parses a PEM-encoded X509 certificate and returns an instance of
I<Crypt::OpenSSL::CA::X509> that already has a number of fields set.
Despite this, the returned object can be L</sign>ed anew if one wants.

=item I<get_public_key()>

Returns an instance of L</Crypt::OpenSSL::CA::PublicKey> that
corresponds to the RSA or DSA public key in this certificate.
Memory-management wise, this performs a copy of the underlying
C<EVP_PKEY *> structure; therefore there is no danger in destroying
this certificate object and keeping only the returned public key.

=item I<get_subject_DN()>

Returns the subject DN of this I<Crypt::OpenSSL::CA::X509> instance,
as an L</Crypt::OpenSSL::CA::X509_NAME> instance.  Memory-management
wise, this performs a copy of the underlying C<X509_NAME *> structure;
therefore there is no danger in destroying this certificate object and
keeping only the returned DN.

=item I<get_subject_keyid()>

Returns the contents of the C<subjectKeyIdentifier> field, if present,
as a string of colon-separated pairs of uppercase hex digits.  If no
such extension is available, returns undef.  Depending on the whims of
the particular CA that signed this certificate, this may or may not be
the same as C<< $self->get_public_key->get_openssl_keyid >>.

=item I<set_serial_hex($serial_hexstring)>

Sets the serial number to C<$serial_hexstring>, which must be a scalar
containing an unadorned, lowercase, hexadecimal string.

=item I<set_subject_DN($dn_object)>

=item I<set_issuer_DN($dn_object)>

Sets the subject and issuer DNs from L</Crypt::OpenSSL::CA::X509_NAME>
objects.

=item I<set_notBefore($startdate)>

=item I<set_notAfter($enddate)>

Sets the validity period of the certificate.  The dates must be in the
GMT timezone, with the format yyyymmddhhmmssZ (it's a literal Z at the
end, meaning "Zulu" in case you care).

=item I<extension_by_name($extname)>

Returns true if and only if $extname is a valid X509v3 certificate
extension, susceptible of being passed to L</set_extension> and
friends.  Specifically, returns the OpenSSL NID associated with
$extname, as an integer.  Can be invoked either as an instance method
or as a class method.

=item I<set_extension($extname, $value, %options, %more_openssl_config)>

Sets X509 extension $extname to the value $value in the certificate,
erasing any extension previously set for $extname in this certificate.
To make a long story short, $extname and $value may be almost any
legit key-value pair in the OpenSSL configuration file's section that
is pointed to by the C<x509_extensions> parameter; for example,
OpenSSL's

   subjectKeyIdentifier=00:DE:AD:BE:EF

becomes

=for My::Tests::Below "set_extension subjectKeyIdentifier" begin

   $cert->set_extension( subjectKeyIdentifier => "00:DE:AD:BE:EF");

=for My::Tests::Below "set_extension subjectKeyIdentifier" end

Actually I<set_extension()> interprets a few ($extname, $value) pairs
that are B<not> understood by stock OpenSSL, most notably C<< $extname
= "authorityKeyIdentifier_keyid" >>.  See the complete discussion in
L</Support for OpenSSL-style extensions>.

The rest of the arguments are interpreted as a list of key-value
pairs.  Those that start with a hyphen are named options; they are
interpreted like so:

=over

=item I<< -critical => 1 >>

Sets the extension as critical.  You may alternatively use the OpenSSL
trick of prepending "critical," to $value, but that's ugly.

=item I<< -critical => 0 >>

Do not set the extension as critical.  If C<critical> is present in
$value, an exception will be raised.

=back

The extra key-value key arguments that do B<not> start with a hyphen
are passed to OpenSSL as sections in its configuration file object;
the corresponding values must therefore be references to hash tables.
For example, here is how to transcribe the C<certificatePolicies>
example from L<Crypt::OpenSSL::CA::Resources/openssl.txt> into Perl:

=for My::Tests::Below "set_extension certificatePolicies" begin

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

=for My::Tests::Below "set_extension certificatePolicies" end

=cut

sub set_extension {
    my ($self, $extname, @stuff) = @_;
    my $real_extname = $extname;
    $real_extname = "authorityKeyIdentifier" if
        ($extname =~ m/^authorityKeyIdentifier/i);
    $self->remove_extension($real_extname);
    $self->add_extension($extname, @stuff);
}

=item I<add_extension($extname, $value, %options, %more_openssl_config)>

Just like L</set_extension>, except that if there is already a
value for this extension, it will not be removed; instead there will
be a duplicate extension in the certificate.  Note that this is
explicitly forbiden by RFC3280 section 4.2, third paragraph, so maybe
you shouldn't do that.

=cut

sub add_extension {
    die("incorrect number of arguments to add_extension()")
        unless (@_ % 2);
    my ($self, $extname, $value, %options) = @_;
    croak("add_extension: name is mandatory") unless
        ($extname && length($extname));
    croak("add_extension: value is mandatory") unless
        ($value && length($value));

    my $critical = "";
    $critical = "critical," if ($value =~ s/^critical(,|$)//i);

    foreach my $k (keys %options) {
        next unless $k =~ m/^-/;
        my $v = delete $options{$k};

        if ($k eq "-critical") {
            if ($v) {
                $critical = "critical,";
            } else {
                croak("add_extension: -critical => 0 conflicts" .
                      " with ``$_[2]''") if ($critical);
            }
        }
        # Other named options may be added later.
    }

    my $ext;
    if ($extname eq "authorityKeyIdentifier_keyid") {
        $ext = Crypt::OpenSSL::CA::X509V3_EXT->
            new_authorityKeyIdentifier_keyid("$critical$value");
    } elsif (my $nid = $self->extension_by_name($extname)) {
        $ext = Crypt::OpenSSL::CA::X509V3_EXT->new_from_X509V3_EXT_METHOD
            ($self, $nid, "$critical$value",
             Crypt::OpenSSL::CA::CONF->new(\%options));
    } else {
        croak "Unknown extension name $extname";
    }
    $self->_do_add_extension($ext);
}



=item I<remove_extension($extname)>

Removes any and all extensions named $extname in this certificate.

Sets the authority key identifier extension to $keyid, using RFC3280's
C<keyIdentifier> production in section 4.2.1.1.  Note that
I<set_authority_keyid> is B<not> a sub-feature of L</set_extension>
because, oddly enough, OpenSSL does not support storing a literal
value in the configuration file for C<authorityKeyIdentifier> (it only
supports copying same from the CA certificate, whereas we don't want
to insist on the caller providing one).

Also 

=cut

sub set_authority_keyid {
    die "UNIMPLEMENTED";
}

=begin internals

=item I<_do_add_extension($extension)>

Does the actual job of L</add_extension>, sans all the syntactic
sugar. $extension is an instance of
L</Crypt::OpenSSL::CA::X509V3_EXT>.

=end internals

=item I<dump()>

Returns a textual representation of all the fields inside the
(unfinished) certificate.  This is done using OpenSSL's
C<X509_print()>.

=item I<sign($privkey, $digestname)>

Signs the certificate (TADA!!).  C<$privkey> is an instance of
L</Crypt::OpenSSL::CA::PrivateKey>; C<$digestname> is the name of one
of cryptographic digests supported by OpenSSL, e.g. "sha1" or "sha256"
(notice that using "md5" is B<strongly discouraged> due to security
considerations; see
L<http://www.win.tue.nl/~bdeweger/CollidingCertificates/>).  Returns
the PEM-encoded certificate as a string.

=cut

use Crypt::OpenSSL::CA::Inline::C <<"X509_CODE";
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h> /* For EVP_get_digestbyname() */
#include <openssl/bn.h>  /* For BN_hex2bn in set_serial_hex() */

static
SV* new(char* class, SV* sv_pubkey) {
    X509* self;
    EVP_PKEY* pubkey = perl_unwrap("Crypt::OpenSSL::CA::PublicKey",
                                   EVP_PKEY *, sv_pubkey);
    char* err;

    self = X509_new();
    if (! self) { err = "not enough memory for X509_new"; goto error; }
    if (! X509_set_version(self, 2))
        { err = "X509_set_version failed"; goto error; }
    if (! X509_set_pubkey(self, pubkey))
        { err = "X509_set_pubkey failed"; goto error; }
    if (! ASN1_INTEGER_set(X509_get_serialNumber(self), 1))
        { err = "ASN1_INTEGER_set failed"; goto error; }
    if (! ASN1_TIME_set(X509_get_notBefore(self), 0))
        { err = "ASN1_TIME_set failed for notBefore"; goto error; }
    if (! ASN1_TIME_set(X509_get_notAfter(self), 0))
        { err = "ASN1_TIME_set failed for notAfter"; goto error; }

    return perl_wrap("${\__PACKAGE__}", self);

 error:
    if (self) { X509_free(self); }
    sslcroak(err);
    return NULL; // Not reached
}

static
SV* parse(char *class, const char* pemcert) {
    BIO* keybio = NULL;
    X509* retval = NULL;

    keybio = BIO_new_mem_buf((void *) pemcert, -1);
    if (keybio == NULL) {
        croak("BIO_new failed");
    }
    retval = PEM_read_bio_X509(keybio, NULL, NULL, NULL);
    BIO_free(keybio);

    if (retval == NULL) {
            sslcroak("unable to parse certificate");
    }
    return perl_wrap("${\__PACKAGE__}", retval);
}

static
SV* get_public_key(SV* obj) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    EVP_PKEY* pkey = X509_get_pubkey(self);
    if (! pkey) { sslcroak("Huh, no public key in this certificate?!"); }

    return perl_wrap("Crypt::OpenSSL::CA::PublicKey", pkey);
}

static
SV* get_subject_DN(SV* obj) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    X509_NAME* name = X509_get_subject_name(self);

    if (! name) { sslcroak("Huh, no subject name in certificate?!"); }

    name = X509_NAME_dup(name);
    if (! name) { croak("Not enough memory for get_subject_DN"); }

    return perl_wrap("Crypt::OpenSSL::CA::X509_NAME", name);
}

static
SV* get_subject_keyid(SV* sv_self) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, sv_self);
    X509_EXTENSION *ext;
    ASN1_OCTET_STRING *ikeyid;
    char* retval;
    int i;

    i = X509_get_ext_by_NID(self, NID_subject_key_identifier, -1);
    if (i < 0) {
        return newSVsv(&PL_sv_undef);
    }
    if (! ((ext = X509_get_ext(self, i)) &&
           (ikeyid = X509V3_EXT_d2i(ext))) ) {
        sslcroak("Failed extracting subject keyID from certificate");
        return NULL; /* Not reached */
    }
    retval = i2s_ASN1_OCTET_STRING(NULL, ikeyid);
    ASN1_OCTET_STRING_free(ikeyid);
    if (! retval) { croak("Converting to hex failed"); }
    return openssl_string_to_SV(retval);
}

static
void set_serial_hex(SV* obj, char* serial_hexstring) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    ASN1_INTEGER* serial_asn1;
    BIGNUM* serial = NULL;

    if (! BN_hex2bn(&serial, serial_hexstring)) {
        sslcroak("BN_hex2bn failed");
    }
    if (! BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(self))) {
        BN_free(serial);
        sslcroak("BN_to_ASN1_INTEGER failed");
    }
    BN_free(serial);
}

static
void set_subject_DN(SV* obj, SV* dn_object) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    X509_NAME* dn = perl_unwrap("Crypt::OpenSSL::CA::X509_NAME",
                                X509_NAME *, dn_object);
    if (! X509_set_subject_name(self, dn)) {
        sslcroak("X509_set_subject_name failed");
    }
}

static
void set_issuer_DN(SV* obj, SV* dn_object) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    X509_NAME* dn = perl_unwrap("Crypt::OpenSSL::CA::X509_NAME",
                                X509_NAME *, dn_object);
    if (! X509_set_issuer_name(self, dn)) {
        sslcroak("X509_set_issuer_name failed");
    }
}

/* RFC3280, section 4.1.2.5 */
#define RFC3280_cutoff_date "20500000" "000000"
static void set_validity(ASN1_TIME* t, char* date) {
    int status;
    int is_generalizedtime;

    if (strlen(date) != strlen(RFC3280_cutoff_date) + 1) {
         croak("Wrong date length");
    }
    if (date[strlen(RFC3280_cutoff_date)] != 'Z') {
         croak("Wrong date format");
    }

    is_generalizedtime = (strcmp(date, RFC3280_cutoff_date) > 0);
    if (! (is_generalizedtime ?
           ASN1_GENERALIZEDTIME_set_string(t, date) :
           ASN1_UTCTIME_set_string(t, date + 2)) ) {
        croak("%s failed: bad date format (%s)",
              (is_generalizedtime ? "ASN1_GENERALIZEDTIME_set_string" :
               "ASN1_UTCTIME_set_string"), date);
    }
}


static
void set_notBefore(SV* obj, char* startdate) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    return set_validity(X509_get_notBefore(self), startdate);
}

static
void set_notAfter(SV* obj, char* enddate) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    return set_validity(X509_get_notAfter(self), enddate);
}

/* This one is callable from both Perl and C, kewl! */
static
int extension_by_name(SV* unused, char* extname) {
    int nid;
    X509V3_EXT_METHOD* method;

    if (! extname) { return 0; }
    nid = OBJ_txt2nid(extname);

    if (! nid) { return 0; }
    if (! (method = X509V3_EXT_get_nid(nid)) ) { return 0; }

    /* Extensions that cannot be created are obviously not supported. */
    if (! (method->v2i || method->s2i || method->r2i) ) { return 0; }
    /* This is also how we check whether this extension is for
       certificates or for CRLs: there is no support for creating
       them!  FIXME: when CRL extension support finally gets added to
       OpenSSL, we'll have to change that. */

    return nid;
}

static
void _do_add_extension(SV* obj, SV* sv_extension) {
    X509V3_CTX ctx;
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    X509_EXTENSION *ex = perl_unwrap("Crypt::OpenSSL::CA::X509V3_EXT",
                                     X509_EXTENSION *, sv_extension);

    if (! X509_add_ext(self, ex, -1)) {
        sslcroak("X509_add_ext failed");
    }
}

static
void remove_extension(SV* obj, char* key) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    X509_EXTENSION* deleted;
    int nid, i;

    nid = extension_by_name(NULL, key);
    if (! nid) { croak("Unknown extension specified"); }

    while( (i = X509_get_ext_by_NID(self, nid, -1)) >= 0) {
        if (! (deleted = X509_delete_ext(self, i)) ) {
            sslcroak("X509_delete_ext failed");
        }
        X509_EXTENSION_free(deleted);
    }
}

static
SV* dump(SV* obj) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    BIO* mem = BIO_new(BIO_s_mem());

    if (! mem) {
        croak("Cannot allocate BIO");
    }

    if (! (X509_print(mem, self) && BIO_write(mem, "\\0", 1)) ) {
        sslcroak("X509_print failed");
    }

    return BIO_mem_to_SV(mem);
}

static
SV* sign(SV* obj, SV* privkey, char* digestname) {
    X509* self = perl_unwrap("${\__PACKAGE__}", X509 *, obj);
    EVP_PKEY* key = perl_unwrap("Crypt::OpenSSL::CA::PrivateKey",
         EVP_PKEY *, privkey);
    const EVP_MD* digest;
    BIO* mem;

    ensure_openssl_stuff_loaded;
    if (! (digest = EVP_get_digestbyname(digestname))) {
        sslcroak("Unknown digest name: %s", digestname);
    }

    if (! X509_sign(self, key, digest)) {
        sslcroak("X509_sign failed");
    }

    if (! (mem = BIO_new(BIO_s_mem()))) {
        croak("Cannot allocate BIO");
    }
    if (! (PEM_write_bio_X509(mem, self) && BIO_write(mem, "\\0", 1)) ) {
        BIO_free(mem);
        croak("Serializing certificate failed");
    }
    return BIO_mem_to_SV(mem);
}

static
void DESTROY(SV* obj) {
    X509_free(perl_unwrap("${\__PACKAGE__}", X509 *, obj));
}


X509_CODE

=back

=head1 TODO

An implementation for the main class is coming soon.  It will feature
a simple CA database abstraction, RFC3280 compliance checks
(especially as regards the criticality of X509v3 certificate
extensions) and the ability to derive much information in the issued
certificates from the CA's own certificate, as OpenSSL does.

OpenSSL engines are only a few hours of work away, but aren't done
yet.

Key formats other than RSA are not (fully) supported, and at any rate,
not unit-tested.

=head1 SEE ALSO

For the X509 stuff: L<Crypt::OpenSSL::CA::Resources>.

For Inline mojo: L<Inline::C>, L<perlxstut>, L<perlguts>, L<perlapi>.

=head1 AUTHOR

Dominique QUATRAVAUX, C<< <domq at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-crypt-openssl-ca at
rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-OpenSSL-CA>.  I
will be notified, and then you'll automatically be notified of
progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Crypt::OpenSSL::CA

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Crypt-OpenSSL-CA>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Crypt-OpenSSL-CA>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-OpenSSL-CA>

=item * Search CPAN

L<http://search.cpan.org/dist/Crypt-OpenSSL-CA>

=back

=head1 ACKNOWLEDGEMENTS

IDEALX (L<http://www.idealx.com/>) is the company that put food on my
family's table for 5 years while I was busy coding IDX-PKI.  I owe
them pretty much everything I know about PKIX, and a great deal of my
todays' Perl-fu.  It is therefore no surprise that the API of this
module closely resembles that of L<IDX::PKI::CA>, as permitted by the
license thereof.  The implementation, however, is original.

=head1 COPYRIGHT & LICENSE


Copyright (C) 2007 Siemens Business Services France SAS, all rights
reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

use Crypt::OpenSSL::CA::Inline::C "__END__";

require My::Tests::Below unless caller();
1;

__END__

=head1 TEST SUITE

=cut

use Test::More no_plan => 1;
use Test::Group;
use Crypt::OpenSSL::CA::Test;
use Data::Dumper;

=head2 X509_NAME tests

=cut

use Crypt::OpenSSL::CA::Test qw(test_simple_utf8 test_bmp_utf8
                                x509_decoder);

test "X509_NAME" => sub {
    my $name = Crypt::OpenSSL::CA::X509_NAME->new();
    ok($name->isa("Crypt::OpenSSL::CA::X509_NAME"));
    is($name->to_string(), "");

    $name = Crypt::OpenSSL::CA::X509_NAME->new
        (CN => "John Doe", "2.5.4.11" => "Internet widgets");
    like($name->to_string(), qr/cn=John Doe/i);
    like($name->to_string(), qr/ou=Internet widgets/i);

    eval {
        my $name = Crypt::OpenSSL::CA::X509_NAME->new("John Doe");
        fail("should have thrown - Bad number of arguments");
    };
    like($@, qr/arg/);

    {
        my $dn = Crypt::OpenSSL::CA::X509_NAME->new
            (C => "fr", CN => test_simple_utf8);
        like($dn->to_string, qr/cn=zoinx/i);
        my $asn1 = x509_decoder('Name');
        my $tree = $asn1->decode($dn->to_asn1);
        if (! isnt($tree, undef, "decoding succesful")) {
            diag $asn1->error;
            diag run_dumpasn1($dn->to_asn1);
        } else {
            my $rdn_asn1 = $tree->{rdnSequence}->[1]->[0];
            my ($rdn_type) = keys %{$rdn_asn1->{value}};
            is($rdn_type, "teletexString"); # Minimal encoding
        }
    }

    {
        my $dn = Crypt::OpenSSL::CA::X509_NAME
             ->new(C => "fr", CN => test_bmp_utf8);
        my $tree = x509_decoder('Name')->decode
            ($dn->to_asn1);
        if (isnt($tree, undef, "decoding succesful")) {
            my $rdn_asn1 = $tree->{rdnSequence}->[1]->[0];
            my ($rdn_type) = keys %{$rdn_asn1->{value}};
            is($rdn_type, "bmpString");
        }
    }
};

skip_next_test "Memchmark needed" if cannot_check_bytes_leaks;
test "X509_NAME accessors don't leak" => sub {
    my $name = Crypt::OpenSSL::CA::X509_NAME->new
        (CN => "coucou", "2.5.4.11.1.2.3.4" => "who cares?");
    leaks_bytes_ok {
        for(1..10000) {
            $name->to_string();
            $name->to_asn1();
        }
    };
};

=head2 PublicKey tests

=cut

use Crypt::OpenSSL::CA::Test qw(%test_public_keys);

test "PublicKey" => sub {
    errstack_empty_ok();

    my $pubkey = Crypt::OpenSSL::CA::PublicKey->parse_RSA
        ($test_public_keys{rsa1024});
    is(ref($pubkey), "Crypt::OpenSSL::CA::PublicKey");
    like($pubkey->get_modulus, qr/^[0-9A-F]+$/);
    like($pubkey->get_openssl_keyid, qr/^[0-9A-F]{2}(:[0-9A-F]{2})*$/);

    errstack_empty_ok();
};

skip_next_test if cannot_check_bytes_leaks;
test "PublicKey leakage" => sub {
        leaks_bytes_ok {
            for(1..1000) {
                my $pubkey = Crypt::OpenSSL::CA::PublicKey
                    ->parse_RSA($test_public_keys{rsa1024});
                $pubkey->to_PEM;
                $pubkey->get_modulus;
                $pubkey->get_openssl_keyid;
                # One more time, as ->get_openssl_keyid does an
                # X509_free() on a fake cert that points to the public
                # key and that's where things could go medieval:
                $pubkey->get_modulus;
                $pubkey->get_openssl_keyid;
            }
        };
};

use Crypt::OpenSSL::CA::Test qw(%test_reqs_SPKAC %test_reqs_PKCS10);
test "SPKAC key extraction" => sub {
    my $spkac = $test_reqs_SPKAC{rsa1024};
    my $pubkey = Crypt::OpenSSL::CA::PublicKey->validate_SPKAC
        ($spkac);
    is($pubkey->to_PEM, $test_public_keys{rsa1024});
    $spkac =~ tr/12345ABCDE/67890UVWXY/;
    eval {
         Crypt::OpenSSL::CA::PublicKey->validate_SPKAC($spkac);
         fail("should have thrown");
     };
    is(ref($@), "Crypt::OpenSSL::CA::Error", "nifty exception object");
};

skip_next_test if cannot_check_bytes_leaks;
test "SPKAC key extraction leakage" => sub {
    leaks_bytes_ok {
        for (1..1000) {
            Crypt::OpenSSL::CA::PublicKey->validate_SPKAC
                ($test_reqs_SPKAC{rsa1024});
        }
    };
};

test "PKCS#10 key extraction" => sub {
    my $pkcs10 = $test_reqs_PKCS10{rsa1024};
    my $pubkey = Crypt::OpenSSL::CA::PublicKey->validate_PKCS10
        ($pkcs10);
    is($pubkey->to_PEM, $test_public_keys{rsa1024});
    $pkcs10 =~ tr/12345ABCDE/67890UVWXY/;
    eval {
         Crypt::OpenSSL::CA::PublicKey->validate_PKCS10($pkcs10);
         fail("should have thrown");
     };
    is(ref($@), "Crypt::OpenSSL::CA::Error", "nifty exception object");
};

skip_next_test if cannot_check_bytes_leaks;
test "PKCS#10 key extraction leakage" => sub {
    leaks_bytes_ok {
        for (1..1000) {
            Crypt::OpenSSL::CA::PublicKey->validate_PKCS10
                ($test_reqs_PKCS10{rsa1024});
        }
    };
};

=head2 PrivateKey tests

=cut

use Crypt::OpenSSL::CA::Test qw(%test_keys_plaintext %test_keys_password);


test "PrivateKey: parse plaintext software key" => sub {
    ok($test_keys_plaintext{rsa1024});
    errstack_empty_ok();

    my $key = Crypt::OpenSSL::CA::PrivateKey->
        parse($test_keys_plaintext{rsa1024});
    is(ref($key), "Crypt::OpenSSL::CA::PrivateKey");

    like($key->get_RSA_modulus, qr/^[0-9A-F]+$/);
    is($key->get_RSA_modulus,
       Crypt::OpenSSL::CA::PublicKey->parse_RSA($test_public_keys{rsa1024})
       ->get_modulus,
      "matching private and public key moduli");

    errstack_empty_ok();
};

test "PrivateKey: parse password-protected software key" => sub {
    ok($test_keys_password{rsa1024});

    my $key = Crypt::OpenSSL::CA::PrivateKey->
        parse($test_keys_password{rsa1024}, -password => "secret");
    is(ref($key), "Crypt::OpenSSL::CA::PrivateKey");
    like($key->get_RSA_modulus, qr/^[0-9A-F]+$/);

    # wrong password:
    eval {
        my $key = Crypt::OpenSSL::CA::PrivateKey->
            parse($test_keys_password{rsa1024}, -password => "coucou");
        fail("Should have thrown - Bad password");
    };
    is(ref($@), "Crypt::OpenSSL::CA::Error",
       "nifty exception object");
    my $firsterror = $@->{-openssl}->[0];

    # no password, despite one needed:
    eval {
        my $key = Crypt::OpenSSL::CA::PrivateKey->
            parse($test_keys_password{rsa1024});
        fail("Should have thrown - No password");
    };
    is(ref($@), "Crypt::OpenSSL::CA::Error",
       "nifty exception object");
    isnt($@->{-openssl}->[0], $firsterror,
         "Different exceptions, allowing one to discriminate errors");

};

test "PrivateKey: parse engine key" => sub {
    local $TODO = "UNIMPLEMENTED";
    fail;
};

test "PrivateKey: parse engine key with some engine parameters" => sub {
    local $TODO = "UNIMPLEMENTED";
    fail;
};

skip_next_test if cannot_check_bytes_leaks;
test "PrivateKey: memory leaks" => sub {
    leaks_bytes_ok {
        for(1..1000) {
            Crypt::OpenSSL::CA::PrivateKey
                ->parse($test_keys_plaintext{rsa1024})->get_RSA_modulus;
        }
    };
};

=head2 CONF tests

=cut

test "CONF functionality" => sub {
    my $conf = Crypt::OpenSSL::CA::CONF->new
        ({ sect1 => { key1 => "val1", key2 => "val2" }});
    is($conf->get_string("sect1", "key1"), "val1");
    is($conf->get_string("sect1", "key2"), "val2");
    # ->get_string is allowed to either return undef or throw
    # for nonexistent keys:
    is(eval { $conf->get_string("sect2", "key1") }, undef);
};

test "CONF defensiveness" => sub {
    eval {
        Crypt::OpenSSL::CA::CONF->new(\"");
        fail("Should not accept bizarre data structure");
    };
    like($@, qr/structure/);
    eval {
        Crypt::OpenSSL::CA::CONF->new
            ({ sect1 => [ key1 => "val1", key2 => "val2" ]});
        fail("Should not accept bizarre data structure");
    };
    like($@, qr/structure/);
};

skip_next_test if cannot_check_bytes_leaks;
test "CONF memory management" => sub {
    leaks_bytes_ok {
        for (1.100) {
            my $conf = Crypt::OpenSSL::CA::CONF->new
                ({ section => { bigkey => "A" x 6000 }});
            $conf->get_string("section", "bigkey");
        }
    }
};

=head2 X509 Tests

=cut

use Crypt::OpenSSL::CA::Test qw(%test_self_signed_certs);

test "X509 parsing" => sub {
    errstack_empty_ok();

    my $x509 = Crypt::OpenSSL::CA::X509->parse
        ($test_self_signed_certs{rsa1024});
    is(ref($x509->get_public_key), "Crypt::OpenSSL::CA::PublicKey");;

    like($x509->get_subject_DN()->to_string(),
         qr/Internet Widgits/);

    like($x509->dump, qr/Internet Widgits/);

    is(Crypt::OpenSSL::CA::PrivateKey->
       parse($test_keys_plaintext{rsa1024})->get_RSA_modulus,
       $x509->get_public_key->get_modulus,
       "matching private key and certificate");

    is($x509->get_subject_keyid,
       $x509->get_public_key->get_openssl_keyid,
       "this certificate was signed by OpenSSL, it seems");

    my $anotherx509 =Crypt::OpenSSL::CA::X509->parse
        ($Crypt::OpenSSL::CA::Test::test_rootca_certs{rsa1024});
    is($anotherx509->get_subject_keyid,
       $x509->get_public_key->get_openssl_keyid,
       "this certificate was also signed by OpenSSL")
        or warn $anotherx509->dump;

    errstack_empty_ok();
};

skip_next_test if cannot_check_bytes_leaks;
test "X509 read accessor memory leaks" => sub {
        leaks_bytes_ok {
            for(1..1000) {
                my $x509 = Crypt::OpenSSL::CA::X509
                    ->parse($test_self_signed_certs{rsa1024});
                $x509->get_public_key->get_modulus;
                $x509->get_subject_DN;
                $x509->get_subject_keyid;
                $x509->dump;
            }
        };
};

my $cakey = Crypt::OpenSSL::CA::PrivateKey
    ->parse($test_keys_plaintext{rsa1024});
my $eepubkey = Crypt::OpenSSL::CA::PublicKey
    ->parse_RSA($test_public_keys{rsa1024});

use Crypt::OpenSSL::CA::Test qw(certificate_chain_invalid_ok
                                %test_rootca_certs);
test "minimalistic certificate" => sub {
    my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
    my $pem = $cert->sign($cakey, "sha1");
    certificate_looks_ok($pem);
    # There is a *zillion* of reasons why this certificate is invalid:
    certificate_chain_invalid_ok($pem, [ $test_rootca_certs{rsa1024} ]);
};

skip_next_test if cannot_check_bytes_leaks;
test "signing several times over the same ::X509 instance" => sub {
    my $pubkey = Crypt::OpenSSL::CA::PublicKey
        ->parse_RSA($test_public_keys{rsa2048});
    my $cert = Crypt::OpenSSL::CA::X509->new($pubkey);
    my $anothercert = Crypt::OpenSSL::CA::X509->parse
        ($test_self_signed_certs{rsa1024});
    my @issuer_DN = (O => "Zoinx") x 50;
    my @subject_DN = (CN => "Olivera da Figueira") x 50;
    leaks_bytes_ok {
        for(1..500) {
            $cert->set_subject_DN
                (Crypt::OpenSSL::CA::X509_NAME->new(@subject_DN));
            $cert->set_issuer_DN
                (Crypt::OpenSSL::CA::X509_NAME->new(@issuer_DN));
            $cert->sign($cakey, "sha1");
        }
        for(1..500) {
            $anothercert->set_subject_DN
                (Crypt::OpenSSL::CA::X509_NAME->new(@subject_DN));
            $anothercert->set_issuer_DN
                (Crypt::OpenSSL::CA::X509_NAME->new(@issuer_DN));
            $anothercert->sign($cakey, "sha1");
        }
    };

};

skip_next_test if cannot_check_bytes_leaks;
test "REGRESSION: set_serial_hex memory leak" => sub {
    leaks_bytes_ok {
        for(1..100) {
            my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
            for(1..200) { # Checks for robustness and leaks
                $cert->set_serial_hex("1234567890abcdef1234567890ABCDEF");
            }
            $cert->sign($cakey, "sha1");
        }
    };
};

test "extension registry" => sub {
    is(Crypt::OpenSSL::CA::X509
       ->extension_by_name("FooBar"), 0, "bogus extension");
    isnt(Crypt::OpenSSL::CA::X509
         ->extension_by_name("basicConstraints"), 0, "legit extension");
    is(Crypt::OpenSSL::CA::X509
         ->extension_by_name("serverAuth"), 0, "not an extension");
    is(Crypt::OpenSSL::CA::X509
         ->extension_by_name("crlNumber"), 0,
       "this extension is for CRLs, not certificates");
};

skip_next_test if cannot_check_bytes_leaks;
test "extension registry memory leak" => sub {
    leaks_bytes_ok {
        for(1..50000) {
            Crypt::OpenSSL::CA::X509
                ->extension_by_name("basicConstraints");
        }
    };
};

test "monkeying with ->set_extension and ->add_extension in various ways"
=> sub {
    my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
    eval (My::Tests::Below->pod_code_snippet
          ("nice try with set_extension, no cigar")
          . 'fail("should have thrown");');
    my $exn = $@;
    ok(eval { $exn->isa("Crypt::OpenSSL::CA::Error") } &&
       grep { m/no issuer certificate/} @{$exn->{-openssl}} )
        or warn Dumper($exn);
    eval {
        $cert->add_extension(undef, "WTF");
        fail("should have thrown");
    };
    isnt($@, '', "congratulations, you dodged a SEGV!");
    eval {
        $cert->add_extension("subjectKeyIdentifier", undef);
        fail("should have thrown");
    };
    isnt($@, '', "... again!");
    eval {
        $cert->add_extension("crlNumber", 4);
    };
    like($@, qr/unknown|unsupported/i, <<WITTY_COMMENT);
You definitely shouldn't be able to set the crlNumber of a certificate.
WITTY_COMMENT
};

skip_next_test if cannot_check_bytes_leaks;
test "no leak on ->set_extension called multiple times" => sub {
    my $longstring = "00:DE:AD:BE:EF" x 200;
    my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
    leaks_bytes_ok {
        for (1..200) {
            $cert->set_extension("subjectKeyIdentifier", $longstring);
            $cert->sign($cakey, "sha1");
        }
    };
    leaks_bytes_ok {
        for (1..40) {
            for (1..5) {
                $cert->set_extension("subjectKeyIdentifier", $longstring);
                $cert->sign($cakey, "sha1");
            }
        }
    };
};

use Crypt::OpenSSL::CA::Test qw(@test_DN_CAs);
sub christmas_tree_ify {
    my ($cert) = @_;
    $cert->set_serial_hex("1234567890abcdef1234567890ABCDEF");

    $cert->set_subject_DN
        (Crypt::OpenSSL::CA::X509_NAME->new
         (CN => "coucou", "2.5.4.11.1.2.3.4" => "who cares?"));
    $cert->set_issuer_DN
        (Crypt::OpenSSL::CA::X509_NAME->new(@test_DN_CAs));

    $cert->set_notBefore("20060108000000Z");
    $cert->set_notAfter("21060108000000Z");
    $cert->set_extension("basicConstraints", "CA:FALSE",
                         -critical => 1);
    set_extensions_like_in_the_POD($cert); # Defined below
    # 'mkay, but if we want the path validation to succeed we'd better
    # use a non-deadbeef authority key id, so here we go again:
    my $keyid = Crypt::OpenSSL::CA::X509
        ->parse($test_self_signed_certs{"rsa1024"})
            ->get_public_key->get_openssl_keyid;
    $cert->set_extension("authorityKeyIdentifier_keyid", $keyid,
                         -critical => 0); # RFC3280 section 4.2.1.1

    $cert->set_extension
       (subjectAltName =>
        'email:johndoe@example.com,email:johndoe@example.net');
}

# christmas_tree_ify runs the POD snippets and that's neat, but we
# want to call Perl's eval only once for fear of memory leakage in
# Perl.
{
    my  $code = My::Tests::Below->pod_code_snippet
        ("set_extension subjectKeyIdentifier");
    $code .= My::Tests::Below->pod_code_snippet
        ("set_extension authorityKeyIdentifier");
    $code .= My::Tests::Below->pod_code_snippet
        ("set_extension certificatePolicies");
    eval <<"SUB_FROM_POD"; die $@ if $@;
sub set_extensions_like_in_the_POD {
    my (\$cert) = \@_;
    $code
}
SUB_FROM_POD
}

test "christmas tree certificate" => sub {
    my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
    christmas_tree_ify($cert);
    my $pem = $cert->sign($cakey, "sha1");
    certificate_looks_ok($pem);

    my $certdump = run_thru_openssl($pem, qw(x509 -noout -text));
    like($certdump, qr/12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF/i,
         "big hex serial");
    like($certdump, qr/Issuer:.*Widgits/, "issuer DN");
    like($certdump, qr/Subject:.*who cares/, "subject DN");
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
        (run_thru_openssl($pem, qw(x509 -outform der)));
    like($dumpasn1, qr/UTCTime.*2006.*\n.*GeneralizedTime.*2106/,
         "Proper detection of time format");
};

test "christmas tree validates OK in certificate chain" => sub {
    my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
    christmas_tree_ify($cert);
    my $pem = $cert->sign($cakey, "sha1");
    certificate_chain_ok($pem, [ $test_rootca_certs{rsa1024} ]);
};

skip_next_test if cannot_check_bytes_leaks;
test "X509 memory leaks" => sub {
    leaks_bytes_ok {
        for(1..100) {
            my $cert = Crypt::OpenSSL::CA::X509->new($eepubkey);
            for(1..200) { # Checks for robustness and leaks
                christmas_tree_ify($cert);
            }
            $cert->sign($cakey, "sha1");
        }
        for(1..100) {
            my $cert = Crypt::OpenSSL::CA::X509->parse
                ($test_self_signed_certs{rsa1024});
            for(1..200) {
                christmas_tree_ify($cert);
            }
            $cert->sign($cakey, "sha1");
        }
    };
};

=head2 Synopsis test

We only check that it runs.  Thorough black-box testing of
I<Crypt::OpenSSL::CA> happens in C<t/> instead.

=cut

test "synopsis" => sub {
    my $synopsis = My::Tests::Below->pod_code_snippet("synopsis");
    $synopsis = <<'PREAMBLE' . $synopsis;
my $pem_private_key = $test_keys_plaintext{rsa1024};
PREAMBLE
    eval $synopsis; die $@ if $@;
    pass;
};

=head2 Symbol leakage test

Validates that no symbols are leaked at the .so interface boundary, as
documented in L</the static-newline trick>.  This test must be kept
after all XS tests, as it needs all relevant .so modules loaded.

=cut

use DynaLoader;
test "symbol leak" => sub {
    is(DynaLoader::dl_find_symbol_anywhere($_), undef,
       "symbol $_ not visible")
        for(qw(sslcroak new load parse to_string to_asn1 sign DESTROY));
};

