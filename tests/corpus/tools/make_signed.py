#!/usr/bin/env python3
"""Génère le corpus de messages signés (PGP/MIME, PGP inline, S/MIME) avec des clés jetables.

Aucune clé réelle : tout est créé à la volée. Les signatures ne sont pas déterministes ; le script
n'est relancé que pour reconstruire le corpus. Usage : python3 make_signed.py <dossier corpus>
"""
import base64, datetime, os, subprocess, sys, tempfile, textwrap
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs7

OUT = sys.argv[1]
EML, KEYS = os.path.join(OUT, "eml"), os.path.join(OUT, "keys")
os.makedirs(KEYS, exist_ok=True)
DATE = "Fri, 13 Nov 2026 10:00:00 +0000"
CRLF = "\r\n"


def crlf(s: str) -> bytes:
    return s.replace("\r\n", "\n").replace("\n", CRLF).encode()


def b64(b: bytes) -> str:
    return CRLF.join(textwrap.wrap(base64.b64encode(b).decode(), 76))


def headers(frm, subject, ctype, extra=""):
    return (
        f"Received: from mail.signed.example (mail.signed.example [198.51.100.20])\n"
        f"\tby mx.victim.example with ESMTPS id S1; {DATE}\n"
        f"Authentication-Results: mx.victim.example; spf=pass smtp.mailfrom={frm.split('@')[1].rstrip('>')}\n"
        f"From: {frm}\nTo: victim@victim.example\nSubject: {subject}\nDate: {DATE}\n"
        f"Message-ID: <{subject.split()[0].lower()}-{abs(hash(subject)) % 10**8}@signed.example>\n"
        f"MIME-Version: 1.0\nContent-Type: {ctype}\n{extra}\n"
    )


def write(name, data: bytes):
    with open(os.path.join(EML, name), "wb") as f:
        f.write(data)


PART = crlf(
    "Content-Type: text/plain; charset=utf-8\n"
    "Content-Transfer-Encoding: 8bit\n\n"
    "Bonjour,\n\nCi-joint la confirmation du virement de 1 250 € prévu le 20 novembre.\n\nAlice\n"
)
TAMPERED = PART.replace("1 250".encode(), "9 850".encode())

# ——— PGP ———
gh = tempfile.mkdtemp()
env = dict(os.environ, GNUPGHOME=gh)


def gpg(*args, data=None):
    return subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *args],
                          input=data, env=env, check=True, capture_output=True).stdout


gpg("--quick-gen-key", "Alice Martin <alice@signed.example>", "ed25519", "sign", "never")
gpg("--quick-gen-key", "Carol Inconnue <carol@unknown.example>", "rsa3072", "sign", "never")
open(os.path.join(KEYS, "alice-pgp.asc"), "wb").write(gpg("--armor", "--export", "alice@signed.example"))


def pgp_mime(part, signer):
    sig = gpg("--armor", "--detach-sign", "--digest-algo", "SHA256", "--local-user", signer, data=part)
    return sig


def pgp_message(frm, subject, part, sig):
    body = (crlf(headers(frm, subject, 'multipart/signed; micalg=pgp-sha256;\n\tprotocol="application/pgp-signature"; boundary="SIG"'))
            + b"--SIG\r\n" + part + b"\r\n--SIG\r\n"
            + crlf('Content-Type: application/pgp-signature; name="signature.asc"\nContent-Description: OpenPGP digital signature\n\n')
            + sig.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n") + b"\r\n--SIG--\r\n")
    return body


sig = pgp_mime(PART, "alice@signed.example")
write("pgp-signed-valid.eml", pgp_message("Alice Martin <alice@signed.example>", "Virement confirmé (PGP)", PART, sig))
write("pgp-signed-tampered.eml", pgp_message("Alice Martin <alice@signed.example>", "Virement modifié (PGP)", TAMPERED, sig))
write("pgp-signed-mismatch.eml", pgp_message("Bob Directeur <bob@other.example>", "Signé par une autre (PGP)", PART, sig))
write("pgp-signed-unknown-key.eml", pgp_message("Carol Inconnue <carol@unknown.example>", "Clé inconnue (PGP)",
                                                PART, pgp_mime(PART, "carol@unknown.example")))
clear = gpg("--clearsign", "--digest-algo", "SHA256", "--local-user", "alice@signed.example",
            data=crlf("Bonjour,\n\nMessage signé en clair (PGP inline).\n\nAlice\n"))
write("pgp-inline-valid.eml", crlf(headers("Alice Martin <alice@signed.example>", "Message en clair (PGP inline)",
                                          "text/plain; charset=utf-8", "Content-Transfer-Encoding: 7bit\n"))
      + clear.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))

# ——— S/MIME ———
now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MailForensics Test CA"),
                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corpus de test")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
      .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .sign(ca_key, hashes.SHA256()))
open(os.path.join(KEYS, "test-ca.pem"), "wb").write(ca.public_bytes(serialization.Encoding.PEM))


def leaf(email, key, start, end):
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email.split("@")[0].title()),
                                     x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
            .sign(ca_key, hashes.SHA256()))


d_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
d_cert = leaf("dana@signed.example", d_key, now, now + datetime.timedelta(days=730))
e_key = ec.generate_private_key(ec.SECP256R1())
e_cert = leaf("erin@signed.example", e_key,
              datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
              datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc))


def smime_detached(part, cert, key):
    return (pkcs7.PKCS7SignatureBuilder().set_data(part).add_signer(cert, key, hashes.SHA256())
            .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))


def smime_message(frm, subject, part, der):
    return (crlf(headers(frm, subject, 'multipart/signed; protocol="application/pkcs7-signature";\n\tmicalg=sha-256; boundary="SMIME"'))
            + b"--SMIME\r\n" + part + b"\r\n--SMIME\r\n"
            + crlf('Content-Type: application/pkcs7-signature; name="smime.p7s"\nContent-Transfer-Encoding: base64\n'
                   'Content-Disposition: attachment; filename="smime.p7s"\n\n')
            + b64(der).encode() + b"\r\n--SMIME--\r\n")


der = smime_detached(PART, d_cert, d_key)
write("smime-signed-valid.eml", smime_message("Dana Leroy <dana@signed.example>", "Virement confirmé (S/MIME)", PART, der))
write("smime-signed-tampered.eml", smime_message("Dana Leroy <dana@signed.example>", "Virement modifié (S/MIME)", TAMPERED, der))
write("smime-signed-expired.eml", smime_message("Erin Petit <erin@signed.example>", "Certificat expiré (S/MIME)", PART,
                                                smime_detached(PART, e_cert, e_key)))
opaque = (pkcs7.PKCS7SignatureBuilder().set_data(PART).add_signer(d_cert, d_key, hashes.SHA256())
          .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
write("smime-opaque-valid.eml", crlf(headers("Dana Leroy <dana@signed.example>", "Signature opaque (S/MIME)",
                                            'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"',
                                            'Content-Transfer-Encoding: base64\nContent-Disposition: attachment; filename="smime.p7m"\n'))
      + b64(opaque).encode() + b"\r\n")
print("corpus signé généré dans", OUT)
