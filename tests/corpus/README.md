# Corpus de référence

| Fichier | Origine | Licence | Rôle |
|---|---|---|---|
| `eml/phishing-basic.eml` | synthétique (projet) | MIT | RFC 2047, 2 `Received`, Reply-To divergent, PJ `.pdf.exe` |
| `eml/phishing-auth.eml` | synthétique (projet) | MIT | Authentication-Results (SPF softfail, DMARC fail), DKIM relaxed au bh valide, domaines sosies, punycode, lien texte ≠ cible, IP brute, user@hôte, PJ HTML et ZIP chiffré |
| `eml/quishing-html-attachment.eml` | synthétique (projet), généré par segno | MIT | QR codes (image `cid:` PNG et image `data:` JPEG), pièce jointe HTML avec formulaire chiffré en `atob()`, exfiltration Telegram, adresse du destinataire pré-remplie, liens Safe Links / Google / Bing |
| `eml/pgp-signed-valid.eml` | synthétique, `tools/make_signed.py` (gpg) | MIT | PGP/MIME signé par une clé ed25519 jetable (`keys/alice-pgp.asc`) |
| `eml/pgp-signed-tampered.eml` | idem | MIT | PGP/MIME, corps modifié après signature (montant changé) |
| `eml/pgp-signed-mismatch.eml` | idem | MIT | PGP/MIME valide, mais From ≠ email de la clé |
| `eml/pgp-signed-unknown-key.eml` | idem | MIT | PGP/MIME signé par une clé RSA non fournie |
| `eml/pgp-inline-valid.eml` | idem | MIT | PGP inline (clearsign) |
| `eml/smime-signed-valid.eml` | synthétique, `tools/make_signed.py` (cryptography) | MIT | S/MIME détaché RSA, certificat émis par `keys/test-ca.pem` |
| `eml/smime-signed-tampered.eml` | idem | MIT | S/MIME, corps modifié après signature |
| `eml/smime-signed-expired.eml` | idem | MIT | S/MIME ECDSA P-256, certificat expiré en 2021 |
| `eml/smime-opaque-valid.eml` | idem | MIT | S/MIME opaque (`application/pkcs7-mime`, smime.p7m) |

Les clés et certificats de `keys/` sont jetables, générés pour ce corpus ; aucune clé privée n'est conservée.
| `eml/remote-resources.eml` | synthétique (projet) | MIT | 9 ressources distantes de types variés (pixel, fonds, srcset, feuilles de style, @import, script, cadre), image `cid:` |
| `eml/html-links-inline.eml` | synthétique (projet) | MIT | liens HTML dupliqués, texte ≠ cible, pixel distant, image `cid:`, script |
| `nested/eml-in-eml.eml` | synthétique (projet) | MIT | `message/rfc822` imbriqué avec sa propre PJ et ses URL |
| `msg/ascii.msg`, `msg/unicode.msg`, `msg/attachment.msg`, `msg/test_email.msg` | jeu de test de [msg_parser](https://github.com/marirs/msg-parser-rs) | MIT | MSG ANSI / Unicode, PJ, MSG embarqués (objet et fichier `.msg` joint) |
| `malformed/not-an-email.bin` | synthétique | MIT | format inconnu |
| `malformed/truncated.msg` | 600 premiers octets de `ascii.msg` | MIT | OLE tronqué |

Ne jamais ajouter ici de preuve réelle issue d'un dossier client.


Les boîtes PST/OST sont décrites dans [`pst/README.md`](pst/README.md).
