#!/bin/sh
# Télécharge les PST/OST publics trop volumineux pour le dépôt dans tests/corpus/pst/large/,
# à des commits figés, et vérifie leur empreinte. Les tests qui en dépendent sont ignorés
# tant qu'ils sont absents. Usage : sh tests/corpus/pst/fetch.sh
set -eu
cd "$(dirname "$0")"
mkdir -p large
fetch() { # fichier url sha256
  if [ -f "large/$1" ] && echo "$3  large/$1" | sha256sum -c --status; then
    echo "ok        $1"; return
  fi
  echo "téléchargement $1"
  curl -fsSL --retry 3 -o "large/$1.part" "$2"
  echo "$3  large/$1.part" | sha256sum -c --status || { echo "EMPREINTE DIFFÉRENTE : $1" >&2; rm -f "large/$1.part"; exit 3; }
  mv "large/$1.part" "large/$1"
}
GO=https://raw.githubusercontent.com/mooijtech/go-pst/74d91fa0faec3830b4e2a6caa70df767d9656aed
JL=https://raw.githubusercontent.com/rjohnsondev/java-libpst/f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26
PE=https://raw.githubusercontent.com/epfromer/pst-extractor/7d08ef9bc7112c23275fa948306c76bba6e24fba
AM=https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/b26e860e0168a47870da9ce8e7681b87691c7ab7
fetch enron-29.pst          "$GO/data/enron.pst"                                    a59557b74f0dd72c421db9093084558f34e6fc00ee8cb0032f6475f6dd592252
fetch enron-14.pst          "$PE/src/__tests__/testdata/enron.pst"                  6152489de3472be6f1f840935d34b6dbf5f62b025dd015929ea9cf66eb5a5b46
fetch example-2013.ost      "$JL/src/test/resources/example-2013.ost"               b18ff390d0c22273029ee580ab6025976af69a4f84e276d1b1c01a988650853d
fetch outlook-com-a.ost     "$PE/src/__tests__/testdata/mtnman1965%40outlook.com.ost"     b884f6313e3507aaa38c1a70fecf2d9e4689923065a3324b61d4ae12887c862d
fetch outlook-com-b.ost     "$PE/src/__tests__/testdata/pstextractortest%40outlook.com.ost" daacd8d441428634e103b7c1e37fe1e5909256cc917551667049b5e84dfcf5f0
fetch gmail-takeout-56.pst  "$AM/Cloud/GoogleTakeout/PST/digitalforensicstestdata%40gmail.com/All_mail_Including_Spam_and_Trash_20241106_convertedWithAid4MailTrial.pst" 5b4efe643b271ad20f2a6525251ec1f59ca59c8a03d71832beacda2ac8bda296
