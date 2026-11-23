"""E2E de la version web (specs/003-web-version, tâches W008, W009, W014).

Prérequis : `npm run build:web`, `cargo build -p mf-cli`, `pip install playwright && playwright install chromium`.
Lancement : `npm run test:web` (depuis apps/desktop).

Vérifie, dans un vrai navigateur :
- dépôt de fichiers, liste, fichier illisible, doublon ;
- concordance avec `mf show --json` (empreintes, en-têtes, fichiers, URL) pour chaque fichier ;
- bouton / touche H, ouverture d'un message joint ;
- aucune requête réseau après le chargement du moteur, et fonctionnement hors-ligne.
"""

import functools
import hashlib
import http.server
import json
import pathlib
import subprocess
import sys
import threading

from playwright.sync_api import sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
APP = HERE.parent
ROOT = APP.parent.parent
DIST = APP / "dist-web"
CORPUS = ROOT / "tests" / "corpus"
MF = ROOT / "target" / "debug" / "mf"

MAILS = sorted(p for p in CORPUS.glob("*/*") if p.suffix in (".eml", ".msg") and p.parent.name != "malformed")
BROKEN = CORPUS / "malformed" / "truncated.msg"
SUPPORT_PST = CORPUS / "pst" / "support.pst"
ENRON_PST = CORPUS / "pst" / "large" / "enron-29.pst"

failures: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("ok    " if cond else "ÉCHEC ") + what)
    if not cond:
        failures.append(what)


def cli(path: pathlib.Path) -> tuple[dict, dict]:
    ev = json.loads(subprocess.check_output([MF, "hash", "--json", path]))[0]
    msg = json.loads(subprocess.check_output([MF, "show", "--json", path]))
    return ev, msg


def mf_pst(*args: object) -> object:
    return json.loads(subprocess.check_output([MF, "--json", "pst", *map(str, args)]))


def check_box(page, path: pathlib.Path, folder_name: str) -> None:
    """Boîte PST dans le navigateur (feature 002, P030) : mêmes résultats que la CLI."""
    import time

    tree = mf_pst("tree", path)
    folder = next(f for f in tree if f["name"] == folder_name and f["item_count"])
    rows = mf_pst("ls", "--folder", folder["id"], path)
    name = path.name
    t0 = time.monotonic()
    with page.expect_file_chooser() as fc:
        page.click("#open-files")
    fc.value.set_files(str(path))
    page.wait_for_selector(".box-head .box-title", timeout=30000)
    opened = time.monotonic() - t0
    check(name in page.locator(".box-head").inner_text(), f"{name} : boîte ouverte en {opened:.2f} s, arborescence affichée")
    check("0 élément(s) lu(s)" in page.locator(".box-read").inner_text(), f"{name} : aucun élément lu à l'ouverture")
    # Plusieurs dossiers peuvent porter le même nom : on désigne celui de la CLI par son chemin.
    title = " › ".join(folder["path"]).replace('"', '\\"')
    row = page.locator(f'.folder-row[title="{title}"]')
    check(row.locator(".folder-count").inner_text() == str(folder["item_count"]), f"{name} : {folder_name} = {folder['item_count']} éléments (CLI)")
    row.click()
    page.wait_for_selector(".box-row")
    first = page.locator(".box-row").first
    shown = first.locator(".subject").inner_text()
    ordered = sorted(rows, key=lambda r: r.get("received") or r.get("sent") or "", reverse=True)
    check(shown == ((ordered[0].get("subject") or "").strip() or "(sans objet)"), f"{name} : première ligne = « {shown[:50]} »")
    first.click()
    page.wait_for_selector(".reading-main", timeout=30000)
    item = mf_pst("show", "--id", ordered[0]["id"], path)
    crumbs = page.locator(".breadcrumb").inner_text()
    check(name in crumbs and folder_name in crumbs, f"{name} : provenance « {crumbs.replace(chr(10), ' ')} »")
    names = [n.inner_text() for n in page.locator(".inventory .file-name").all()]
    check(names == [a["filename"] for a in item["message"]["attachments"]], f"{name} : pièces jointes identiques à la CLI {names}")
    check("1 élément(s) lu(s)" in page.locator(".box-read").inner_text(), f"{name} : seul l'élément cliqué est lu")
    with_att = next((i for i, r in enumerate(ordered[:20]) if r.get("has_attachments")), None)
    if with_att is not None:
        page.locator(".box-row").nth(with_att).click()
        page.wait_for_selector(".inventory button.download", timeout=30000)
        att = mf_pst("show", "--id", ordered[with_att]["id"], path)["message"]["attachments"][0]
        page.once("dialog", lambda d: d.accept())
        with page.expect_download() as dl:
            page.locator(".inventory button.download").first.click()
        got = hashlib.sha256(pathlib.Path(dl.value.path()).read_bytes()).hexdigest()
        check(got == att["sha256"], f"{name} : pièce jointe « {att['filename']} » téléchargée, SHA-256 identique")
    # Recherche sur toute la boîte (FR-007) : mêmes résultats que `mf pst ls --text`, rien de lu.
    word = (ordered[0].get("subject") or "").split()[0] if (ordered[0].get("subject") or "").split() else "a"
    want = mf_pst("ls", "--text", word, path)
    read_before = page.locator(".box-read").inner_text()
    page.fill(".box-search", word)
    page.wait_for_selector(".box-results", timeout=15000)
    check(f"{len(want)} résultat(s)" in page.locator(".box-results").inner_text(), f"{name} : recherche « {word} » = {len(want)} résultat(s), comme la CLI")
    check(page.locator(".box-read").inner_text() == read_before, f"{name} : la recherche ne lit aucun élément")
    # Filtres : pièces jointes + « analysés seulement ».
    page.click(".box-tools button:has-text('Filtres')")
    page.fill(".box-search", "")
    page.wait_for_selector(".box-results", state="detached", timeout=15000)
    with_atts = mf_pst("ls", "--attachments", path)
    page.select_option("select[data-keep='has_attachments']", "yes")
    page.wait_for_selector(".box-results", timeout=15000)
    check(f"{len(with_atts)} résultat(s)" in page.locator(".box-results").inner_text(), f"{name} : filtre « avec pièces jointes » = {len(with_atts)}, comme la CLI")
    # Deux critères saisis coup sur coup se cumulent (nom d'expéditeur + pièces jointes).
    sender = next((r["from_name"] for r in with_atts if r.get("from_name")), None)
    if sender:
        word = sender.split()[0]
        both = mf_pst("ls", "--attachments", "--from-name", word, path)
        page.fill("input[data-keep='from_name']", word)
        page.press("input[data-keep='from_name']", "Enter")
        page.wait_for_selector(f".box-results:has-text('{len(both)} résultat(s)')", timeout=15000)
        check("Filtres (2)" in page.locator(".box-tools").first.inner_text(), f"{name} : expéditeur « {word} » + pièces jointes = {len(both)}, comme la CLI")
        page.fill("input[data-keep='from_name']", "")
        page.press("input[data-keep='from_name']", "Enter")
    page.select_option("select[data-keep='has_attachments']", "")
    page.wait_for_selector(".box-results", state="detached", timeout=15000)
    page.click(".filter-opened summary")
    page.check("input[data-keep='analyzed_only']")
    page.wait_for_selector(".box-results:has-text('résultat')", timeout=15000)
    n_read = 2 if with_att is not None else 1
    check(f"{n_read} résultat(s)" in page.locator(".box-results").inner_text(), f"{name} : « analysés seulement » = {n_read} élément(s) ouverts")
    check(page.locator(".box-row .verdict-pill").count() == n_read, f"{name} : verdict affiché sur les éléments analysés")
    with page.expect_download() as dl:
        page.click(".box-iocs button:has-text('CSV')")
    csv = pathlib.Path(dl.value.path()).read_text(encoding="utf-8-sig")
    check(csv.startswith("type,valeur,sources") and (csv.count("\n") <= 1 or f"{name} ›" in csv), f"{name} : indicateurs des éléments analysés exportés avec provenance")
    page.uncheck("input[data-keep='analyzed_only']")
    page.wait_for_selector(".box-results", state="detached", timeout=15000)
    page.click(".box-tools button:has-text('Filtres')")
    sha = mf_pst("info", path)["hash"]["sha256"]
    page.wait_for_selector(f".box-hash[title*='{sha}']", timeout=60000)
    check(True, f"{name} : empreinte SHA-256 de la boîte identique à la CLI")
    page.click(".box-back")
    page.click(".box-back")
    page.wait_for_selector(".box-entry")


def serve() -> str:
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

    handler = functools.partial(Quiet, directory=str(DIST))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/"


def main() -> int:
    if not DIST.joinpath("index.html").exists():
        print("dist-web/ absent : lancer `npm run build:web`")
        return 2
    url = serve()
    expected = {p.name: cli(p) for p in MAILS}

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 920}, accept_downloads=True)
        page = ctx.new_page()
        requests: list[str] = []
        page.on("request", lambda r: requests.append(r.url))
        ctx.on("request", lambda r: requests.append(r.url))
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        page.goto(url)
        # Attente par sélecteur : la CSP de la page interdit l'évaluation de code (wait_for_function).
        page.wait_for_selector("html[data-engine]", state="attached")
        check(all(r.startswith(url) for r in requests), f"chargement : uniquement la même origine ({len(requests)} ressources)")
        requests.clear()  # à partir d'ici, plus aucune requête n'est admise (FR-W02)

        # Dépôt via le sélecteur de fichiers (même chemin de code que le glisser-déposer).
        with page.expect_file_chooser() as fc:
            page.click("#open-files")
        fc.value.set_files([str(p) for p in MAILS] + [str(BROKEN)])
        page.wait_for_selector(".message-item.failed")
        items = page.locator(".message-item:not(.failed)")
        check(items.count() == len(MAILS), f"{len(MAILS)} messages listés")
        check("Illisible" in page.locator(".message-item.failed").inner_text(), "fichier OLE tronqué listé en erreur")

        # Concordance avec la CLI pour chaque message.
        for i in range(items.count()):
            items.nth(i).click()
            page.wait_for_selector(".seal-file")
            name = page.locator(".seal-file").inner_text().split(" — ")[0]
            ev, msg = expected[name]
            seal = page.locator(".seal").inner_text()
            check(ev["sha256"] in seal and ev["md5"] in seal, f"{name} : SHA-256 et MD5 identiques à la CLI")
            btn = page.locator(".header-toggle-row button").first.inner_text()
            check(f"({len(msg['headers'])})" in btn, f"{name} : {len(msg['headers'])} en-têtes")
            files = page.locator(".inventory section.files")
            names = files.locator(".file-name").all_inner_texts()
            check(names == [a["filename"] for a in msg["attachments"]], f"{name} : fichiers contenus {names}")
            hashes = files.locator(".file-hash").all_inner_texts()
            check(all(a["sha256"] in h for a, h in zip(msg["attachments"], hashes)), f"{name} : SHA-256 des fichiers")
            check(all(a["md5"] in h for a, h in zip(msg["attachments"], hashes)), f"{name} : MD5 visibles sans survol")
            urls = page.locator(".inventory section.urls > ul > li > .url-text").all_inner_texts()
            # FR-042 : panneau d'acheminement au-dessus des fichiers, expéditeur en titre.
            route = msg.get("route") or {}
            check(page.locator(".inventory > section").first.get_attribute("class") == "route", f"{name} : acheminement en tête du panneau")
            if route.get("sender"):
                check(page.locator(".route-title").inner_text() == route["sender"], f"{name} : titre = {route['sender']}")
            origin = (route.get("origin") or {}).get("ip")
            if origin:
                check(origin in page.locator(".route").inner_text(), f"{name} : IP d'envoi {origin} affichée")
            check(urls == [u["url"] for u in msg["urls"]], f"{name} : {len(urls)} URL identiques")

        # FR-041 : HTML reconstitué depuis le RTF d'un .msg.
        page.locator(".message-item", has_text="Test for TIF").click()
        page.wait_for_selector(".body-frame")
        check("RTF Outlook" in page.locator(".body-tabs").inner_text(), "MSG : HTML reconstitué depuis le RTF, provenance indiquée")
        check("This is a test email" in page.frame_locator(".body-frame").locator("body").inner_text(), "MSG : rendu HTML affiché")
        page.click("text=Plein écran")
        check(page.locator(".fullscreen .body-frame").count() == 1, "plein écran ouvert")
        page.keyboard.press("Escape")
        check(page.locator(".fullscreen").count() == 0, "Échap ferme le plein écran")
        r = page.locator(".route").inner_text()
        check("209.85.220.182" in r and "mail-vc0-f182.google.com" in r and "ms06561.mac.com" in r, "MSG : IP/DNS d'envoi et serveur de réception")

        # FR-040 : thème clair / sombre mémorisé.
        page.click(".theme-toggle")
        page.click(".theme-toggle")
        check(page.locator("html").get_attribute("data-theme") == "dark", "thème sombre appliqué")
        page.click(".theme-toggle")
        check(page.locator("html").get_attribute("data-theme") is None, "retour au thème automatique")

        # FR-038 : téléchargement avec boîte de confirmation.
        page.locator(".message-item", has_text="Urgent : mot de passe").click()
        page.wait_for_selector("button.download")
        seen: list[str] = []
        downloads: list[object] = []
        page.on("download", lambda d: downloads.append(d))

        def refuse(d):
            seen.append(d.message)
            d.dismiss()

        page.once("dialog", refuse)
        page.click("button.download")
        page.wait_for_timeout(800)
        check(bool(seen) and "facture.pdf.exe" in seen[0] and "malveillant" in seen[0], "confirmation : nom et avertissement affichés")
        check("34b9348ecccb09747637e5bdaa744e48362a9e684b260766e49868f2e50cecab" in (seen[0] if seen else ""), "confirmation : SHA-256 affiché")
        check(not downloads, "Annuler : aucun fichier téléchargé")
        page.once("dialog", lambda d: d.accept())
        with page.expect_download() as dl:
            page.click("button.download")
        saved = dl.value.path()
        digest = hashlib.sha256(pathlib.Path(saved).read_bytes()).hexdigest()
        check(dl.value.suggested_filename == "facture.pdf.exe", f"OK : fichier proposé « {dl.value.suggested_filename} »")
        check(digest == "34b9348ecccb09747637e5bdaa744e48362a9e684b260766e49868f2e50cecab", "OK : SHA-256 du fichier téléchargé identique")
        page.locator(".message-item", has_text="Test Email").click()
        check(page.locator("button.download").nth(0).is_disabled(), "objet MAPI embarqué : téléchargement indisponible")
        check(page.locator("button.download").nth(2).is_enabled(), ".msg joint : téléchargeable")

        # Bouton des en-têtes (touche H) sur le message de phishing.
        page.locator(".message-item", has_text="Urgent : mot de passe").click()
        page.keyboard.press("h")
        rows = page.locator(".headers-panel li")
        check(rows.count() == len(expected["phishing-basic.eml"][1]["headers"]), "touche H : tous les en-têtes dépliés")
        check(rows.nth(0).inner_text().startswith("1\nReceived:") or "Received:" in rows.nth(0).inner_text(), "premier en-tête = Received")
        page.screenshot(path=str(APP / "test-results" / "web-entetes.png"))

        # Message joint : test_email.msg › PJ 3 (fichier .msg joint).
        page.locator(".message-item", has_text="Test Email").click()
        page.locator("button.open-embedded").nth(1).click()
        check("PJ 3" in page.locator(".breadcrumb").inner_text(), "message joint ouvert avec fil d'Ariane")
        check(page.locator(".inventory .file-name").count() == 2, "message joint : 2 fichiers contenus")
        page.keyboard.press("Escape")
        check(page.locator(".breadcrumb").count() == 0, "Échap revient au message parent")

        # FR-013 à FR-023, FR-043, FR-044 : analyse, rapport et indicateurs, sans réseau.
        page.locator(".message-item", has_text="boite Microsoft 365").click()
        page.wait_for_selector("section.analysis")
        check(page.locator("section.verdict.v-malicious").is_visible() and "malveillant" in page.locator(".verdict-level").inner_text().lower(), "verdict : malveillant")
        check("imitant « microsoft »" in page.locator(".verdict-reasons").inner_text(), "verdict : raisons affichées")
        check(page.locator(".message-item", has_text="boite Microsoft 365").locator(".verdict-pill.v-malicious").count() == 1, "pastille de verdict dans la liste")
        auth = page.locator(".auth-row").inner_text()
        check("SPF" in auth and "softfail" in auth and "DMARC" in auth and "fail" in auth, f"puces SPF/DKIM/DMARC ({auth!r})")
        check("corps intact" in page.locator("section.analysis").inner_text(), "DKIM : empreinte du corps recalculée et intacte")
        fx = page.locator("section.analysis").inner_text()
        check("imitant « microsoft »" in fx, "constat : expéditeur sosie de microsoft")
        check("user@hôte" in fx, "constat : lien user@hôte")
        check(page.locator(".finding .sev-high").count() >= 4, "au moins 4 constats élevés")
        files_txt = page.locator(".inventory section.files").inner_text()
        check("chiffr" in files_txt.lower() and "HTML" in files_txt, "badges des pièces jointes (archive chiffrée, HTML)")
        check("pаypal.example" in page.locator(".inventory").inner_text(), "URL : domaine Unicode réel affiché")
        page.screenshot(path=str(APP / "test-results" / "web-analyse.png"), full_page=False)
        check(page.locator(".export-all").inner_text() == "Télécharger tous les indicateurs", "libellé du bouton d'export global")
        page.locator(".reading-grid > .inventory").hover()
        page.mouse.wheel(0, 1200)
        page.wait_for_timeout(300)
        check(page.locator(".reading-main").evaluate("e => e.scrollTop") == 0 and page.locator(".reading-grid > .inventory").evaluate("e => e.scrollTop") > 0, "panneau de droite : défilement indépendant du corps")
        check(page.locator(".inventory > .seal").count() == 1 and page.locator(".reading-main .seal").count() == 0, "empreintes de la preuve en tête du panneau de droite")
        page.click(".analysis-toggle")
        check(page.locator(".analysis-body").is_hidden() and page.locator(".analysis-head .sev-high").is_visible(), "Replier : constats masqués, compteurs visibles")
        page.locator(".message-item", has_text="Votre colis").click()
        page.wait_for_selector("section.analysis")
        check(page.locator(".analysis-body").is_hidden(), "état replié conservé d'un message à l'autre")
        page.locator(".message-item", has_text="boite Microsoft 365").click()
        page.wait_for_selector("section.analysis")
        page.click(".analysis-toggle")
        check(page.locator(".analysis-body").is_visible(), "Déplier : constats affichés")
        for fmt, sel in (("html", ".report-html"), ("json", ".report-json")):
            with page.expect_download() as dl:
                page.click(sel)
            body = pathlib.Path(dl.value.path()).read_text(encoding="utf-8")
            check(dl.value.suggested_filename.endswith(f".{fmt}"), f"rapport {fmt} : {dl.value.suggested_filename}")
            if fmt == "html":
                check("Verdict : MALVEILLANT" in body, "rapport HTML : verdict")
                check("default-src 'none'" in body and "micros0ft-security[.]example" in body, "rapport HTML autonome, indicateurs défangés")
                (APP / "test-results" / "rapport.html").write_text(body, encoding="utf-8")
            else:
                rep = json.loads(body)
                check(rep["evidence"]["sha256"] == expected["phishing-auth.eml"][0]["sha256"], "rapport JSON : SHA-256 de la preuve")
                check(rep["findings_summary"]["high"] >= 4, "rapport JSON : synthèse des constats")
                check(rep["verdict"]["level"] == "malicious", "rapport JSON : verdict")
        with page.expect_download() as dl:
            page.click(".ioc-csv")
        csv = pathlib.Path(dl.value.path()).read_text(encoding="utf-8-sig")
        check("198.51.100.77" in csv and "micros0ft-security" in csv, "export CSV des indicateurs")
        with page.expect_download() as dl:
            page.click(".export-all")
        allcsv = pathlib.Path(dl.value.path()).read_text(encoding="utf-8-sig")
        check(allcsv.count("\n") > csv.count("\n"), "export des indicateurs de tous les messages")

        # FR-046 à FR-048 : QR codes, page HTML jointe, redirections décodées.
        page.locator(".message-item", has_text="Contrat_2026").click()
        page.wait_for_selector("section.verdict.v-malicious")
        inv = page.locator(".inventory").inner_text()
        check("quish-m365.example/scan" in page.locator("section.files").inner_text(), "QR code de l'image jointe décodé")
        check("QR code dans l'image n° 1 intégrée au HTML" in inv, "QR code d'une image data: décodé")
        rep = page.locator(".html-report").inner_text()
        check("collect.evil-kit.example/next.php" in rep and "bot Telegram" in rep, "page HTML jointe : formulaire et exfiltration")
        check("victim@victim.example" in rep, "page HTML jointe : destinataire pré-rempli")
        check("Redirecteur détourné (Bing)" in inv and "login.evil-kit.example/auth" in inv, "redirection Bing décodée")
        check("Lien réécrit (Microsoft Safe Links)" in inv, "Safe Links décodé")
        check(page.locator(".finding", has_text="Texte du lien différent").count() == 0, "Safe Links : pas de faux « texte ≠ destination »")
        page.locator("section.files").scroll_into_view_if_needed()
        page.screenshot(path=str(APP / "test-results" / "web-quishing.png"))

        # FR-049 à FR-051 : signatures PGP / S/MIME, trousseau local, liens externes.
        def open_msg(subject: str) -> None:
            page.locator(".message-item", has_text=subject).click()
            page.wait_for_selector("section.signatures")

        open_msg("Virement confirmé (PGP)")
        check("Clé inconnue" in page.locator(".sig-status").inner_text(), "PGP sans clé importée : « clé inconnue »")
        check(page.locator(".message-item", has_text="Virement confirmé (PGP)").locator(".verdict-pill.v-suspicious").count() == 1, "sans clé : jamais « légitime »")
        # Lien externe : la confirmation est refusée (Playwright rejette les boîtes) → rien n'est ouvert.
        pages_before = len(ctx.pages)
        page.locator(".ext-link").first.click()
        page.wait_for_timeout(300)
        check(len(ctx.pages) == pages_before, "lien externe : rien n'est ouvert sans confirmation")
        with page.expect_file_chooser() as fc:
            page.click(".import-keys")
        fc.value.set_files([str(CORPUS / "keys" / "alice-pgp.asc"), str(CORPUS / "keys" / "test-ca.pem")])
        page.wait_for_selector(".sig-status:has-text('Signature valide')")
        sig = page.locator("section.signatures").inner_text()
        check("Alice Martin" in sig and "correspond à l'email de la clé" in sig, "PGP valide après import, signataire = expéditeur")
        check(page.locator(".message-item", has_text="Virement confirmé (PGP)").locator(".verdict-pill.v-legitimate").count() == 1, "verdict « légitime » après vérification")
        check("Signature PGP valide" in page.locator(".verdict-reasons").inner_text(), "verdict fondé sur la signature")
        check("Clés et certificats (2)" in page.locator(".keys-button").inner_text(), "trousseau : 2 entrées")
        page.screenshot(path=str(APP / "test-results" / "web-signature.png"))
        open_msg("Virement modifié (PGP)")
        check("Signature invalide" in page.locator(".sig-status").inner_text(), "PGP : corps modifié détecté")
        open_msg("Signé par une autre (PGP)")
        check("ne correspond pas" in page.locator("section.signatures").inner_text(), "PGP : signataire ≠ expéditeur")
        open_msg("Virement confirmé (S/MIME)")
        sig = page.locator("section.signatures").inner_text()
        check("Signature valide" in sig and "rattaché à une autorité importée" in sig, "S/MIME valide, autorité importée")
        open_msg("Virement modifié (S/MIME)")
        check("Signature invalide" in page.locator(".sig-status").inner_text(), "S/MIME : corps modifié détecté")
        open_msg("Certificat expiré (S/MIME)")
        check("expiré à la date de signature" in page.locator("section.signatures").inner_text(), "S/MIME : certificat expiré")
        open_msg("Signature opaque (S/MIME)")
        check("Signature valide" in page.locator(".sig-status").inner_text(), "S/MIME opaque (.p7m) vérifiée")
        page.click(".keys-button")
        page.wait_for_selector("dialog.key-dialog[open]")
        check(page.locator(".key-list li").count() == 2 and "MailForensics Test CA" in page.locator(".key-list").inner_text(), "gestionnaire de clés : liste")
        page.screenshot(path=str(APP / "test-results" / "web-trousseau.png"))
        page.click(".key-close")

        # Hors-ligne : un nouveau dépôt fonctionne toujours (doublon détecté).
        ctx.set_offline(True)
        with page.expect_file_chooser() as fc:
            page.click("#open-files")
        fc.value.set_files([str(MAILS[0])])
        page.wait_for_selector("#list-status:has-text('doublon')")
        check(True, "hors-ligne : analyse toujours possible (doublon signalé)")

        page.locator(".message-item", has_text="Votre relevé").click()
        page.wait_for_selector(".body-frame")
        page.wait_for_timeout(500)
        check("1 ressource distante bloquée" in page.locator(".blocked-panel summary").inner_text(), "pixel de suivi bloqué et compté")
        page.screenshot(path=str(APP / "test-results" / "web-lecture.png"))

        # FR-039 : détail et localisation des ressources bloquées.
        page.locator(".message-item", has_text="Votre colis").click()
        page.wait_for_selector(".body-frame")
        page.click(".blocked-panel summary")
        items = page.locator(".blocked-list > li")
        check(items.count() == 9, f"9 ressources détaillées ({items.count()})")
        last = items.nth(8).inner_text()
        check("t.mailtrack.example/open" in last and "ligne 17" in last and "<img src>" in last, "pixel : URL, élément et ligne affichés")
        frame = page.frame_locator(".body-frame")
        check(frame.locator(".mf-badge").count() == 4, "4 repères visibles dans le rendu")
        items.nth(8).get_by_role("button", name="Voir dans le rendu").click()
        page.wait_for_timeout(600)
        check(frame.locator("img.mf-flash").count() == 1, "« Voir dans le rendu » met en évidence le pixel")
        page.screenshot(path=str(APP / "test-results" / "web-bloquees-rendu.png"))
        page.locator(".blocked-list > li").nth(7).get_by_role("button", name="Voir dans la source").click()
        page.wait_for_selector(".html-source li.mf-flash")
        check(page.locator(".html-source li.mf-flash").get_attribute("data-line") == "16", "« Voir dans la source » atteint la ligne 16 (iframe)")
        check(page.locator(".html-source li.has-blocked").count() == 8, "8 lignes du HTML portent une ressource bloquée")
        page.screenshot(path=str(APP / "test-results" / "web-bloquees-source.png"))
        tagged = page.locator(".tag-blocked").count()
        check(tagged == 9, f"liste des URL : 9 URL marquées « chargement bloqué » ({tagged})")
        page.locator(".body-tabs button", has_text="HTML").first.click()

        # Boîtes PST : ouverture dans le navigateur, lecture par tranches du fichier.
        check_box(page, SUPPORT_PST, "Drafts")
        if ENRON_PST.exists():
            check_box(page, ENRON_PST, "Sent Items")
        page.screenshot(path=str(APP / "test-results" / "web-pst.png"))

        check(not requests, f"aucune requête réseau après le chargement (vu : {requests[:3]})")
        check(not errors, f"aucune erreur JavaScript ({errors[:2]})")

        # Le trousseau est mémorisé sur le poste et réimporté au rechargement.
        ctx.set_offline(False)
        page.reload()
        page.wait_for_selector("html[data-engine]", state="attached")
        page.wait_for_selector(".keys-button:has-text('(2)')", timeout=10000)
        check(True, "trousseau réimporté après rechargement")
        browser.close()

    print(f"\n{len(failures)} échec(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    (APP / "test-results").mkdir(exist_ok=True)
    sys.exit(main())
