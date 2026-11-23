//! Contrat CLI `mf pst` (specs/002-pst-support/contracts/cli.md) sur `support.pst`.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

fn mf(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_mf"))
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

fn support() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/corpus/pst/support.pst")
        .display()
        .to_string()
}

#[test]
fn info_tree_ls_show_json() {
    let f = support();
    let (code, out, _) = mf(&["pst", "info", &f, "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["store"]["format"], "unicode");
    assert_eq!(v["store"]["items"], 17);
    assert_eq!(
        v["hash"]["sha256"],
        "5872c9aec2e0aacd0f793f3ffa2a7e85eba1d873a1d2659fb01019d4de197a1c"
    );
    assert_eq!(v["items_read"], 0, "info ne lit aucun élément");

    let (_, out, _) = mf(&["pst", "tree", &f, "--json"]);
    let tree: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    let drafts = tree.iter().find(|d| d["name"] == "Drafts").unwrap();
    assert_eq!(drafts["item_count"], 6);

    let (code, out, err) = mf(&["pst", "ls", &f, "--folder", "Drafts", "--json"]);
    assert_eq!(code, 0, "{err}");
    let rows: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(rows.len(), 6);
    let id = rows[0]["id"].as_u64().unwrap().to_string();

    let (code, out, err) = mf(&["pst", "show", &f, "--id", &id, "--json"]);
    assert_eq!(code, 0, "{err}");
    let a: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        a["message"]["provenance"]["folder_path"],
        serde_json::json!(["Drafts"])
    );
    assert!(a["message"]["verdict"].is_object());
}

#[test]
fn ls_whole_box_reads_no_item_and_report_refuses_evidence_dir() {
    let f = support();
    let (code, _, err) = mf(&["pst", "ls", &f]);
    assert_eq!(code, 0);
    assert!(err.contains("17 élément(s) ; éléments lus : 0"), "{err}");
    let (_, out, _) = mf(&["pst", "ls", &f, "--json"]);
    let rows: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    let id = rows[0]["id"].as_u64().unwrap().to_string();
    let inside = PathBuf::from(&f).with_file_name("rapport-interdit.html");
    let (code, _, err) = mf(&[
        "pst",
        "report",
        &f,
        "--id",
        &id,
        "--out",
        &inside.display().to_string(),
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("dossier de la preuve"), "{err}");
    assert!(!inside.exists());
    let out = std::env::temp_dir().join(format!("mf-pst-report-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&out);
    let (code, _, err) = mf(&[
        "pst",
        "report",
        &f,
        "--id",
        &id,
        "--format",
        "json",
        "--out",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    let r: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(
        r["evidence"]["sha256"],
        "5872c9aec2e0aacd0f793f3ffa2a7e85eba1d873a1d2659fb01019d4de197a1c"
    );
    assert!(
        r["provenance"].as_str().unwrap().contains("support.pst"),
        "{}",
        r["provenance"]
    );
    std::fs::remove_file(&out).unwrap();
}

#[test]
fn ls_filters_and_iocs() {
    let f = support();
    let count = |extra: &[&str]| -> usize {
        let mut args = vec!["--json", "pst", "ls", &f];
        args.extend_from_slice(extra);
        let (code, out, err) = mf(&args);
        assert_eq!(code, 0, "{extra:?} : {err}");
        assert!(err.contains("éléments lus : 0") || err.is_empty(), "{err}");
        serde_json::from_str::<Vec<serde_json::Value>>(&out)
            .unwrap()
            .len()
    };
    assert_eq!(count(&[]), 17);
    assert_eq!(count(&["--folder", "Drafts"]), 6);
    assert_eq!(count(&["--attachments"]), 1);
    assert_eq!(count(&["--no-attachments"]), 16);
    // Période : journée incluse ; 2015 = 9 éléments (voir la liste de la boîte).
    assert_eq!(
        count(&["--after", "2015-01-01", "--before", "2015-12-31"]),
        9
    );
    assert_eq!(
        count(&["--after", "2015-02-02", "--before", "2015-02-02"]),
        6
    );
    assert_eq!(
        count(&["--from-name", "rcs SUPPORT", "--min-size", "60000"]),
        5
    );
    assert_eq!(count(&["--from-name", "personne"]), 0);
    let (code, _, err) = mf(&["pst", "ls", &f, "--after", "hier"]);
    assert_ne!(code, 0);
    assert!(err.contains("AAAA-MM-JJ"));

    // Indicateurs des seuls éléments désignés, avec provenance.
    let (_, out, _) = mf(&["--json", "pst", "ls", &f, "--folder", "Drafts"]);
    let rows: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    let ids: Vec<String> = rows.iter().take(2).map(|r| r["id"].to_string()).collect();
    let (code, out, err) = mf(&[
        "pst",
        "iocs",
        &f,
        "--id",
        &ids.join(","),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("éléments lus : 2"), "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let text = v.to_string();
    assert!(text.contains("support.pst › Drafts › élément #"), "{text}");
}

#[test]
fn export_msg_and_eml() {
    let f = support();
    let tmp = std::env::temp_dir().join(format!("mf-cli-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let out = tmp.join("msg");
    let o = out.to_str().unwrap();
    let (code, stdout, err) = mf(&[
        "--json", "pst", "export", &f, "--folder", "Drafts", "--out", o,
    ]);
    assert_eq!(code, 0, "{err}");
    let m: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(m["items"].as_array().unwrap().len(), 6);
    assert_eq!(m["store"]["verified"], true);
    assert_eq!(
        m["store"]["sha256"],
        "5872c9aec2e0aacd0f793f3ffa2a7e85eba1d873a1d2659fb01019d4de197a1c"
    );
    // 6 fichiers + manifeste JSON et CSV ; chaque fichier se rouvre avec `mf show`.
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 8);
    for it in m["items"].as_array().unwrap() {
        let p = out.join(it["file"].as_str().unwrap());
        let (code, _, err) = mf(&["show", p.to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
    }
    // Destination non vide : refus, rien d'écrit.
    let (code, _, err) = mf(&["pst", "export", &f, "--folder", "Drafts", "--out", o]);
    assert_ne!(code, 0);
    assert!(err.contains("n'est pas vide"), "{err}");
    // .eml reconstruit, marqué comme tel.
    let out = tmp.join("eml");
    let (code, _, err) = mf(&[
        "pst",
        "export",
        &f,
        "--subject",
        "downtime",
        "--format",
        "eml",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    let eml = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.path().extension().is_some_and(|x| x == "eml"))
        .unwrap();
    let text = std::fs::read_to_string(eml.path()).unwrap();
    assert!(text.contains("X-MailForensics-Reconstructed: pst"));
    // Sans désignation : refus.
    let (code, _, err) = mf(&[
        "pst",
        "export",
        &f,
        "--out",
        tmp.join("rien").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("préciser les éléments"), "{err}");
    std::fs::remove_dir_all(&tmp).unwrap();
}
