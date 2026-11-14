//! MOVEMENT: applies the 8 original .reg files (embedded byte-for-byte) exactly as written, in file order 1..8,
//! only the operations the user confirmed, after a backup of the previous state (including "did not exist").
use crate::assess::{assess, detect_conflicts, max_level, Conflict, Finding, Level};
use crate::regfile::{parse, render_value, Hive, Op, OpKind, Parsed, RegData};
use crate::{hardware, license, store};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

pub struct RegSrc { pub pack: &'static str, pub name: &'static str, pub path: &'static str, pub bytes: &'static [u8] }
macro_rules! src { ($pack:expr, $name:expr, $path:expr) => { RegSrc { pack: $pack, name: $name, path: $path, bytes: include_bytes!(concat!("../regs/", $path)) } }; }
/// All original files, embedded byte-for-byte. Global file number = position + 1 (that is the order of application).
pub const REGS: [RegSrc; 20] = [
    src!("444CFG", "444cfg1.reg", "444cfg1.reg"), src!("444CFG", "444cfg2.reg", "444cfg2.reg"), src!("444CFG", "444cfg3.reg", "444cfg3.reg"), src!("444CFG", "444cfg4.reg", "444cfg4.reg"),
    src!("444CFG", "444cfg5.reg", "444cfg5.reg"), src!("444CFG", "444cfg6.reg", "444cfg6.reg"), src!("444CFG", "444cfg7.reg", "444cfg7.reg"), src!("444CFG", "444cfg8.reg", "444cfg8.reg"),
    src!("EREN", "erenlolxd.reg", "eren/erenlolxd.reg"), src!("EREN", "erenlolxd2.reg", "eren/erenlolxd2.reg"), src!("EREN", "erenlolxd3.reg", "eren/erenlolxd3.reg"),
    src!("GODLEAK", "godleak1.reg", "godleak/godleak1.reg"), src!("GODLEAK", "godleak2.reg", "godleak/godleak2.reg"), src!("GODLEAK", "godleak3.reg", "godleak/godleak3.reg"),
    src!("GODLEAK", "godleak4.reg", "godleak/godleak4.reg"), src!("GODLEAK", "godleak5.reg", "godleak/godleak5.reg"), src!("GODLEAK", "godleak6.reg", "godleak/godleak6.reg"),
    src!("GODLEAK", "godleak7.reg", "godleak/godleak7.reg"), src!("GODLEAK", "godleak8.reg", "godleak/godleak8.reg"), src!("GODLEAK", "godleak9.reg", "godleak/godleak9.reg"),
];
const KEY_ENUM_ADMIN_PROBE: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile";

pub fn load_all() -> Vec<(u8, Parsed)> {
    REGS.iter().enumerate().map(|(i, r)| {
        let n = (i + 1) as u8; let mut p = parse(n, r.bytes);
        for op in p.ops.iter_mut() { op.file_name = r.name.to_string(); op.pack = r.pack.to_string(); }
        (n, p)
    }).collect()
}
pub fn all_ops(parsed: &[(u8, Parsed)]) -> Vec<Op> { parsed.iter().flat_map(|(_, p)| p.ops.iter().cloned()).collect() }

// ---------------------------------------------------------------- registry abstraction
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "kind")]
pub enum Orig { Missing, Raw { vtype: u32, hex: String } }
impl Orig {
    pub fn from_data(d: &RegData) -> Orig { Orig::Raw { vtype: d.vtype, hex: HEXLOWER.encode(&d.bytes) } }
    pub fn to_data(&self) -> Option<RegData> { match self { Orig::Missing => None, Orig::Raw { vtype, hex } => HEXLOWER.decode(hex.as_bytes()).ok().map(|bytes| RegData { vtype: *vtype, bytes }) } }
    pub fn text(&self) -> String { self.to_data().map(|d| render_value(&d)).unwrap_or_else(|| "(no existe)".into()) }
}

pub trait Reg {
    fn read(&self, h: Hive, key: &str, name: &str) -> Result<Orig, String>;
    fn write(&mut self, h: Hive, key: &str, name: &str, d: &RegData) -> Result<(), String>; // creates the key if needed
    fn delete_value(&mut self, h: Hive, key: &str, name: &str) -> Result<(), String>;
    fn key_exists(&self, h: Hive, key: &str) -> bool;
    fn create_key(&mut self, h: Hive, key: &str) -> Result<(), String>;
    fn delete_key_if_empty(&mut self, h: Hive, key: &str) -> bool;
    fn is_admin(&self) -> bool;
}

#[cfg(windows)]
pub struct SysReg;
#[cfg(windows)]
mod winimpl {
    use super::*;
    use winreg::{enums::*, RegKey, RegValue};
    fn root(h: Hive) -> RegKey { RegKey::predef(if h == Hive::Hkcu { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE }) }
    fn vt_from(n: u32) -> Option<RegType> { Some(match n { 0 => REG_NONE, 1 => REG_SZ, 2 => REG_EXPAND_SZ, 3 => REG_BINARY, 4 => REG_DWORD, 5 => REG_DWORD_BIG_ENDIAN, 6 => REG_LINK, 7 => REG_MULTI_SZ, 8 => REG_RESOURCE_LIST, 9 => REG_FULL_RESOURCE_DESCRIPTOR, 10 => REG_RESOURCE_REQUIREMENTS_LIST, 11 => REG_QWORD, _ => return None }) }
    fn nf(e: &std::io::Error) -> bool { e.kind() == std::io::ErrorKind::NotFound }
    impl Reg for SysReg {
        fn read(&self, h: Hive, key: &str, name: &str) -> Result<Orig, String> {
            let k = match root(h).open_subkey_with_flags(key, KEY_READ | KEY_WOW64_64KEY) { Ok(k) => k, Err(e) if nf(&e) => return Ok(Orig::Missing), Err(e) => return Err(e.to_string()) };
            match k.get_raw_value(name) { Ok(v) => Ok(Orig::Raw { vtype: v.vtype as u32, hex: HEXLOWER.encode(&v.bytes) }), Err(e) if nf(&e) => Ok(Orig::Missing), Err(e) => Err(e.to_string()) }
        }
        fn write(&mut self, h: Hive, key: &str, name: &str, d: &RegData) -> Result<(), String> {
            let vt = vt_from(d.vtype).ok_or_else(|| format!("tipo de valor {} no soportado", d.vtype))?;
            let (k, _) = root(h).create_subkey_with_flags(key, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY).map_err(|e| e.to_string())?;
            k.set_raw_value(name, &RegValue { bytes: d.bytes.clone(), vtype: vt }).map_err(|e| e.to_string())
        }
        fn delete_value(&mut self, h: Hive, key: &str, name: &str) -> Result<(), String> {
            let k = match root(h).open_subkey_with_flags(key, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY) { Ok(k) => k, Err(e) if nf(&e) => return Ok(()), Err(e) => return Err(e.to_string()) };
            match k.delete_value(name) { Ok(()) => Ok(()), Err(e) if nf(&e) => Ok(()), Err(e) => Err(e.to_string()) }
        }
        fn key_exists(&self, h: Hive, key: &str) -> bool { root(h).open_subkey_with_flags(key, KEY_READ | KEY_WOW64_64KEY).is_ok() }
        fn create_key(&mut self, h: Hive, key: &str) -> Result<(), String> { root(h).create_subkey_with_flags(key, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY).map(|_| ()).map_err(|e| e.to_string()) }
        fn delete_key_if_empty(&mut self, h: Hive, key: &str) -> bool {
            let Ok(k) = root(h).open_subkey_with_flags(key, KEY_READ | KEY_WOW64_64KEY) else { return false };
            if k.enum_values().next().is_some() || k.enum_keys().next().is_some() { return false; }
            drop(k);
            root(h).delete_subkey_with_flags(key, KEY_WOW64_64KEY).is_ok()
        }
        fn is_admin(&self) -> bool { root(Hive::Hklm).open_subkey_with_flags(KEY_ENUM_ADMIN_PROBE, KEY_WRITE | KEY_WOW64_64KEY).is_ok() }
    }
}
#[cfg(not(windows))]
pub struct SysReg;
#[cfg(not(windows))]
impl Reg for SysReg {
    fn read(&self, _: Hive, _: &str, _: &str) -> Result<Orig, String> { Err("Solo disponible en Windows".into()) }
    fn write(&mut self, _: Hive, _: &str, _: &str, _: &RegData) -> Result<(), String> { Err("Solo disponible en Windows".into()) }
    fn delete_value(&mut self, _: Hive, _: &str, _: &str) -> Result<(), String> { Err("Solo disponible en Windows".into()) }
    fn key_exists(&self, _: Hive, _: &str) -> bool { false }
    fn create_key(&mut self, _: Hive, _: &str) -> Result<(), String> { Err("Solo disponible en Windows".into()) }
    fn delete_key_if_empty(&mut self, _: Hive, _: &str) -> bool { false }
    fn is_admin(&self) -> bool { false }
}

// ---------------------------------------------------------------- backup + apply + restore (pure over `Reg`)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValEntry { pub hive: Hive, pub key: String, pub name: String, pub original: Orig, pub applied: bool }
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyEntry { pub hive: Hive, pub key: String, pub existed: bool }
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Backup { pub created_at: u64, pub values: Vec<ValEntry>, pub keys: Vec<KeyEntry>, #[serde(default)] pub active_pack: Option<String> }

#[derive(Serialize, Clone, Debug)]
pub struct StepResult { pub id: String, pub file: u8, pub location: String, pub name: String, pub value: String, pub ok: bool, pub error: Option<String> }
#[derive(Serialize)]
pub struct Report { pub results: Vec<StepResult>, pub all_ok: bool, pub reboot_recommended: bool }

/// Records the true previous state of every target touched. A target already in the backup keeps its FIRST (real) original.
pub fn snapshot(reg: &dyn Reg, mut b: Backup, ops: &[&Op], ts: u64) -> Result<Backup, String> {
    if b.values.is_empty() && b.keys.is_empty() { b.created_at = ts; }
    for op in ops {
        let parts: Vec<&str> = op.key.split('\\').collect();
        for n in 1..=parts.len() {
            let k = parts[..n].join("\\");
            if !b.keys.iter().any(|e| e.hive == op.hive && e.key.eq_ignore_ascii_case(&k)) { b.keys.push(KeyEntry { hive: op.hive, key: k.clone(), existed: reg.key_exists(op.hive, &k) }); }
        }
        if matches!(op.kind, OpKind::Set(_)) && !b.values.iter().any(|e| op.same_target(e.hive, &e.key, &e.name)) {
            let original = reg.read(op.hive, &op.key, &op.name).map_err(|e| format!("No se pudo leer {} {}: {e}", op.location(), op.name_display()))?;
            b.values.push(ValEntry { hive: op.hive, key: op.key.clone(), name: op.name.clone(), original, applied: false });
        }
    }
    Ok(b)
}

pub fn do_apply(reg: &mut dyn Reg, b: &mut Backup, ops: &[&Op], progress: &mut dyn FnMut(usize, usize)) -> Vec<StepResult> {
    let total = ops.len(); let mut out = vec![];
    for (i, op) in ops.iter().enumerate() {
        let (r, shown): (Result<(), String>, String) = match &op.kind {
            OpKind::KeyOnly => (reg.create_key(op.hive, &op.key).and_then(|_| if reg.key_exists(op.hive, &op.key) { Ok(()) } else { Err("la clave no existe tras crearla".into()) }), "(clave vacía)".into()),
            OpKind::Set(d) => (reg.write(op.hive, &op.key, &op.name, d).and_then(|_| {
                let got = reg.read(op.hive, &op.key, &op.name)?;
                if got == Orig::from_data(d) { Ok(()) } else { Err(format!("verificación fallida: se leyó {}", got.text())) }
            }), render_value(d)),
        };
        if r.is_ok() && matches!(op.kind, OpKind::Set(_)) { if let Some(e) = b.values.iter_mut().find(|e| op.same_target(e.hive, &e.key, &e.name)) { e.applied = true; } }
        out.push(StepResult { id: op.id.clone(), file: op.file, location: op.location(), name: op.name_display(), value: shown, ok: r.is_ok(), error: r.err() });
        progress(i + 1, total);
    }
    out
}

pub fn do_restore(reg: &mut dyn Reg, b: &mut Backup, progress: &mut dyn FnMut(usize, usize)) -> Vec<StepResult> {
    let idxs: Vec<usize> = b.values.iter().enumerate().filter(|(_, e)| e.applied).map(|(i, _)| i).collect();
    let total = idxs.len(); let mut out = vec![];
    for (n, i) in idxs.into_iter().enumerate() {
        let e = b.values[i].clone();
        let r: Result<(), String> = (|| {
            match e.original.to_data() {
                None => reg.delete_value(e.hive, &e.key, &e.name)?,
                Some(d) => reg.write(e.hive, &e.key, &e.name, &d)?,
            }
            let got = reg.read(e.hive, &e.key, &e.name)?;
            if got == e.original { Ok(()) } else { Err(format!("verificación fallida: se leyó {}", got.text())) }
        })();
        if r.is_ok() { b.values[i].applied = false; }
        out.push(StepResult { id: format!("restore:{i}"), file: 0, location: format!("{}\\{}", e.hive.short(), e.key), name: if e.name.is_empty() { "@".into() } else { format!("\"{}\"", e.name) }, value: e.original.text(), ok: r.is_ok(), error: r.err() });
        progress(n + 1, total);
    }
    if out.iter().all(|r| r.ok) { for k in b.keys.iter().rev() { if !k.existed { reg.delete_key_if_empty(k.hive, &k.key); } } }
    out
}

pub fn is_risky(ops: &[&Op]) -> bool { ops.iter().any(|o| max_level(&assess(o)) >= Level::Danger) }

// ---------------------------------------------------------------- views for the UI
#[derive(Serialize)] pub struct ForeignView { pub line: usize, pub text: String }
#[derive(Serialize)] pub struct FileView { pub n: u8, pub pack: String, pub name: String, pub size: usize, pub sha256: String, pub encoding: String, pub ops: usize, pub foreign: Vec<ForeignView>, pub errors: Vec<String> }
#[derive(Serialize)]
pub struct OpView { pub id: String, pub file: u8, pub file_name: String, pub pack: String, pub order: usize, pub line: usize, pub location: String, pub name: String, pub kind: &'static str, pub value: String, pub source: String,
    pub current: String, pub needs_admin: bool, pub level: Level, pub findings: Vec<Finding>, pub default_selected: bool }
#[derive(Serialize)] pub struct Plan { pub files: Vec<FileView>, pub ops: Vec<OpView>, pub conflicts: Vec<Conflict>, pub windows_ok: bool, pub build: Option<u32>, pub elevated: bool }

pub fn build_plan(reg: &dyn Reg, build: Option<u32>) -> Plan {
    let parsed = load_all(); let ops = all_ops(&parsed);
    let files = parsed.iter().map(|(n, p)| FileView { n: *n, pack: REGS[(*n - 1) as usize].pack.into(), name: REGS[(*n - 1) as usize].name.into(), size: REGS[(*n - 1) as usize].bytes.len(),
        sha256: HEXLOWER.encode(&Sha256::digest(REGS[(*n - 1) as usize].bytes)), encoding: p.encoding.into(), ops: p.ops.len(),
        foreign: p.foreign.iter().map(|f| ForeignView { line: f.line, text: f.text.clone() }).collect(), errors: p.errors.clone() }).collect();
    let views = ops.iter().enumerate().map(|(i, op)| {
        let findings = assess(op); let level = max_level(&findings);
        let (value, kind) = match &op.kind { OpKind::Set(d) => (render_value(d), "set"), OpKind::KeyOnly => ("(crear clave)".into(), "key") };
        let current = match &op.kind { OpKind::Set(_) => reg.read(op.hive, &op.key, &op.name).map(|o| o.text()).unwrap_or_else(|e| format!("error: {e}")),
            OpKind::KeyOnly => if reg.key_exists(op.hive, &op.key) { "(la clave existe)".into() } else { "(la clave no existe)".into() } };
        OpView { id: op.id.clone(), file: op.file, file_name: op.file_name.clone(), pack: op.pack.clone(), order: i + 1, line: op.line, location: op.location(), name: op.name_display(), kind, value, source: op.source.clone(), current,
            needs_admin: op.hive == Hive::Hklm, level, findings, default_selected: level < Level::Danger }
    }).collect();
    Plan { files, ops: views, conflicts: detect_conflicts(&ops), windows_ok: build.map(|b| b >= 10240).unwrap_or(true), build, elevated: reg.is_admin() }
}

#[derive(Serialize)] pub struct BackupRow { pub location: String, pub name: String, pub original: String, pub applied: bool }
#[derive(Serialize)] pub struct BackupView { pub created_at: u64, pub rows: Vec<BackupRow>, pub created_keys: usize }

// ---------------------------------------------------------------- Tauri commands
#[derive(Serialize, Clone)] struct Progress { done: usize, total: usize }

#[tauri::command]
pub fn movement_plan(app: AppHandle) -> Result<Plan, String> { license::require_license(&app)?; Ok(build_plan(&SysReg, hardware::build_number())) }

#[tauri::command]
pub fn apply_movement(app: AppHandle, ids: Vec<String>, ack_risky: bool) -> Result<Report, String> {
    license::require_license(&app)?;
    if hardware::build_number().map(|b| b < 10240).unwrap_or(false) { return Err("Esta versión de Windows no es compatible.".into()); }
    if ids.is_empty() { return Err("No hay ajustes seleccionados.".into()); }
    let all = all_ops(&load_all());
    for id in &ids { if !all.iter().any(|o| &o.id == id) { return Err(format!("Operación desconocida: {id}")); } }
    let selected: Vec<&Op> = all.iter().filter(|o| ids.contains(&o.id)).collect(); // keeps ORIGINAL order, values untouched
    let selected_pack = selected[0].pack.as_str();
    if selected.iter().any(|op| op.pack != selected_pack) {
        return Err("Solo puedes aplicar un pack cada vez. Selecciona 444CFG, EREN o GODLEAK.".into());
    }
    if is_risky(&selected) && !ack_risky { return Err("RISKY: hay ajustes incompatibles o potencialmente peligrosos seleccionados sin confirmación explícita.".into()); }
    let mut reg = SysReg;
    if selected.iter().any(|o| o.hive == Hive::Hklm) && !reg.is_admin() { return Err("NEEDS_ADMIN: hay ajustes en HKLM que requieren administrador.".into()); }
    let previous: Backup = store::read(&app, "movement_backup.json").unwrap_or_default();
    if let Some(active) = &previous.active_pack {
        if active != selected_pack {
            return Err(format!("Ya hay cambios del pack {active}. Usa RESTAURAR ORIGINAL antes de aplicar {selected_pack}."));
        }
    }
    let mut backup = snapshot(&reg, previous, &selected, store::now())?;
    backup.active_pack = Some(selected_pack.to_string());
    // Mark every selected value as potentially changed *before* the first write.
    // If Windows closes the app between a registry write and saving the report,
    // the backup still contains enough information to restore the true original.
    for op in &selected {
        if matches!(op.kind, OpKind::Set(_)) {
            if let Some(entry) = backup.values.iter_mut().find(|e| op.same_target(e.hive, &e.key, &e.name)) {
                entry.applied = true;
            }
        }
    }
    store::write(&app, "movement_backup.json", &backup)?;
    let a2 = app.clone();
    let results = do_apply(&mut reg, &mut backup, &selected, &mut |d, t| { let _ = a2.emit("movement-progress", Progress { done: d, total: t }); });
    // The prewritten backup remains valid even if this write fails.
    store::write(&app, "movement_backup.json", &backup)?;
    let ok = results.iter().filter(|r| r.ok).count();
    store::log(&app, &format!("Movement aplicado: {ok}/{} operaciones verificadas", results.len()));
    Ok(Report { all_ok: ok == results.len(), reboot_recommended: ok > 0, results })
}

#[tauri::command]
pub fn restore_movement(app: AppHandle) -> Result<Report, String> {
    license::require_license(&app)?;
    let mut backup: Backup = store::read(&app, "movement_backup.json").ok_or("No hay copia de seguridad que restaurar.")?;
    let mut reg = SysReg;
    if backup.values.iter().any(|e| e.applied && e.hive == Hive::Hklm) && !reg.is_admin() { return Err("NEEDS_ADMIN: restaurar valores de HKLM requiere administrador.".into()); }
    let a2 = app.clone();
    let results = do_restore(&mut reg, &mut backup, &mut |d, t| { let _ = a2.emit("movement-progress", Progress { done: d, total: t }); });
    let all_ok = results.iter().all(|r| r.ok);
    if all_ok { store::remove(&app, "movement_backup.json"); } else { store::write(&app, "movement_backup.json", &backup)?; }
    store::log(&app, &format!("Movement restaurado: {}/{} valores", results.iter().filter(|r| r.ok).count(), results.len()));
    Ok(Report { all_ok, reboot_recommended: !results.is_empty(), results })
}

#[tauri::command]
pub fn backup_info(app: AppHandle) -> Option<BackupView> {
    let b: Backup = store::read(&app, "movement_backup.json")?;
    Some(BackupView { created_at: b.created_at, created_keys: b.keys.iter().filter(|k| !k.existed).count(), rows: b.values.iter().filter(|e| e.applied).map(|e| BackupRow { location: format!("{}\\{}", e.hive.short(), e.key),
        name: if e.name.is_empty() { "@".into() } else { format!("\"{}\"", e.name) }, original: e.original.text(), applied: e.applied }).collect() })
}
#[tauri::command]
pub fn applied_count(app: AppHandle) -> usize { store::read::<Backup>(&app, "movement_backup.json").map(|b| b.values.iter().filter(|e| e.applied).count()).unwrap_or(0) }
#[tauri::command]
pub fn is_elevated() -> bool { SysReg.is_admin() }

/// Writes the embedded originals, byte for byte, into a folder chosen by the user. Never overwrites existing files.
#[tauri::command]
pub fn export_reg_files(dir: String) -> Result<Vec<String>, String> {
    use std::io::Write;
    let d = std::path::Path::new(&dir);
    if !std::fs::metadata(d).map(|m| m.is_dir()).unwrap_or(false) { return Err("La carpeta de destino no existe.".into()); }
    let mut out = vec![];
    for r in REGS.iter() {
        let name = r.name;
        match std::fs::OpenOptions::new().write(true).create_new(true).open(d.join(name)) {
            Ok(mut f) => { f.write_all(r.bytes).map_err(|e| e.to_string())?; out.push(format!("{name}: exportado")); }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => out.push(format!("{name}: ya existe, no se sobrescribió")),
            Err(e) => return Err(format!("{name}: {e}")),
        }
    }
    Ok(out)
}

#[tauri::command]
pub fn relaunch_as_admin(app: AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let cmd = format!("Start-Process -FilePath '{}' -Verb RunAs", exe.display().to_string().replace('\'', "''"));
        std::process::Command::new("powershell").args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd]).creation_flags(0x0800_0000).spawn().map_err(|e| e.to_string())?;
        app.exit(0);
        Ok(())
    }
    #[cfg(not(windows))] { let _ = app; Err("Solo Windows".into()) }
}

#[tauri::command]
pub fn restart_windows() -> Result<(), String> {
    // The UI asks for a second explicit confirmation first. 30 s grace period, cancellable with `shutdown /a`.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("shutdown").args(["/r", "/t", "30", "/c", "444CFG TOOL: reinicio solicitado por el usuario"]).creation_flags(0x0800_0000).spawn().map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(windows))] Err("Solo Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regfile::{as_string, as_dword};
    use std::collections::{BTreeMap, BTreeSet};

    /// In-memory registry: lets the tests exercise apply/backup/restore without touching the real system.
    #[derive(Default, Clone, PartialEq, Debug)]
    struct Mem { keys: BTreeSet<(Hive, String)>, vals: BTreeMap<(Hive, String, String), RegData>, admin: bool }
    fn lc(k: &str) -> String { k.to_lowercase() }
    impl Mem {
        fn put(&mut self, h: Hive, key: &str, name: &str, d: RegData) { self.create_key(h, key).unwrap(); self.vals.insert((h, lc(key), lc(name)), d); }
        fn get(&self, h: Hive, key: &str, name: &str) -> Option<&RegData> { self.vals.get(&(h, lc(key), lc(name))) }
    }
    impl Reg for Mem {
        fn read(&self, h: Hive, key: &str, name: &str) -> Result<Orig, String> { Ok(self.get(h, key, name).map(Orig::from_data).unwrap_or(Orig::Missing)) }
        fn write(&mut self, h: Hive, key: &str, name: &str, d: &RegData) -> Result<(), String> { self.create_key(h, key)?; self.vals.insert((h, lc(key), lc(name)), d.clone()); Ok(()) }
        fn delete_value(&mut self, h: Hive, key: &str, name: &str) -> Result<(), String> { self.vals.remove(&(h, lc(key), lc(name))); Ok(()) }
        fn key_exists(&self, h: Hive, key: &str) -> bool { self.keys.contains(&(h, lc(key))) }
        fn create_key(&mut self, h: Hive, key: &str) -> Result<(), String> {
            let parts: Vec<&str> = key.split('\\').collect();
            for n in 1..=parts.len() { self.keys.insert((h, lc(&parts[..n].join("\\")))); } Ok(())
        }
        fn delete_key_if_empty(&mut self, h: Hive, key: &str) -> bool {
            let k = (h, lc(key)); let prefix = format!("{}\\", lc(key));
            if self.vals.keys().any(|(hh, kk, _)| *hh == h && kk == &k.1) || self.keys.iter().any(|(hh, kk)| *hh == h && kk.starts_with(&prefix)) { return false; }
            self.keys.remove(&k)
        }
        fn is_admin(&self) -> bool { self.admin }
    }
    fn sz(s: &str) -> RegData { RegData { vtype: 1, bytes: crate::regfile::utf16z(s) } }

    const SUMS: [&str; 20] = [
        "eee95a90ad020155bf4a3bf0e3a5da2964fb21fcceb5b4ff52f16a6eb07a1ba5",
        "54059c4b3f3e3e6bcd4172d1925c1efbd5cd5f46fa7399cddd60cd3d832151db",
        "7984ca5b6b606f19c509ed5824e0d1280dc7989fd55735bddeccee1672c2e5ea",
        "432fb02981e4928f76df0761422e7d8bba216bb88767a18bdec191e75c3a7c98",
        "a879987747e71618b6c73c2ef069694e490f1ae4943b1ee1f14808fc7138f9fe",
        "508cda88f7ab9b0b4715d898db163143565989757517209f967a833435c5103a",
        "84f350aba0585934874e92c83ed913acafb5bc9a31155d9ae2c1c73f0f5be1c8",
        "ab97d7c9a75a7cecd829f26b1fd1f577adea65a178103ea0051e17759ac0dfc5",
        "7bcae046051eb21d29a7af13aa6a504df67e47b7e91269e324072ee748e0d5e9",
        "20907fdfc909222da0b2327ba9008321d88cf7f5f960807c8104dec2e7021379",
        "e7e7cc34a565a3707328d11c5ce3021f2b596d6875bc517601c0eaf722cad55c",
        "dd6dc32692d30174922b836ab900c6225cf6b307ef8cf2dc217fd817a8885584",
        "ef9ef2a66cfd050f845a3b72ebfdaa405e7b9d57c1f89416f5362f849447c54e",
        "d2889f67bab649f724e23dee7a877cb35f7d2dd162f32e6b14636aa7b154fe16",
        "dd6dc32692d30174922b836ab900c6225cf6b307ef8cf2dc217fd817a8885584",
        "80f05733cc8f5acf507bc4dacb5e94ae2292ff349df494d9908006e9b3e35bdc",
        "40e8876533e9da014ef439cdbe9a9b3c29e07f87c8e310d6aaf9fb42b38be35c",
        "ae74f1db5630b7bd31353701cc03e98277ee29da842154438e3e616d5e4d895b",
        "a69dc0431fd3d38ec014453894ea931572d54a6072a81ba579956201d77274f7",
        "42f408e05fb70e30636f46ba0777ac35380595c716c200fb883210797b98ca80",
    ];

    fn pack_ops(pack: &str) -> Vec<Op> { all_ops(&load_all()).into_iter().filter(|o| o.pack == pack).collect() }
    fn lvl(ops: &[Op], f: u8, n: &str) -> Level { max_level(&assess(ops.iter().find(|o| o.file == f && o.name == n).unwrap())) }

    #[test] fn embedded_originals_are_byte_exact() {
        for (i, r) in REGS.iter().enumerate() { assert_eq!(HEXLOWER.encode(&Sha256::digest(r.bytes)), SUMS[i], "{} was modified", r.path); assert!(r.path.ends_with(r.name)); }
    }
    #[test] fn all_twenty_files_parse_without_errors() {
        let p = load_all();
        let counts: Vec<usize> = p.iter().map(|(_, x)| x.ops.len()).collect();
        assert_eq!(counts, vec![18, 4, 4, 3, 9, 6, 9, 63, 9, 4, 3, 4, 18, 4, 4, 3, 9, 6, 9, 63]);
        assert_eq!(pack_ops("444CFG").len(), 116); assert_eq!(pack_ops("EREN").len(), 16); assert_eq!(pack_ops("GODLEAK").len(), 120);
        assert!(p.iter().all(|(_, x)| x.errors.is_empty()), "{:?}", p.iter().map(|(_, x)| x.errors.clone()).collect::<Vec<_>>());
        assert_eq!(p[3].1.encoding, "ANSI/ASCII (sin BOM)"); assert_eq!(p[0].1.encoding, "UTF-16 LE"); assert_eq!(p[10].1.encoding, "ANSI/ASCII (sin BOM)");
    }
    #[test] fn foreign_text_is_reported_and_never_an_operation() {
        let p = load_all();
        assert_eq!(p.iter().take(8).map(|(_, x)| x.foreign.len()).sum::<usize>(), 8);
        assert!(p.iter().take(8).flat_map(|(_, x)| x.foreign.iter()).all(|f| f.text.contains("arizonashaders")));
        assert!(p[8..11].iter().all(|(_, x)| x.foreign.len() == 1 && x.foreign[0].text == "."), "EREN files end with a lone '.'");
        assert!(p[11..].iter().all(|(_, x)| x.foreign.is_empty()));
        assert!(all_ops(&p).iter().all(|o| !o.source.contains("arizonashaders")));
    }
    #[test] fn operation_order_is_file_order_then_line_order() {
        let ops = all_ops(&load_all());
        assert!(ops.windows(2).all(|w| (w[0].file, w[0].line) < (w[1].file, w[1].line)));
        assert_eq!(ops[0].id, "1:1");
    }
    #[test] fn values_are_parsed_exactly() {
        let ops = all_ops(&load_all());
        let get = |f: u8, n: &str| ops.iter().find(|o| o.file == f && o.name == n).unwrap();
        let OpKind::Set(d) = &get(3, "KeyboardSpeed").kind else { panic!() }; assert_eq!(as_string(d).unwrap(), "50");
        let OpKind::Set(d) = &get(8, "NetworkThrottlingIndex").kind else { panic!() }; assert_eq!(as_dword(d), Some(0x0fffffff));
        let OpKind::Set(d) = &get(1, "SmoothMouseXCurve").kind else { panic!() }; assert_eq!((d.vtype, d.bytes.len(), d.bytes[8], d.bytes[9]), (3, 40, 0xc0, 0xcc));
        let OpKind::Set(d) = &get(4, "SmoothMouseXCurve").kind else { panic!() }; assert_eq!(d.bytes.len(), 40, "continuation lines in file 4 must be joined");
    }
    #[test] fn conflicts_between_files_are_detected() {
        let c = detect_conflicts(&pack_ops("444CFG"));
        let conf: Vec<_> = c.iter().filter(|x| x.kind == "conflict").map(|x| x.name.clone()).collect();
        assert_eq!(conf.len(), 4, "{conf:?}");
        for n in ["\"AutoRepeatDelay\"", "\"AutoRepeatRate\"", "\"Flags\"", "\"Last Valid Wait\""] { assert!(conf.contains(&n.to_string()), "missing {n}"); }
        assert_eq!(c.iter().filter(|x| x.kind == "duplicate").count(), 8);
        let flags = c.iter().find(|x| x.name == "\"Flags\"").unwrap();
        assert_eq!((flags.entries[0].file, flags.entries[1].file), (5, 7)); assert!(flags.winner.starts_with("7:"));
    }
    #[test] fn incompatible_and_dangerous_values_are_flagged() {
        let ops = all_ops(&load_all());
        assert_eq!(lvl(&ops, 3, "KeyboardSpeed"), Level::Incompatible);
        assert_eq!(lvl(&ops, 8, "NetworkThrottlingIndex"), Level::Incompatible);
        assert_eq!(lvl(&ops, 5, "Flags"), Level::Danger); assert_eq!(lvl(&ops, 7, "Flags"), Level::Danger);
        assert!(lvl(&ops, 3, "My Regedit") >= Level::Warning);
        assert!(lvl(&ops, 1, "MouseSensitivity") < Level::Warning);
        assert!(lvl(&ops, 8, "SystemResponsiveness") < Level::Danger);
        // same findings in the new packs
        assert_eq!(lvl(&ops, 9, "Flags"), Level::Danger);                     // erenlolxd.reg
        assert_eq!(lvl(&ops, 10, "KeyboardSpeed"), Level::Incompatible);      // erenlolxd2.reg
        assert_eq!(lvl(&ops, 19, "Flags"), Level::Danger);                    // godleak8.reg
        assert_eq!(lvl(&ops, 20, "NetworkThrottlingIndex"), Level::Incompatible); // godleak9.reg
    }
    #[test] fn risky_selection_requires_ack() {
        let ops = all_ops(&load_all());
        let safe: Vec<&Op> = ops.iter().filter(|o| o.file == 1).collect(); assert!(!is_risky(&safe));
        let risky: Vec<&Op> = ops.iter().filter(|o| o.file == 3).collect(); assert!(is_risky(&risky));
    }
    #[test] fn apply_all_then_restore_returns_exact_previous_state() {
        let ops = pack_ops("444CFG"); let sel: Vec<&Op> = ops.iter().collect();
        let mut m = Mem { admin: true, ..Default::default() };
        m.put(Hive::Hkcu, "Control Panel\\Mouse", "MouseSpeed", sz("1"));            // pre-existing value that must come back
        m.put(Hive::Hkcu, "Control Panel\\Mouse", "UserKept", sz("keep"));         // unrelated value, must survive
        m.put(Hive::Hkcu, "Control Panel\\Keyboard", "KeyboardDelay", RegData { vtype: 4, bytes: vec![1, 0, 0, 0] }); // different type before
        let before = m.clone();
        let mut b = snapshot(&m, Backup::default(), &sel, 1).unwrap();
        let res = do_apply(&mut m, &mut b, &sel, &mut |_, _| {});
        assert!(res.iter().all(|r| r.ok), "{:?}", res.iter().filter(|r| !r.ok).collect::<Vec<_>>());
        assert_eq!(res.len(), 116);
        // exact values written, last file wins on conflicts
        assert_eq!(as_string(m.get(Hive::Hkcu, "Control Panel\\Keyboard", "KeyboardSpeed").unwrap()).unwrap(), "50");
        assert_eq!(as_string(m.get(Hive::Hkcu, "Control Panel\\Accessibility\\Keyboard Response", "Flags").unwrap()).unwrap(), "1");
        assert_eq!(as_dword(m.get(Hive::Hklm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", "NetworkThrottlingIndex").unwrap()), Some(0x0fffffff));
        assert_ne!(m, before);
        let r = do_restore(&mut m, &mut b, &mut |_, _| {});
        assert!(r.iter().all(|x| x.ok));
        assert_eq!(m, before, "restore must leave the registry exactly as before (values, types and created keys)");
    }
    #[test] fn new_packs_only_use_known_targets_with_identical_values() {
        let base = pack_ops("444CFG");
        for op in all_ops(&load_all()).iter().filter(|o| o.pack != "444CFG") {
            let OpKind::Set(d) = &op.kind else { continue };
            let same = base.iter().any(|b| b.same_target(op.hive, &op.key, &op.name) && matches!(&b.kind, OpKind::Set(x) if x == d));
            assert!(same, "{} {} {} has no identical counterpart in the 444CFG pack", op.file_name, op.location(), op.name);
        }
    }
    #[test] fn pack_conflicts_match_expectations() {
        let eren = detect_conflicts(&pack_ops("EREN")); assert!(eren.is_empty());
        let gl = detect_conflicts(&pack_ops("GODLEAK"));
        assert_eq!(gl.iter().filter(|x| x.kind == "conflict").count(), 4);
        assert_eq!(gl.iter().filter(|x| x.kind == "duplicate").count(), 12);
        let f = gl.iter().find(|x| x.name == "\"Flags\"").unwrap();
        assert_eq!((f.entries[0].file_name.as_str(), f.entries[1].file_name.as_str()), ("godleak6.reg", "godleak8.reg"));
    }
    #[test] fn all_packs_together_apply_in_order_and_restore_exactly() {
        let ops = all_ops(&load_all()); let sel: Vec<&Op> = ops.iter().collect();
        let mut m = Mem { admin: true, ..Default::default() };
        m.put(Hive::Hkcu, "Control Panel\\Mouse", "MouseSpeed", sz("1"));
        let before = m.clone();
        let mut b = snapshot(&m, Backup::default(), &sel, 1).unwrap();
        let res = do_apply(&mut m, &mut b, &sel, &mut |_, _| {});
        assert_eq!(res.len(), 252); assert!(res.iter().all(|r| r.ok));
        // last file in global order (godleak8.reg) wins
        assert_eq!(as_string(m.get(Hive::Hkcu, "Control Panel\\Accessibility\\Keyboard Response", "Flags").unwrap()).unwrap(), "1");
        do_restore(&mut m, &mut b, &mut |_, _| {});
        assert_eq!(m, before);
    }
    #[test] fn only_confirmed_operations_are_applied() {
        let ops = all_ops(&load_all()); let sel: Vec<&Op> = ops.iter().filter(|o| o.file == 1 && o.name == "MouseSpeed").collect();
        let mut m = Mem::default(); let mut b = snapshot(&m, Backup::default(), &sel, 1).unwrap();
        do_apply(&mut m, &mut b, &sel, &mut |_, _| {});
        assert_eq!(m.vals.len(), 1); assert_eq!(b.values.len(), 1);
    }
    #[test] fn second_apply_keeps_the_true_original() {
        let ops = all_ops(&load_all()); let sel: Vec<&Op> = ops.iter().filter(|o| o.name == "MouseSpeed").collect();
        let mut m = Mem::default(); m.put(Hive::Hkcu, "Control Panel\\Mouse", "MouseSpeed", sz("1"));
        let mut b = snapshot(&m, Backup::default(), &sel, 1).unwrap(); do_apply(&mut m, &mut b, &sel, &mut |_, _| {});
        let mut b2 = snapshot(&m, b, &sel, 2).unwrap();            // user applies again before restoring
        assert_eq!(b2.values[0].original.text(), "\"1\"");
        do_restore(&mut m, &mut b2, &mut |_, _| {});
        assert_eq!(as_string(m.get(Hive::Hkcu, "Control Panel\\Mouse", "MouseSpeed").unwrap()).unwrap(), "1");
    }
    #[test] fn failed_write_is_reported_and_not_marked_applied() {
        struct Fail(Mem); impl Reg for Fail {
            fn read(&self, h: Hive, k: &str, n: &str) -> Result<Orig, String> { self.0.read(h, k, n) }
            fn write(&mut self, _: Hive, _: &str, _: &str, _: &RegData) -> Result<(), String> { Err("acceso denegado".into()) }
            fn delete_value(&mut self, h: Hive, k: &str, n: &str) -> Result<(), String> { self.0.delete_value(h, k, n) }
            fn key_exists(&self, h: Hive, k: &str) -> bool { self.0.key_exists(h, k) }
            fn create_key(&mut self, h: Hive, k: &str) -> Result<(), String> { self.0.create_key(h, k) }
            fn delete_key_if_empty(&mut self, h: Hive, k: &str) -> bool { self.0.delete_key_if_empty(h, k) }
            fn is_admin(&self) -> bool { true } }
        let ops = all_ops(&load_all()); let sel: Vec<&Op> = ops.iter().filter(|o| o.name == "MouseSpeed").collect();
        let mut f = Fail(Mem::default()); let mut b = snapshot(&f, Backup::default(), &sel, 1).unwrap();
        let r = do_apply(&mut f, &mut b, &sel, &mut |_, _| {});
        assert!(!r[0].ok && r[0].error.as_deref() == Some("acceso denegado")); assert!(!b.values[0].applied);
    }
    #[test] fn export_writes_identical_bytes_and_never_overwrites() {
        let d = tempfile::tempdir().unwrap(); let p = d.path().display().to_string();
        let r = export_reg_files(p.clone()).unwrap(); assert!(r.iter().all(|s| s.ends_with("exportado")));
        for r in REGS.iter() { assert_eq!(&std::fs::read(d.path().join(r.name)).unwrap()[..], r.bytes); }
        assert!(export_reg_files(p).unwrap().iter().all(|s| s.contains("ya existe")));
    }
    #[test] fn render_roundtrip_matches_source_values() {
        let ops = all_ops(&load_all());
        let o = ops.iter().find(|o| o.file == 8 && o.name == "SystemResponsiveness").unwrap();
        let OpKind::Set(d) = &o.kind else { panic!() }; assert_eq!(render_value(d), "dword:0000000a");
        let o = ops.iter().find(|o| o.file == 7 && o.name == "Flags").unwrap();
        let OpKind::Set(d) = &o.kind else { panic!() }; assert_eq!(render_value(d), "\"1\"");
    }
}
