//! Compatibility / risk findings and cross-file conflict detection. Pure functions: they never change a value, only describe it.
use crate::regfile::{as_dword, as_string, render_value, Op, OpKind, RegData};
use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level { Info, Warning, Danger, Incompatible }

#[derive(Clone, Serialize, Debug)]
pub struct Finding { pub level: Level, pub text: String }
fn f(level: Level, text: impl Into<String>) -> Finding { Finding { level, text: text.into() } }

fn str_int(out: &mut Vec<Finding>, d: &RegData, lo: i64, hi: i64, what: &str) -> Option<i64> {
    let Some(s) = as_string(d) else { out.push(f(Level::Incompatible, format!("{what}: Windows espera REG_SZ (texto) y el archivo trae otro tipo."))); return None };
    match s.trim().parse::<i64>() {
        Err(_) => { out.push(f(Level::Incompatible, format!("{what}: \"{s}\" no es un número entero."))); None }
        Ok(v) if v < lo || v > hi => { out.push(f(Level::Incompatible, format!("{what}: {v} está fuera del rango válido de Windows ({lo}–{hi})."))); Some(v) }
        Ok(v) => Some(v),
    }
}
fn dword(out: &mut Vec<Finding>, d: &RegData, range: Option<(u32, u32)>, what: &str) -> Option<u32> {
    let Some(v) = as_dword(d) else { out.push(f(Level::Incompatible, format!("{what}: Windows espera REG_DWORD y el archivo trae otro tipo."))); return None };
    if let Some((lo, hi)) = range { if v < lo || v > hi { out.push(f(Level::Incompatible, format!("{what}: {v} (0x{v:08x}) está fuera del rango válido {lo}–{hi}."))); } }
    Some(v)
}
fn str_in(out: &mut Vec<Finding>, d: &RegData, allowed: &[&str], what: &str) {
    match as_string(d) {
        None => out.push(f(Level::Incompatible, format!("{what}: Windows espera REG_SZ (texto)."))),
        Some(s) if !allowed.iter().any(|a| a.eq_ignore_ascii_case(&s)) => out.push(f(Level::Incompatible, format!("{what}: \"{s}\" no es un valor válido ({}).", allowed.join(", ")))),
        _ => {}
    }
}

const MM: &str = "software\\microsoft\\windows nt\\currentversion\\multimedia\\systemprofile";

pub fn assess(op: &Op) -> Vec<Finding> {
    let mut o: Vec<Finding> = vec![];
    let OpKind::Set(d) = &op.kind else { o.push(f(Level::Info, "Solo crea la clave (sin valores).")); return o };
    let key = op.key.to_lowercase(); let name = op.name.to_lowercase(); let n = op.name.as_str();
    let undocumented = |o: &mut Vec<Finding>| o.push(f(Level::Warning, format!("'{n}' no está documentado como ajuste de Windows en esta clave; se crearía un valor sin efecto conocido.")));

    match key.as_str() {
        "control panel\\mouse" => match name.as_str() {
            "mousesensitivity" => { str_int(&mut o, d, 1, 20, n); }
            "mousespeed" => { str_int(&mut o, d, 0, 2, n); }
            "mousethreshold1" | "mousethreshold2" => { str_int(&mut o, d, 0, 65535, n); }
            "mousetrails" => { str_int(&mut o, d, 0, 20, n); }
            "mousehovertime" => { if str_int(&mut o, d, 0, 100000, n).is_some() { o.push(f(Level::Info, "Tiempo de hover del puntero (ms). Afecta a cuándo aparecen tooltips; el valor por defecto de Windows es 400.")); } }
            "doubleclickspeed" => { str_int(&mut o, d, 1, 5000, n); }
            "doubleclickheight" | "doubleclickwidth" | "mousehoverheight" => { str_int(&mut o, d, 0, 65535, n); }
            "mousehoverwidth" => { if str_int(&mut o, d, 0, 65535, n) == Some(0) { o.push(f(Level::Info, "Anchura de hover 0 (por defecto 4): inusual; puede alterar cuándo aparecen los tooltips.")); } }
            "activewindowtracking" => { dword(&mut o, d, Some((0, 1)), n); }
            "beep" | "extendedsounds" => str_in(&mut o, d, &["Yes", "No"], n),
            "snaptodefaultbutton" | "swapmousebuttons" => { str_int(&mut o, d, 0, 1, n); }
            "smoothmousexcurve" | "smoothmouseycurve" => {
                if d.vtype != 3 || d.bytes.len() != 40 { o.push(f(Level::Incompatible, format!("{n}: debe ser REG_BINARY de 40 bytes (5 puntos de 8 bytes); aquí hay {} bytes.", d.bytes.len()))); }
                o.push(f(Level::Info, "Curva de aceleración: solo es coherente con escala de pantalla del 100 % y Windows la ignora si MouseSpeed=0."));
            }
            _ => undocumented(&mut o),
        },
        "control panel\\keyboard" => match name.as_str() {
            "keyboarddelay" => { str_int(&mut o, d, 0, 3, n); }
            "keyboardspeed" => { str_int(&mut o, d, 0, 31, n); }
            "initialkeyboardindicators" => { str_int(&mut o, d, 0, 4294967295, n); }
            _ => undocumented(&mut o),
        },
        "control panel\\accessibility\\keyboard response" => match name.as_str() {
            "flags" => {
                if let Some(v) = str_int(&mut o, d, 0, 255, n) {
                    if v & 1 != 0 { o.push(f(Level::Danger, format!("Flags={v} (0x{v:02x}) activa «Teclas de filtro» (bit 0x1): Windows empieza a ignorar/retrasar pulsaciones y puede alterar la repetición y respuesta del teclado."))); }
                }
            }
            "autorepeatdelay" | "autorepeatrate" => {
                if let Some(v) = str_int(&mut o, d, 0, 100000, n) { if v == 0 { o.push(f(Level::Warning, format!("{n}=0 junto a Teclas de filtro puede deshabilitar o alterar la repetición de teclas."))); } }
            }
            "bouncetime" | "delaybeforeacceptance" => { str_int(&mut o, d, 0, 100000, n); }
            "last bouncekey setting" | "last valid delay" | "last valid repeat" | "last valid wait" => { dword(&mut o, d, None, n); }
            _ => undocumented(&mut o),
        },
        "system\\currentcontrolset\\services\\afd\\parameters" => {
            match name.as_str() { "defaultsendwindow" | "defaultreceivewindow" | "fastsenddatagramthreshold" | "fastcopyreceivethreshold" => { dword(&mut o, d, None, n); } _ => undocumented(&mut o) }
            o.push(f(Level::Warning, "Modifica parámetros del servicio de red AFD (HKLM): requiere administrador y reinicio; su efecto no está garantizado ni medido."));
        }
        "system\\currentcontrolset\\services\\kbdclass\\parameters" => {
            match name.as_str() {
                "connectmultipleports" | "keyboarddataqueuesize" | "maximumportsserviced" | "sendoutputtoallports" => { dword(&mut o, d, None, n); }
                "keyboarddevicebasename" => str_in(&mut o, d, &["KeyboardClass"], n),
                "wpprecorder_traceguid" => o.push(f(Level::Warning, "Identificador de traza WPP: no es un ajuste de configuración documentado.")),
                _ => undocumented(&mut o),
            }
            o.push(f(Level::Warning, "Modifica el controlador de teclado de Windows (kbdclass, HKLM): un valor erróneo puede afectar al teclado en el arranque; requiere administrador y reinicio."));
        }
        k if k == MM => match name.as_str() {
            "networkthrottlingindex" => {
                if let Some(v) = dword(&mut o, d, None, n) {
                    if v != 0xFFFF_FFFF && !(1..=70).contains(&v) { o.push(f(Level::Incompatible, format!("NetworkThrottlingIndex=0x{v:08x} no es un valor documentado: Windows admite 1–70 o 0xFFFFFFFF (desactivar). Su efecto no está definido."))); }
                }
            }
            "systemresponsiveness" => { dword(&mut o, d, Some((0, 100)), n); }
            "nolazymode" | "alwayson" => { dword(&mut o, d, Some((0, 1)), n); o.push(f(Level::Warning, format!("'{n}' es un valor de MMCSS que Microsoft no documenta oficialmente."))); }
            _ => undocumented(&mut o),
        },
        k if k.starts_with(&format!("{MM}\\tasks\\")) => {
            let task = op.key.rsplit('\\').next().unwrap_or("");
            match name.as_str() {
                "affinity" | "clock rate" => { dword(&mut o, d, None, n); }
                "background only" => str_in(&mut o, d, &["True", "False"], n),
                "gpu priority" => { dword(&mut o, d, Some((0, 31)), n); }
                "priority" | "backgroundpriority" => { dword(&mut o, d, Some((1, 8)), n); }
                "scheduling category" => str_in(&mut o, d, &["Low", "Medium", "High"], n),
                "sfio priority" => str_in(&mut o, d, &["Idle", "Very Low", "Low", "Normal", "High", "Critical"], n),
                _ => undocumented(&mut o),
            }
            if !task.eq_ignore_ascii_case("games") { o.push(f(Level::Warning, format!("Modifica el perfil multimedia «{task}» de Windows, que usan otras aplicaciones (no solo juegos)."))); }
        }
        _ => o.push(f(Level::Warning, "Clave no reconocida por las reglas de compatibilidad: no se puede validar este valor.")),
    }
    if op.hive == crate::regfile::Hive::Hklm { o.push(f(Level::Info, "Está en HKLM: requiere permisos de administrador.")); }
    o
}
pub fn max_level(fs: &[Finding]) -> Level { fs.iter().map(|x| x.level).max().unwrap_or(Level::Info) }

#[derive(Serialize, Clone, Debug)] pub struct ConflictEntry { pub op_id: String, pub file: u8, pub file_name: String, pub pack: String, pub line: usize, pub value: String }
#[derive(Serialize, Clone, Debug)] pub struct Conflict { pub location: String, pub name: String, pub kind: &'static str, pub entries: Vec<ConflictEntry>, pub winner: String }

/// Same (hive,key,name) written more than once across/inside files. Identical bytes => "duplicate"; different => "conflict" (last one in order wins).
pub fn detect_conflicts(ops: &[Op]) -> Vec<Conflict> {
    let mut groups: Vec<Vec<&Op>> = vec![];
    for op in ops.iter().filter(|o| matches!(o.kind, OpKind::Set(_))) {
        match groups.iter_mut().find(|g| g[0].same_target(op.hive, &op.key, &op.name)) { Some(g) => g.push(op), None => groups.push(vec![op]) }
    }
    groups.into_iter().filter(|g| g.len() > 1).map(|g| {
        let datas: Vec<&RegData> = g.iter().filter_map(|o| if let OpKind::Set(d) = &o.kind { Some(d) } else { None }).collect();
        let same = datas.iter().all(|d| **d == *datas[0]);
        Conflict { location: g[0].location(), name: g[0].name_display(), kind: if same { "duplicate" } else { "conflict" },
            entries: g.iter().zip(datas.iter()).map(|(o, d)| ConflictEntry { op_id: o.id.clone(), file: o.file, file_name: o.file_name.clone(), pack: o.pack.clone(), line: o.line, value: render_value(d) }).collect(),
            winner: g.last().unwrap().id.clone() }
    }).collect()
}
