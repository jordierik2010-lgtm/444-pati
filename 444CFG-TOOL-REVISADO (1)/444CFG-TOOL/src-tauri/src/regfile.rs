//! Parser for Windows .reg files (REGEDIT5). It NEVER rewrites values: what is parsed is exactly what is shown and what is applied.
//! Unknown lines (e.g. advertising text pasted in the files) are reported as "foreign" and ignored, never executed.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum Hive { Hkcu, Hklm }
impl Hive {
    pub fn short(self) -> &'static str { match self { Hive::Hkcu => "HKCU", Hive::Hklm => "HKLM" } }
    fn from_root(r: &str) -> Option<Hive> {
        match r.to_uppercase().as_str() { "HKEY_CURRENT_USER" | "HKCU" => Some(Hive::Hkcu), "HKEY_LOCAL_MACHINE" | "HKLM" => Some(Hive::Hklm), _ => None }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegData { pub vtype: u32, pub bytes: Vec<u8> }

#[derive(Clone, Debug)]
pub enum OpKind { Set(RegData), KeyOnly }

#[derive(Clone, Debug)]
pub struct Op {
    pub id: String,        // "<file>:<n>", n counts operations in file order
    pub file: u8,
    pub file_name: String, // filled by movement::load_all
    pub pack: String,      // filled by movement::load_all
    pub line: usize,
    pub hive: Hive,
    pub key: String,       // without root, original capitalisation
    pub name: String,      // "" = default value (@)
    pub kind: OpKind,
    pub source: String,    // original text of the line(s), verbatim
}
impl Op {
    pub fn location(&self) -> String { format!("{}\\{}", self.hive.short(), self.key) }
    pub fn name_display(&self) -> String { if self.name.is_empty() { "@".into() } else { format!("\"{}\"", self.name) } }
    pub fn same_target(&self, h: Hive, key: &str, name: &str) -> bool { self.hive == h && self.key.eq_ignore_ascii_case(key) && self.name.eq_ignore_ascii_case(name) }
}

#[derive(Clone, Debug)]
pub struct Foreign { pub line: usize, pub text: String }

#[derive(Default, Debug)]
pub struct Parsed { pub ops: Vec<Op>, pub foreign: Vec<Foreign>, pub errors: Vec<String>, pub encoding: &'static str }

pub fn decode(b: &[u8]) -> (String, &'static str) {
    if b.starts_with(&[0xFF, 0xFE]) {
        let u: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        (String::from_utf16_lossy(&u), "UTF-16 LE")
    } else if b.starts_with(&[0xFE, 0xFF]) {
        let u: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        (String::from_utf16_lossy(&u), "UTF-16 BE")
    } else if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (String::from_utf8_lossy(&b[3..]).into_owned(), "UTF-8 (BOM)")
    } else {
        (String::from_utf8_lossy(b).into_owned(), "ANSI/ASCII (sin BOM)")
    }
}

pub fn utf16z(s: &str) -> Vec<u8> { s.encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect() }

fn parse_name(t: &str) -> Option<(String, &str)> {
    if let Some(r) = t.strip_prefix('@') { return r.trim_start().strip_prefix('=').map(|x| (String::new(), x.trim())); }
    let mut name = String::new(); let mut esc = false;
    for (i, c) in t[1..].char_indices() {
        if esc { name.push(c); esc = false; }
        else if c == '\\' { esc = true; }
        else if c == '"' { return t[1 + i + 1..].trim_start().strip_prefix('=').map(|x| (name, x.trim())); }
        else { name.push(c); }
    }
    None
}

fn parse_value(v: &str) -> Result<RegData, String> {
    if let Some(rest) = v.strip_prefix('"') {
        let mut s = String::new(); let mut esc = false; let mut end = None;
        for (i, c) in rest.char_indices() {
            if esc { s.push(c); esc = false; } else if c == '\\' { esc = true; } else if c == '"' { end = Some(i); break; } else { s.push(c); }
        }
        let i = end.ok_or("cadena sin cerrar")?;
        let tail = rest[i + 1..].trim();
        if !tail.is_empty() && !tail.starts_with(';') { return Err("texto inesperado tras la cadena".into()); }
        Ok(RegData { vtype: 1, bytes: utf16z(&s) })
    } else if let Some(h) = v.strip_prefix("dword:") {
        let h = h.trim();
        if h.len() != 8 || !h.chars().all(|c| c.is_ascii_hexdigit()) { return Err("dword debe tener 8 dígitos hexadecimales".into()); }
        Ok(RegData { vtype: 4, bytes: u32::from_str_radix(h, 16).map_err(|e| e.to_string())?.to_le_bytes().to_vec() })
    } else if let Some(rest) = v.strip_prefix("hex") {
        let (vtype, data) = if let Some(d) = rest.strip_prefix(':') { (3u32, d) }
            else if let Some(r2) = rest.strip_prefix('(') {
                let (n, d) = r2.split_once("):").ok_or("hex(N) mal formado")?;
                (u32::from_str_radix(n.trim(), 16).map_err(|_| "tipo hex(N) inválido".to_string())?, d)
            } else { return Err("valor hex mal formado".into()) };
        let mut bytes = vec![];
        for part in data.split(',') {
            let p = part.trim();
            if p.is_empty() { continue; }
            if p.len() > 2 { return Err(format!("byte hexadecimal inválido '{p}'")); }
            bytes.push(u8::from_str_radix(p, 16).map_err(|_| format!("byte hexadecimal inválido '{p}'"))?);
        }
        Ok(RegData { vtype, bytes })
    } else if v == "-" { Err("eliminación de valores no soportada".into()) }
    else { Err("tipo de valor no reconocido".into()) }
}

fn push_key_only(p: &mut Parsed, file: u8, idx: &mut usize, line: usize, hive: Hive, key: &str, src: &str) {
    *idx += 1;
    p.ops.push(Op { id: format!("{file}:{idx}"), file, file_name: String::new(), pack: String::new(), line, hive, key: key.to_string(), name: String::new(), kind: OpKind::KeyOnly, source: src.to_string() });
}

pub fn parse(file: u8, bytes: &[u8]) -> Parsed {
    const HEADER: &str = "Windows Registry Editor Version 5.00";
    let (text, enc) = decode(bytes);
    let mut p = Parsed { encoding: enc, ..Default::default() };
    let raw: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();

    // logical lines (hex values may continue with a trailing backslash)
    let mut logical: Vec<(usize, String, String)> = vec![];
    let mut i = 0;
    while i < raw.len() {
        let start = i + 1;
        let mut joined = raw[i].trim_end().to_string();
        let mut orig = raw[i].to_string();
        if joined.contains("=hex") {
            while joined.ends_with('\\') && i + 1 < raw.len() {
                joined.pop(); i += 1; joined.push_str(raw[i].trim()); orig.push('\n'); orig.push_str(raw[i]);
            }
        }
        logical.push((start, joined, orig)); i += 1;
    }

    let (mut seen_first, mut header_ok) = (false, false);
    let mut cur: Option<(Hive, String, usize, String)> = None; // hive, key, line, source
    let mut has_values = false; let mut skip_section = false; let mut idx = 0usize;

    for (ln, s, orig) in logical {
        let t = s.trim().trim_start_matches('\u{feff}');
        if t.is_empty() { continue; }
        if !seen_first {
            seen_first = true;
            if let Some(rest) = t.strip_prefix(HEADER) {
                header_ok = true;
                let r = rest.trim();
                if !r.is_empty() { p.foreign.push(Foreign { line: ln, text: r.to_string() }); }
            } else { p.errors.push(format!("Línea {ln}: cabecera no reconocida (se esperaba '{HEADER}'); este archivo no se aplica.")); }
            continue;
        }
        if !header_ok || t.starts_with(';') { continue; }

        if t.starts_with('[') {
            if let Some((h, k, l, src)) = cur.take() { if !has_values { push_key_only(&mut p, file, &mut idx, l, h, &k, &src); } }
            has_values = false; skip_section = false;
            if !t.ends_with(']') { p.errors.push(format!("Línea {ln}: sección mal formada.")); skip_section = true; continue; }
            let inner = &t[1..t.len() - 1];
            if inner.starts_with('-') { p.errors.push(format!("Línea {ln}: borrado de claves no soportado; omitido.")); skip_section = true; continue; }
            let (root, rest) = inner.split_once('\\').unwrap_or((inner, ""));
            match Hive::from_root(root) {
                Some(h) if !rest.is_empty() => cur = Some((h, rest.to_string(), ln, orig)),
                Some(_) => { p.errors.push(format!("Línea {ln}: no se permiten claves raíz.")); skip_section = true; }
                None => { p.errors.push(format!("Línea {ln}: hive '{root}' no soportado; sección omitida.")); skip_section = true; }
            }
            continue;
        }
        if t.starts_with('"') || t.starts_with('@') {
            match parse_name(t) {
                Some((name, val)) => {
                    let Some((h, k, _, _)) = cur.as_ref() else {
                        if !skip_section { p.errors.push(format!("Línea {ln}: valor fuera de una sección.")); } else { p.errors.push(format!("Línea {ln}: valor omitido (sección no soportada).")); }
                        continue; };
                    match parse_value(val) {
                        Ok(d) => { has_values = true; idx += 1;
                            p.ops.push(Op { id: format!("{file}:{idx}"), file, file_name: String::new(), pack: String::new(), line: ln, hive: *h, key: k.clone(), name, kind: OpKind::Set(d), source: orig }); }
                        Err(e) => p.errors.push(format!("Línea {ln}: {e}; valor omitido.")),
                    }
                }
                None => p.errors.push(format!("Línea {ln}: nombre de valor mal formado.")),
            }
            continue;
        }
        p.foreign.push(Foreign { line: ln, text: t.to_string() });
    }
    if let Some((h, k, l, src)) = cur.take() { if !has_values { push_key_only(&mut p, file, &mut idx, l, h, &k, &src); } }
    p
}

fn hexlist(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(",") }

/// Canonical .reg text of a value (what will be written, byte for byte).
pub fn render_value(d: &RegData) -> String {
    match d.vtype {
        1 => {
            let u: Vec<u16> = d.bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let s = String::from_utf16_lossy(&u); let s = s.trim_end_matches('\0');
            format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
        }
        4 if d.bytes.len() == 4 => format!("dword:{:08x}", u32::from_le_bytes([d.bytes[0], d.bytes[1], d.bytes[2], d.bytes[3]])),
        3 => format!("hex:{}", hexlist(&d.bytes)),
        n => format!("hex({:x}):{}", n, hexlist(&d.bytes)),
    }
}
pub fn as_string(d: &RegData) -> Option<String> {
    if d.vtype != 1 { return None; }
    let u: Vec<u16> = d.bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&u).trim_end_matches('\0').to_string())
}
pub fn as_dword(d: &RegData) -> Option<u32> { if d.vtype == 4 && d.bytes.len() == 4 { Some(u32::from_le_bytes([d.bytes[0], d.bytes[1], d.bytes[2], d.bytes[3]])) } else { None } }
