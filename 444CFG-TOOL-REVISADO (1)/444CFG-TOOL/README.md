# 444CFG TOOL

Aplicación de escritorio para Windows 10/11 (Tauri 2 + Rust + React/TypeScript). Interfaz con la paleta del logo 444 (índigo/lavanda metálico sobre negro).

> **Estado honesto:** el código está completo, pero **no se ha podido compilar** en el entorno donde se generó (sin Rust ni acceso a red). Lo único ejecutado y verificado ahí es el generador de licencias (ver "Pruebas"). La primera compilación en GitHub Actions puede mostrar errores menores de Rust/TS que habrá que corregir.

## 1. Subir a GitHub
Crea un repositorio privado y sube **todo el contenido de esta carpeta** (`.gitignore` ya excluye `private.key`).

## 2. Generar claves (una sola vez)
Abre `key-manager/index.html` en Chrome/Edge → **CREAR CLAVES**. Guarda `private.key` fuera de GitHub (copia de seguridad cifrada).

## 3. Configurar la clave pública
En GitHub ve a **Settings → Secrets and variables → Actions → New repository secret**.
Crea el secreto **`CFG444_PUBLIC_KEY_HEX`** y pega los 64 caracteres hexadecimales de tu `public.key`.
El workflow incorpora esta clave **pública** antes de compilar; el archivo `src-tauri/public.key` conserva un marcador hasta ese momento. **Nunca subas `private.key`**.

## 4. Compilar
GitHub → **Actions → Build Windows → Run workflow**. Al terminar, descarga en *Artifacts*: `444CFG-TOOL-installer` (NSIS) y `444CFG-TOOL-portable-exe`.
Opcional: copia tu vídeo a `public/movement.mp4` antes de compilar para incluirlo en Movement.

## 5. Licencia para un cliente
El cliente abre la app → copia su **HWID** → tú, en el Key Manager, cargas `private.key`, pegas el HWID y pulsas **GENERAR KEY** → se la envías → él pulsa **ACTIVAR LICENCIA**.
Formato: Ed25519 sobre `444CFG|v1|<HWID>`, Base32 sin relleno en bloques de 8. Offline: **no hay caducidad ni revocación remota**.

## 6. Uso
- **Movement:** *Aplicar Movement Tweak* abre una **revisión** con: (1) los **packs** de regedits (444CFG, EREN, GODLEAK; por defecto solo 444CFG) y sus archivos originales (codificación, tamaño, SHA-256), (2) los conflictos entre los archivos activados, (3) las operaciones **en el orden original** (archivo a archivo, línea a línea) con clave, valor actual y valor nuevo **exacto**, y los avisos de cada una. Marcas lo que quieres aplicar y confirmas. Se guarda una copia de seguridad (incluida la ausencia previa de valores/claves) **antes** de escribir, se escribe cada valor tal cual y se verifica leyéndolo de vuelta. Pide administrador solo si hay valores en HKLM. Ofrece reinicio con doble confirmación; nunca reinicia solo.
- **Restaurar original:** muestra a qué valor volverá cada ajuste, recupera los valores reales guardados, elimina los que no existían y las claves que creó la app (si quedan vacías), y lo verifica.
- **Exportar los .reg originales:** copia los 20 archivos, byte a byte, a una carpeta (nunca sobrescribe).
- **FiveM Optimizer:** *Limpiar caché* → vista previa → confirmar. Requiere FiveM cerrado. `nui-storage` es opcional y está desactivado.

## Cómo trata Movement tus .reg (3 packs, 20 archivos)
Los archivos están en `src-tauri/regs/` **sin modificar** (hashes en `SHA256SUMS`, protegidos con `.gitattributes` y comprobados en los tests y en GitHub Actions). La app los incrusta en el EXE y los interpreta con su propio lector; lo que se muestra es exactamente lo que se escribe (tipos y bytes incluidos). No sustituye ni corrige ningún valor.

| Pack | Archivos | Operaciones | Origen |
|---|---|---|---|
| **444CFG** | `444cfg1…8.reg` | 116 | tu ZIP `444-regedit.zip` |
| **EREN** | `eren/erenlolxd.reg`, `…2`, `…3` | 16 | `Erenlolstrafe.rar` |
| **GODLEAK** | `godleak/godleak1…9.reg` | 120 | `GodLeak_Strafe.rar` |

Los `.rar` se extrajeron comprobando el CRC32 de cada archivo contra el que guarda el propio RAR (los 12 coinciden). Los 4 `.txt` del RAR de GodLeak (`godleak.txt`, `OKUMADAN GEÇME !!!.txt`, repetidos) **no se han añadido**: no son regedits, solo publicidad (`discord.gg/godleak`).

- **Packs:** solo se permite un pack cada vez: 444CFG, EREN o GODLEAK. Para cambiar de pack después de aplicar, utiliza **RESTAURAR ORIGINAL** primero. Los archivos y sus valores originales se mantienen intactos.
- **Análisis:** EREN y GODLEAK **no contienen ninguna clave ni valor nuevo**: todo coincide con algo que ya traía 444CFG (mismos objetivos, mismos valores). `godleak9` es igual que `444cfg8` y `godleak8` que `444cfg7`.
- **Orden:** el de cada pack, línea a línea.
- **Texto ajeno:** `444cfg1…8` traen `discord.gg/arizonashaders` (8 veces) y los 3 archivos EREN terminan en una línea con un punto (`.`). Se conserva en los archivos, se avisa y **no se ejecuta**. Los archivos GODLEAK no traen texto ajeno.
- **Conflictos:** 444CFG: 4 reales entre `444cfg5` y `444cfg7` (`AutoRepeatDelay`, `AutoRepeatRate`, `Flags`, `Last Valid Wait`) y 8 duplicados. GODLEAK: los mismos 4 entre `godleak6` y `godleak8` y 12 duplicados. EREN: ninguno. Entre packs distintos también pueden aparecer (p. ej. `Flags`).
- **Marcados NO COMPATIBLE** (fuera de lo que Windows admite): `KeyboardSpeed="50"` (rango 0–31; en 444cfg3, erenlolxd2, godleak1 y godleak4) y `NetworkThrottlingIndex=0x0fffffff` (Windows admite 1–70 o 0xFFFFFFFF; en 444cfg8 y godleak9).
- **Marcados PELIGRO:** `Flags` =59 o =1 (444cfg5/7, erenlolxd, godleak6/8), porque activan «Teclas de filtro» y pueden alterar la respuesta del teclado.
- **Marcados AVISO:** `My Regedit` (no es un ajuste de Windows), `NoLazyMode`/`AlwaysOn` (MMCSS no documentado), AFD y kbdclass (servicios de red/teclado en HKLM), perfiles multimedia distintos de *Games*, y `AutoRepeat*=0`.
- **Seguridad de la aplicación:** lo NO COMPATIBLE o PELIGROSO aparece **desmarcado** por defecto; para aplicarlo debes marcarlo y confirmar expresamente. El backend lo vuelve a exigir (no se puede saltar desde la interfaz).
- Ni FPS, ni ping, ni precisión: no se han medido.
- Nota: los valores de HKCU se escriben en el usuario que ejecuta la app; si la abres como administrador con *otra* cuenta, afectarán a esa cuenta.

> Corrección: en la versión anterior de este README dije que `444cfg4.reg` estaba «corrupto». Era un error mío: está guardado en ANSI (sin BOM) y es válido. Esta versión lo lee y lo aplica con normalidad.

## Pruebas
- Ejecutadas: `node key-manager/test/compat.mjs` (firma del navegador verificada con OpenSSL; HWID/prefijo distinto falla). El vector resultante está en los tests de `license.rs`.
- Escritas pero **no ejecutadas** (sin cargo): `cargo test --manifest-path src-tauri/Cargo.toml`: integridad de los 20 .reg, parser (252 operaciones, orden, texto ajeno), conflictos por pack, que EREN/GODLEAK no traigan valores nuevos, valores no compatibles/peligrosos, aplicar→restaurar sobre un registro simulado en memoria (estado idéntico al inicial), licencia y limpiador de caché.
- Ejecutada: comprobación de tipos de TypeScript con declaraciones mínimas de React/Tauri (sin errores propios). `npm run typecheck` real, la compilación de Rust y de Tauri **no** se han ejecutado.

## Pendiente / limitaciones
- Sin `package-lock.json` (sin red); el workflow usa `npm install` sin la opción de caché de npm que requería el archivo de bloqueo. Conviene generar y versionar el lockfile cuando sea posible.
- NVIDIA/GPU: solo detección, estado de HAGS (lectura) y accesos a Ajustes de Windows. No modifica nada.
- Vídeo: no adjuntado; el reproductor permite elegir archivo o usar `public/movement.mp4`.
- Probar los cambios de Registro solo en una VM o equipo de pruebas.
- Discord: https://discord.gg/444cfg

## Correcciones de la revisión de noviembre de 2026

- GitHub Actions toma la clave pública de `CFG444_PUBLIC_KEY_HEX`, y falla explícitamente si falta o no tiene 64 caracteres hexadecimales. **No hace falta enviar ni publicar la clave privada.**
- Retirada la opción de cachear npm sin `package-lock.json` para evitar un fallo temprano del workflow.
- Movement solo acepta operaciones de **un pack** por aplicación, incluso desde el backend. Guarda el estado potencialmente modificado **antes** de escribir el Registro, de modo que una interrupción posterior deja información suficiente para intentar restaurar.
- El limpiador de FiveM comprueba adicionalmente que `FiveM.app` no sea un enlace de redirección y utiliza `symlink_metadata` al explorar y borrar archivos.
- Un backup con claves nuevas pero sin valores también habilita la opción de restaurar.

**No se ha ejecutado aquí una compilación Windows ni se ha probado la modificación real del Registro.** Antes de distribuir, ejecuta GitHub Actions y prueba la herramienta en una máquina virtual o de pruebas. Las advertencias sobre valores no compatibles de los archivos originales siguen vigentes.
