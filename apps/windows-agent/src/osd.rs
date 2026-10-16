//! On-screen flyout for hotkey sends: a small pill above the taskbar
//! ("Sending to …" → "Waking …" → progress bar → "Sent" / "Not sent: …").
//! Toasts are not enough for this: Windows hides their banners during
//! full-screen apps, games and streams.
//!
//! The window is created on demand on the UI thread, never takes focus, lets
//! clicks through, and is destroyed when it hides, so nothing stays resident
//! at idle (resource-budget.md §2). Its timers exist only while it is shown.

// Pixel geometry on OS-reported screen and text sizes (a few thousand pixels at
// most): plain i32 arithmetic cannot overflow here and reads like the layout.
#![allow(clippy::arithmetic_side_effects)]

use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM},
    Graphics::Gdi::{
        BITMAPINFO, BITMAPINFOHEADER, BeginPaint, CreateCompatibleDC, CreateDIBSection,
        CreateFontW, CreateRoundRectRgn, CreateSolidBrush, DIB_RGB_COLORS, DT_CALCRECT,
        DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DeleteDC, DeleteObject,
        DrawTextW, EndPaint, FillRect, FillRgn, FrameRgn, GdiFlush, GetDC, GetMonitorInfoW, HDC,
        HGDIOBJ, InvalidateRect, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint,
        PAINTSTRUCT, PtInRegion, ReleaseDC, SelectObject, SetBkMode, SetTextColor, SetWindowRgn,
        TRANSPARENT,
    },
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        HiDpi::GetDpiForWindow,
        WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, GetClientRect, GetCursorPos,
            HWND_TOPMOST, KillTimer, LWA_ALPHA, RegisterClassW, SW_SHOWNOACTIVATE, SWP_NOACTIVATE,
            SetLayeredWindowAttributes, SetTimer, SetWindowPos, ShowWindow, WM_DESTROY,
            WM_NCHITTEST, WM_PAINT, WM_TIMER, WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE,
            WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
        },
    },
};

use crate::{i18n::is_tr, l10n, win::wide};

/// What the flyout reports; picks the accent colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Busy,
    Ok,
    Error,
}

/// One progress report of a send, as the flyout shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendProgress {
    pub peer: String,
    pub done: u64,
    pub total: u64,
    pub bytes_per_sec: u64,
}

/// The bar under the text while bytes are moving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bar {
    /// 0..=1000.
    pub permille: u16,
    /// No bytes for [`STALL_AFTER`]: the bar and the dot turn amber.
    pub stalled: bool,
}

/// How long a result stays on screen.
pub const RESULT_FOR: Duration = Duration::from_millis(2500);
/// A "busy" flyout hides by itself after this, in case no result ever comes
/// (longer than the sender's pending-session TTL of 120 s).
pub const BUSY_MAX: Duration = Duration::from_secs(130);
/// No new bytes for this long: say so instead of a stale speed. The core
/// reports at least every 250 ms while bytes flow (and a stream with no
/// progress for 30 s fails), so this is a real stall, not a slow link.
pub const STALL_AFTER: Duration = Duration::from_secs(5);

const CLASS: &str = "WarpshotFlyout";
const TIMER_HIDE: usize = 1;
/// Re-checks for a stall once a second; exists only while a bar is shown.
const TIMER_TICK: usize = 2;
const HTTRANSPARENT: LRESULT = -1;
/// Height of the strip that holds the bar, at 96 dpi.
const BAR_STRIP: i32 = 12;
/// Narrowest pill with a bar, at 96 dpi.
const MIN_BAR_W: i32 = 340;

struct State {
    hwnd: HWND,
    text: Vec<u16>,
    tone: Tone,
    /// The last report and when its byte count last changed.
    progress: Option<(SendProgress, Instant)>,
    /// Width while a bar is shown: grows, never shrinks, so the pill doesn't
    /// jitter as the numbers change.
    min_w: i32,
}

impl State {
    fn bar(&self) -> Option<Bar> {
        self.progress.as_ref().map(|(p, since)| Bar {
            permille: permille(p.done, p.total),
            stalled: since.elapsed() >= STALL_AFTER,
        })
    }
}

fn permille(done: u64, total: u64) -> u16 {
    if total == 0 {
        return 0;
    }
    let v = u128::from(done.min(total)) * 1000 / u128::from(total);
    u16::try_from(v).unwrap_or(1000)
}

/// "12.3 MB" (decimal units, like Android's short file sizes), with a decimal
/// comma in Turkish.
pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut unit = 0usize;
    let mut tenths = u128::from(b) * 10;
    while tenths >= 10_000 && unit < UNITS.len() - 1 {
        tenths /= 1000;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("GB");
    if unit == 0 || tenths >= 1000 {
        // Whole numbers for bytes and for values of 100 or more.
        return format!("{} {name}", tenths / 10);
    }
    let sep = if is_tr() { ',' } else { '.' };
    format!("{}{sep}{} {name}", tenths / 10, tenths % 10)
}

/// "S21 FE · %42 · 12,3 MB / 30 MB · 5,1 MB/sn", with the stall note in place
/// of the speed.
pub fn progress_text(p: &SendProgress, stalled_for: Option<Duration>) -> String {
    let pct = permille(p.done, p.total) / 10;
    let mut parts = vec![p.peer.clone(), l10n!("{} %", "%{}", pct)];
    if p.total > 0 {
        parts.push(format!("{} / {}", fmt_bytes(p.done), fmt_bytes(p.total)));
    }
    match stalled_for {
        Some(d) => parts.push(l10n!("no data for {} s", "{} sn'dir veri yok", d.as_secs())),
        None if p.bytes_per_sec > 0 => {
            parts.push(l10n!("{}/s", "{}/sn", fmt_bytes(p.bytes_per_sec)));
        }
        None => {}
    }
    parts.join(" · ")
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static CLASS_REGISTERED: RefCell<bool> = const { RefCell::new(false) };
}

/// Shows (or updates) the flyout. UI thread only. It hides after
/// [`RESULT_FOR`] for results and [`BUSY_MAX`] for busy states.
pub fn show(text: &str, tone: Tone) {
    let Some(hwnd) = window() else {
        return;
    };
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            hwnd,
            text: text.encode_utf16().collect(),
            tone,
            progress: None,
            min_w: 0,
        });
    });
    // SAFETY: our own window on this thread (no-op if the timer is not set).
    unsafe { KillTimer(hwnd, TIMER_TICK) };
    present(
        hwnd,
        if tone == Tone::Busy {
            BUSY_MAX
        } else {
            RESULT_FOR
        },
    );
}

/// Shows a send's progress with a bar. UI thread only. Reports come up to four
/// times a second; the pill keeps its width while the numbers change.
pub fn show_progress(p: &SendProgress) {
    let Some(hwnd) = window() else {
        return;
    };
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let (since, min_w) = match s.as_ref() {
            Some(st) => match &st.progress {
                // Same bytes as before: keep counting towards a stall.
                Some((old, since)) if old.done == p.done => (*since, st.min_w),
                Some(_) => (Instant::now(), st.min_w),
                None => (Instant::now(), 0),
            },
            None => (Instant::now(), 0),
        };
        *s = Some(State {
            hwnd,
            text: Vec::new(),
            tone: Tone::Busy,
            progress: Some((p.clone(), since)),
            min_w,
        });
    });
    // SAFETY: our own window on this thread; SetTimer replaces a timer with the
    // same id.
    unsafe { SetTimer(hwnd, TIMER_TICK, 1000, None) };
    update_text(hwnd);
    present(hwnd, BUSY_MAX);
}

/// The existing flyout window, or a new one.
fn window() -> Option<HWND> {
    STATE
        .with(|s| s.borrow().as_ref().map(|st| st.hwnd))
        .or_else(create)
}

/// Sizes, repaints and shows the window; it hides after `hide_after`.
fn present(hwnd: HWND, hide_after: Duration) {
    layout(hwnd);
    let ms = u32::try_from(hide_after.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: our own window on this thread; SetTimer replaces a timer with the
    // same id, InvalidateRect queues a repaint.
    unsafe {
        SetTimer(hwnd, TIMER_HIDE, ms, None);
        InvalidateRect(hwnd, std::ptr::null(), 1);
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    }
}

/// Rebuilds the progress text: the speed, or the stall note once no bytes
/// came for [`STALL_AFTER`]. Returns whether it changed.
fn update_text(hwnd: HWND) -> bool {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let Some(st) = s.as_mut().filter(|st| st.hwnd == hwnd) else {
            return false;
        };
        let Some((p, since)) = &st.progress else {
            return false;
        };
        let idle = since.elapsed();
        let text: Vec<u16> = progress_text(p, (idle >= STALL_AFTER).then_some(idle))
            .encode_utf16()
            .collect();
        let changed = text != st.text;
        st.text = text;
        changed
    })
}

/// Hides and destroys the flyout if it is shown.
pub fn hide() {
    if let Some(h) = STATE.with(|s| s.borrow().as_ref().map(|st| st.hwnd)) {
        // SAFETY: our own window on this thread; WM_DESTROY clears the state.
        unsafe { DestroyWindow(h) };
    }
}

pub fn is_shown() -> bool {
    STATE.with(|s| s.borrow().is_some())
}

fn create() -> Option<HWND> {
    let class = wide(CLASS);
    // SAFETY: registers our class once and creates a hidden popup owned by this
    // thread; the strings outlive the calls.
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        if !CLASS_REGISTERED.with(|r| *r.borrow()) {
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: hinst,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            if RegisterClassW(&wc) == 0 {
                return None;
            }
            CLASS_REGISTERED.with(|r| *r.borrow_mut() = true);
        }
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT | WS_EX_LAYERED,
            class.as_ptr(),
            class.as_ptr(),
            WS_POPUP,
            0,
            0,
            1,
            1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return None;
        }
        SetLayeredWindowAttributes(hwnd, 0, 245, LWA_ALPHA);
        Some(hwnd)
    }
}

/// Scales a 96-dpi length to the window's DPI.
fn px(v: i32, dpi: u32) -> i32 {
    let dpi = i32::try_from(dpi).unwrap_or(96).max(96);
    v.saturating_mul(dpi) / 96
}

fn font(dpi: u32) -> HGDIOBJ {
    let face = wide("Segoe UI");
    // SAFETY: plain font creation; the caller deletes the object.
    unsafe {
        CreateFontW(
            -px(15, dpi),
            0,
            0,
            0,
            600,
            0,
            0,
            0,
            1, // DEFAULT_CHARSET
            0,
            0,
            5, // CLEARTYPE_QUALITY
            0,
            face.as_ptr(),
        )
    }
}

/// Sizes the pill to its text and puts it above the taskbar of the monitor
/// under the cursor.
fn layout(hwnd: HWND) {
    let Some((text, bar, min_w)) = STATE.with(|s| {
        s.borrow()
            .as_ref()
            .map(|st| (st.text.clone(), st.progress.is_some(), st.min_w))
    }) else {
        return;
    };
    // SAFETY: our own window; the DC and font are released/deleted below; all
    // structs are plain data.
    unsafe {
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        let mon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = u32::try_from(std::mem::size_of::<MONITORINFO>()).unwrap_or(0);
        if GetMonitorInfoW(mon, &mut mi) == 0 {
            return;
        }
        let work = mi.rcWork;
        // Move onto that monitor first so GetDpiForWindow reports its DPI.
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            work.left,
            work.top,
            1,
            1,
            SWP_NOACTIVATE,
        );
        let dpi = GetDpiForWindow(hwnd);
        let dc = GetDC(hwnd);
        let (text_w, h) = measure(dc, &text, dpi, bar);
        ReleaseDC(hwnd, dc);
        let max_w = (work.right - work.left) / 2;
        let w = if bar {
            text_w.max(min_w).max(px(MIN_BAR_W, dpi)).min(max_w)
        } else {
            text_w.min(max_w)
        };
        if bar {
            STATE.with(|s| {
                if let Some(st) = s.borrow_mut().as_mut() {
                    st.min_w = w;
                }
            });
        }
        let margin = px(12, dpi);
        let x = work.right - w - margin;
        let y = work.bottom - h - margin;
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE);
        let radius = px(16, dpi);
        // The window owns the region after SetWindowRgn.
        SetWindowRgn(
            hwnd,
            CreateRoundRectRgn(0, 0, w + 1, h + 1, radius, radius),
            1,
        );
    }
}

/// Light or dark, following the apps theme.
fn dark_theme() -> bool {
    windows_registry::CURRENT_USER
        .open(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        .and_then(|k| k.get_u32("AppsUseLightTheme"))
        .map(|v| v == 0)
        .unwrap_or(false)
}

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

fn paint(hwnd: HWND) {
    let Some((text, tone, bar)) = STATE.with(|s| {
        s.borrow()
            .as_ref()
            .filter(|st| st.hwnd == hwnd)
            .map(|st| (st.text.clone(), st.tone, st.bar()))
    }) else {
        return;
    };
    // SAFETY: standard WM_PAINT sequence on our own window.
    unsafe {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let dc = BeginPaint(hwnd, &mut ps);
        let mut client = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        GetClientRect(hwnd, &mut client);
        draw(
            dc,
            client,
            GetDpiForWindow(hwnd),
            &text,
            tone,
            bar,
            dark_theme(),
        );
        EndPaint(hwnd, &ps);
    }
}

/// Draws the pill into `dc` (window or memory DC). Every GDI object created
/// here is deleted before returning.
fn draw(dc: HDC, client: RECT, dpi: u32, text: &[u16], tone: Tone, bar: Option<Bar>, dark: bool) {
    let (bg, fg, border) = if dark {
        (
            rgb(0x2b, 0x2b, 0x2b),
            rgb(0xff, 0xff, 0xff),
            rgb(0x45, 0x45, 0x45),
        )
    } else {
        (
            rgb(0xf9, 0xf9, 0xf9),
            rgb(0x1a, 0x1a, 0x1a),
            rgb(0xd0, 0xd0, 0xd0),
        )
    };
    let accent = match (tone, bar) {
        (_, Some(Bar { stalled: true, .. })) => rgb(0xc8, 0x82, 0x00),
        (Tone::Busy, _) => rgb(0x00, 0x78, 0xd4),
        (Tone::Ok, _) => rgb(0x10, 0x7c, 0x10),
        (Tone::Error, _) => rgb(0xc4, 0x2b, 0x1c),
    };
    // With a bar, the text row is the pill minus the bar strip.
    let text_bottom = if bar.is_some() {
        client.bottom - px(BAR_STRIP, dpi)
    } else {
        client.bottom
    };
    // SAFETY: GDI calls on a valid DC; objects are deleted after use.
    unsafe {
        let bg_brush = CreateSolidBrush(bg);
        FillRect(dc, &client, bg_brush);
        DeleteObject(bg_brush);
        // Status dot.
        let d = px(10, dpi);
        let cx = px(18, dpi);
        let cy = (text_bottom - client.top) / 2;
        let dot = CreateRoundRectRgn(cx - d / 2, cy - d / 2, cx + d / 2 + 1, cy + d / 2 + 1, d, d);
        let accent_brush = CreateSolidBrush(accent);
        FillRgn(dc, dot, accent_brush);
        DeleteObject(accent_brush);
        DeleteObject(dot);
        // Border along the rounded edge.
        let radius = px(16, dpi);
        let edge = CreateRoundRectRgn(0, 0, client.right, client.bottom, radius, radius);
        let border_brush = CreateSolidBrush(border);
        FrameRgn(dc, edge, border_brush, 1, 1);
        DeleteObject(border_brush);
        DeleteObject(edge);
        // Text.
        let f = font(dpi);
        let old = SelectObject(dc, f);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, fg);
        let mut r = RECT {
            left: px(32, dpi),
            top: 0,
            right: client.right - px(12, dpi),
            bottom: text_bottom,
        };
        let len = i32::try_from(text.len()).unwrap_or(0);
        DrawTextW(
            dc,
            text.as_ptr(),
            len,
            &mut r,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
        );
        SelectObject(dc, old);
        DeleteObject(f);
        if let Some(b) = bar {
            // Rounded track and fill, aligned with the text, in the strip below it.
            let (left, right) = (px(32, dpi), client.right - px(16, dpi));
            let h = px(4, dpi);
            let top = text_bottom - px(4, dpi);
            let fill_w = (right - left) * i32::from(b.permille) / 1000;
            let track = CreateRoundRectRgn(left, top, right + 1, top + h + 1, h, h);
            let track_brush = CreateSolidBrush(border);
            FillRgn(dc, track, track_brush);
            DeleteObject(track_brush);
            DeleteObject(track);
            if fill_w > 0 {
                let fill = CreateRoundRectRgn(left, top, left + fill_w + 1, top + h + 1, h, h);
                let fill_brush = CreateSolidBrush(accent);
                FillRgn(dc, fill, fill_brush);
                DeleteObject(fill_brush);
                DeleteObject(fill);
            }
        }
    }
}

/// Pill size for `text` at `dpi` (before clamping to the screen).
fn measure(dc: HDC, text: &[u16], dpi: u32, bar: bool) -> (i32, i32) {
    // SAFETY: font selected into a valid DC and restored/deleted afterwards.
    unsafe {
        let f = font(dpi);
        let old = SelectObject(dc, f);
        let mut r = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        let len = i32::try_from(text.len()).unwrap_or(0);
        DrawTextW(
            dc,
            text.as_ptr(),
            len,
            &mut r,
            DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
        );
        SelectObject(dc, old);
        DeleteObject(f);
        let h = if bar { 44 + BAR_STRIP } else { 44 };
        (r.right - r.left + px(44, dpi), px(h, dpi))
    }
}

/// Renders the flyout off-screen to PNG (dev check: `--render-flyout`), with
/// the area outside the rounded shape transparent. Never touches the screen.
pub fn render_png(
    text: &str,
    tone: Tone,
    bar: Option<Bar>,
    dark: bool,
    dpi: u32,
) -> Option<Vec<u8>> {
    let text: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: memory DC and DIB section owned here and released before return;
    // `bits` points at w*h*4 bytes while the bitmap lives.
    unsafe {
        let dc = CreateCompatibleDC(std::ptr::null_mut());
        if dc.is_null() {
            return None;
        }
        let (w, h) = measure(dc, &text, dpi, bar.is_some());
        let w = if bar.is_some() {
            w.max(px(MIN_BAR_W, dpi))
        } else {
            w
        };
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = u32::try_from(std::mem::size_of::<BITMAPINFOHEADER>()).unwrap_or(0);
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h; // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let bmp = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        if bmp.is_null() || bits.is_null() {
            DeleteDC(dc);
            return None;
        }
        let old = SelectObject(dc, bmp);
        let client = RECT {
            left: 0,
            top: 0,
            right: w,
            bottom: h,
        };
        draw(dc, client, dpi, &text, tone, bar, dark);
        GdiFlush();
        let n = usize::try_from(w * h * 4).unwrap_or(0);
        let bgra = std::slice::from_raw_parts(bits.cast::<u8>(), n);
        let radius = px(16, dpi);
        let shape = CreateRoundRectRgn(0, 0, w + 1, h + 1, radius, radius);
        let mut rgba = Vec::with_capacity(n);
        for (i, [b, g, r, _]) in bgra.as_chunks::<4>().0.iter().enumerate() {
            let i = i32::try_from(i).unwrap_or(0);
            let inside = PtInRegion(shape, i % w, i / w) != 0;
            rgba.extend_from_slice(&[*r, *g, *b, if inside { 255 } else { 0 }]);
        }
        DeleteObject(shape);
        SelectObject(dc, old);
        DeleteObject(bmp);
        DeleteDC(dc);
        crate::image::encode_png(
            u32::try_from(w).ok()?,
            u32::try_from(h).ok()?,
            png::ColorType::Rgba,
            &rgba,
        )
        .ok()
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            paint(hwnd);
            0
        }
        WM_TIMER if wp == TIMER_HIDE => {
            // SAFETY: our own window on this thread.
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_TIMER if wp == TIMER_TICK => {
            if update_text(hwnd) {
                layout(hwnd);
                // SAFETY: our own window on this thread.
                unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
            }
            0
        }
        // Click-through even where WS_EX_TRANSPARENT is not honoured.
        WM_NCHITTEST => HTTRANSPARENT,
        WM_DESTROY => {
            // SAFETY: our own timers (no-op if already gone).
            unsafe {
                KillTimer(hwnd, TIMER_HIDE);
                KillTimer(hwnd, TIMER_TICK);
            }
            STATE.with(|s| {
                let mut s = s.borrow_mut();
                if s.as_ref().is_some_and(|st| st.hwnd == hwnd) {
                    *s = None;
                }
            });
            0
        }
        // SAFETY: default handling for everything else.
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_permille() {
        let dot = if is_tr() { "," } else { "." };
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(999), "999 B");
        assert_eq!(fmt_bytes(1_500), format!("1{dot}5 KB"));
        assert_eq!(fmt_bytes(12_345_678), format!("12{dot}3 MB"));
        assert_eq!(fmt_bytes(250_000_000), "250 MB");
        assert_eq!(fmt_bytes(3_210_000_000), format!("3{dot}2 GB"));
        assert_eq!(fmt_bytes(u64::MAX), "18446744073 GB");
        assert_eq!(permille(0, 0), 0);
        assert_eq!(permille(5, 10), 500);
        assert_eq!(permille(20, 10), 1000);
        assert_eq!(permille(u64::MAX, u64::MAX), 1000);
    }

    #[test]
    fn progress_text_has_speed_or_stall() {
        let p = SendProgress {
            peer: "S21 FE".into(),
            done: 12_300_000,
            total: 30_000_000,
            bytes_per_sec: 5_100_000,
        };
        let t = progress_text(&p, None);
        assert!(t.starts_with("S21 FE · ") && t.contains("41"), "{t}");
        assert!(t.ends_with("/s") || t.ends_with("/sn"), "{t}");
        let s = progress_text(&p, Some(Duration::from_secs(7)));
        assert!(
            s.contains('7') && !s.ends_with("/s") && !s.ends_with("/sn"),
            "{s}"
        );
    }
}
