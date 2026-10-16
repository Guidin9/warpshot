# Read-only: logs every thread that appears in or leaves a process, with its
# description (Rust/tokio thread names) and the module its Win32 start address
# falls in (ntdll+0x24990-style = OS thread pool or loader worker, mswsock =
# Winsock's SockAsyncThread, the exe = our own std threads). For finding what
# pushes the agent over its thread budget (docs/resource-budget.md §4):
#
#   powershell -ExecutionPolicy Bypass -File scripts\watch-threads.ps1 `
#       -ProcessId (Get-Process warpshot-agent).Id -Seconds 600
param([int]$ProcessId, [int]$Seconds = 360, [int]$IntervalMs = 250)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Thr {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, IntPtr retLen);
    [DllImport("kernel32.dll")] static extern int GetThreadDescription(IntPtr h, out IntPtr desc);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    public static long Start(uint tid) {
        IntPtr h = OpenThread(0x0040, false, tid);
        if (h == IntPtr.Zero) return -1;
        IntPtr a; int st = NtQueryInformationThread(h, 9, out a, IntPtr.Size, IntPtr.Zero);
        CloseHandle(h);
        return st == 0 ? a.ToInt64() : -2;
    }
    public static string Name(uint tid) {
        IntPtr h = OpenThread(0x0800, false, tid);
        if (h == IntPtr.Zero) return "";
        IntPtr d; string s = "";
        if (GetThreadDescription(h, out d) >= 0 && d != IntPtr.Zero) { s = Marshal.PtrToStringUni(d); LocalFree(d); }
        CloseHandle(h);
        return s;
    }
}
"@
$p = Get-Process -Id $ProcessId
function Get-Mods {
    $p.Refresh()
    $p.Modules | ForEach-Object {
        [pscustomobject]@{ Name = $_.ModuleName; Base = [int64]$_.BaseAddress; End = [int64]$_.BaseAddress + $_.ModuleMemorySize }
    }
}
$mods = Get-Mods
function Describe([int]$tid) {
    $a = [Thr]::Start([uint32]$tid)
    $where = "0x{0:x}" -f $a
    foreach ($m in $mods) { if ($a -ge $m.Base -and $a -lt $m.End) { $where = "{0}+0x{1:x}" -f $m.Name, ($a - $m.Base); break } }
    $n = [Thr]::Name([uint32]$tid)
    if ($n) { return "$where `"$n`"" }
    return $where
}
$known = @{}
$t0 = Get-Date
"{0:HH:mm:ss.fff} start, {1} threads" -f (Get-Date), $p.Threads.Count
foreach ($t in $p.Threads) { $o = Describe $t.Id; $known[$t.Id] = $o; "  existing {0} {1}" -f $t.Id, $o }
$max = $p.Threads.Count
while (((Get-Date) - $t0).TotalSeconds -lt $Seconds) {
    try { $p.Refresh() } catch { "process gone"; break }
    $now = @{}
    foreach ($t in $p.Threads) {
        $now[$t.Id] = $true
        if (-not $known.ContainsKey($t.Id)) {
            $o = Describe $t.Id
            if ($o -like "0x*") { $mods = Get-Mods; $o = Describe $t.Id }
            $known[$t.Id] = $o
            "{0:HH:mm:ss.fff} +{1} {2} (count {3})" -f (Get-Date), $t.Id, $o, $p.Threads.Count
        }
    }
    foreach ($id in @($known.Keys)) {
        if (-not $now.ContainsKey($id)) { "{0:HH:mm:ss.fff} -{1} {2}" -f (Get-Date), $id, $known[$id]; $known.Remove($id) }
    }
    if ($p.Threads.Count -gt $max) { $max = $p.Threads.Count }
    Start-Sleep -Milliseconds $IntervalMs
}
"{0:HH:mm:ss.fff} end, max {1}" -f (Get-Date), $max
