$ErrorActionPreference = 'Stop'

$defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
    -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notlike '127.*' -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.InterfaceAlias -notmatch 'Loopback'
    })

if ($defaultRoute) {
    $preferred = $addresses | Where-Object { $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex } |
        Select-Object -First 1
    if ($preferred) {
        [Console]::Write($preferred.IPAddress)
        exit 0
    }
}

$fallback = $addresses | Select-Object -First 1
if ($fallback) {
    [Console]::Write($fallback.IPAddress)
    exit 0
}

$cimFallback = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' `
    -ErrorAction SilentlyContinue |
    ForEach-Object { $_.IPAddress } |
    Where-Object {
        $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and
        $_ -notlike '127.*' -and
        $_ -notlike '169.254.*'
    } |
    Select-Object -First 1
if ($cimFallback) {
    [Console]::Write($cimFallback)
    exit 0
}

exit 1
