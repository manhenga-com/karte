$ErrorActionPreference = "SilentlyContinue"

function Test-PortOpen {
    param ([int] $Port)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        $open = $connect.AsyncWaitHandle.WaitOne(300, $false)
        if ($open -and $client.Connected) {
            $client.EndConnect($connect)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

foreach ($port in 8008..8020) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/health" -TimeoutSec 1 -ErrorAction Stop
        if ($response.Content -like "*vps-wireguard-v1*") {
            Write-Output $port
            exit 0
        }
    } catch {
    }

    if (-not (Test-PortOpen -Port $port)) {
        Write-Output $port
        exit 0
    }
}

Write-Output 8008
