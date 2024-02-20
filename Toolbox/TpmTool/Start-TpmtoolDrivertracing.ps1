if (Get-Command "tpmtool" -ErrorAction SilentlyContinue) {
    TpmTool.exe drivertracing start
} else {
    Write-Host "TpmTool.exe not found. Please install the TPM Management Console from the Windows Store."
}