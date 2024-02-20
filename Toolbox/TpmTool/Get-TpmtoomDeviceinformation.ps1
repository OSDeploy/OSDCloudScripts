if (Get-Command "tpmtool" -ErrorAction SilentlyContinue) {
    TpmTool.exe getdeviceinformation
} else {
    Write-Host "TpmTool.exe not found. Please install the TPM Management Console from the Windows Store."
}