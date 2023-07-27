$GitRoot = 'C:\GitHub'

# Restore my Modules
$GitPath = "$GitRoot\MyModules"
if (-NOT (Test-Path $GitPath)) {
    git clone https://github.com/OSDeploy/OSD.git "$GitPath\OSD"
    git clone https://github.com/OSDeploy/OSDSUS.git "$GitPath\OSDSUS"
    git clone https://github.com/OSDeploy/OSDBuilder.git "$GitPath\OSDBuilder"
}

# Restore my Repos
$GitPath = "$GitRoot\MyRepos"
if (-NOT (Test-Path $GitPath)) {
    git clone https://github.com/OSDeploy/OSDCloudScripts.git "$GitPath\OSDCloudScripts"
    git clone https://github.com/OSDeploy/OSDCloudScriptsGUI.git "$GitPath\OSDCloudScriptsGUI"
}


