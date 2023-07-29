On Windows, script execution policy must be set to either RemoteSigned or Unrestricted.
Check the script execution policy setting by executing Get-ExecutionPolicy.
If the policy is not set to one of the two required values,
run PowerShell as Administrator and execute Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm.

Git must be installed and available via the PATH environment variable.
Check that git is accessible from PowerShell by executing git --version from PowerShell.
If git is not recognized as the name of a command, verify that you have Git installed.
If not, install Git from https://git-scm.com.
If you have Git installed, make sure the path to git is in your PATH environment variable.