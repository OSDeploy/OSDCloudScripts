<#
You should read the instructions for Contributing first
https://github.com/microsoft/winget-pkgs/blob/master/CONTRIBUTING.md

In a nutshell you will need to fork the repo, create a branch, make your changes, and then submit a pull request.
https://github.com/microsoft/winget-pkgs

https://docs.github.com/en/get-started/quickstart/fork-a-repo
#>

# Set the location for the Git repository
$Destination = 'C:\GitHub\Forks\winget-pkgs'

# Clone the repository
git.exe clone https://github.com/OSDeploy/winget-pkgs.git $Destination