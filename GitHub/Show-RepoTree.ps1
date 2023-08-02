<#
.SYNOPSIS
Displays the file tree of a GitHub repository.

.DESCRIPTION
This script retrieves the file tree of a specified GitHub repository and displays it in the console.

.LINK
https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28
#>
#Repository
$RepoOwner = 'OSDeploy'
$RepoName = 'PwshHub'
$RepoPath = $null

#Get the Repo SHA of the Master
$Uri = "https://api.github.com/repos/$RepoOwner/$RepoName/branches/master"
$RepoMaster = Invoke-RestMethod $Uri
$RepoSha = $RepoMaster.commit.sha
$RepoTreeUrl = $RepoMaster.commit.commit.tree.url
$RepoTreeSha = $RepoMaster.commit.commit.tree.sha

#Get the Repo Tree

$Uri = "https://api.github.com/repos/$RepoOwner/$RepoName/git/trees/$($RepoTreeSha)?recursive=1"
$RepoTree = Invoke-RestMethod $Uri -Verbose

$RepoTree.tree