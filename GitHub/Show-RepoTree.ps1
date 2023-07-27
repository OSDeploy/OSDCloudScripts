<#PSScriptInfo
.VERSION 23.7.27.4
.GUID 96920c50-7617-41ec-b587-210d2c73e0d2c
.AUTHOR David Segura
.COMPANYNAME David Segura
.COPYRIGHT (c) 2023 David Segura. All rights reserved.
.TAGS WinGet
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/PwshHub
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.DESCRIPTION
This script will clone a GitHub Repo and return the Repo Tree
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