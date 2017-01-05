[![AppVeyor - master](https://img.shields.io/appveyor/ci/claudiospizzi/SecurityFever/master.svg)](https://ci.appveyor.com/project/claudiospizzi/SecurityFever/branch/master)
[![AppVeyor - dev](https://img.shields.io/appveyor/ci/claudiospizzi/SecurityFever/dev.svg)](https://ci.appveyor.com/project/claudiospizzi/SecurityFever/branch/dev)
[![GitHub - Release](https://img.shields.io/github/release/claudiospizzi/SecurityFever.svg)](https://github.com/claudiospizzi/SecurityFever/releases)
[![PowerShell Gallery - SecurityFever](https://img.shields.io/badge/PowerShell_Gallery-SecurityFever-0072C6.svg)](https://www.powershellgallery.com/packages/SecurityFever)


# SecurityFever PowerShell Module

PowerShell Module with additional custom functions and cmdlets related to
Windows and application security.


## Introduction

This is a personal PowerShell Module created by Claudio Spizzi. I've collected
all my security related functions into this module, ready to use.

You can invoke PowerShell scripts or script blocks in an elevated context with
sudo, test your credentials against the local system or an Active Directory
domain.

With the security activity and audit policy cmdlets, you can get the security
related configuration of security audit events in the **Audit Policy** and check
the latest activity on the target computer.

With the **Vault** cmdlets, you can interact with the Windows Credential Manager
to store and received PowerShell credentials and secure strings. 


## Requirements

The following minimum requirements are necessary to use this module:

* Windows PowerShell 3.0
* Windows Server 2008 R2 / Windows 7


## Installation

With PowerShell 5.0, the new [PowerShell Gallery] was introduced. Additionally,
the new module [PowerShellGet] was added to the default WMF 5.0 installation.
With the cmdlet `Install-Module`, a published module from the PowerShell Gallery
can be downloaded and installed directly within the PowerShell host, optionally
with the scope definition:

```powershell
Install-Module SecurityFever [-Scope {CurrentUser | AllUsers}]
```

Alternatively, download the latest release from GitHub and install the module
manually on your local system:

1. Download the latest release from GitHub as a ZIP file: [GitHub Releases]
2. Extract the module and install it: [Installing a PowerShell Module]


## Features

* **Invoke-Elevated**  
  Invoke a script block or an executable in an elevated session. It will handle
  the parameter passing into the elevated session and return the result as
  object to the caller. Because it's running in a different elevated process,
  XML serialization is used to return the result. The cmdlet has the alias
  **sudo**, as used on *nix systems.

* **Invoke-PowerShell**  
  Start a new PowerShell Console session with alternative credentials. The
  cmdlet has the alias **posh**.

* **Test-Credential**  
  With this cmdlet, credential objects or username and password pairs can be
  tested, if they are valid. With the method parameter, it's possible to choose
  how the credentials are validated (start process, Active Directory). Be aware,
  multiple testing with wrong credentials can lock out the used account
  depending on your security settings. 

* **Get-VaultEntry**  
  With this cmdlet, the entires form the Windows Credential Manager vault can be
  retrieved. The entries contain a PSCredential object and all additional
  metadata like target name, type and persistence location.

* **Get-VaultEntryCredential**  
  This cmdlet works similar like the Get-VaultEntry, but returns only a native
  PSCredential object without additional metadata. This is useful if just the
  simple PSCredential object is required.

* **Get-VaultEntrySecureString**  
  This cmdlet works similar like the Get-VaultEntry, but returns only a native
  secure string object containing the password without additional metadata. This
  is useful if just the simple secure string object is required.

* **New-VaultEntry**  
  Create a new entry in the Windows Credential Manager vault. The credential
  type and persist location can be specified. By default, a generic entry with
  no special purpose is created on the local machine persist location. It will
  not override existing entries.

* **Update-VaultEntry**  
  Update an existing entry in the Windows Credential Manager vault. The
  credential target name and type are required to identify the entry to update.
  The persist location and the credentials (or username/password) can be
  updated.

* **Remove-VaultEntry**  
  Remove an existing entry in the Windows Credential Manager vault. The cmdlet
  accepts pipeline input with credential entry objects.

* **Get-SecurityActivity**  
  Get security and life-cycle related events on the target computer like start
  up / shutdown, user log on / log off, workstation locked /unlocked, session
  reconnected / disconnected and screen saver invoke / dismiss.

* **Get-SecurityAuditPolicy**  
  List the current local security audit policy settings. It will execute the
  auditpol.exe command and parse the result into objects.

* **Get-SecurityAuditPolicySetting**  
  Return the value of one security audit policy setting. It will use the
  Get-SecurityAuditPolicy cmdlet and just filter and expand the result. 


## Versions

### Unreleased

* Add Invoke-PowerShell function with (alias: posh)

### 1.1.0

* Add cmdlets for the Windows Credential Manager Vault
* Test-Credential: Add verbose output

### 1.0.2

* Test-Credential: Fix wrong output in quiet mode
* Test-Credential: Fix failing Active Directory verification method
* Test-Credential: Add unit tests

### 1.0.1

* Test-Credential: Support positional parameter and pipeline input
* Test-Credential: Fix issues with for inaccessible working directory
* Test-Credential: Replace -Throw with -Quiet
* Get-SecurityActivity: Remove 'run as admin' requirement for remote calls
* Get-SecurityActivity: Add 'After' parameter to narrow down event span
* Fix suppression in script analyzer tests

### 1.0.0

* Add Get-SecurityActivity cmdlet to get security and life-cycle events
* Add Get-SecurityAuditPolicy cmdlet to get current audit policy settings
* Add Get-SecurityAuditPolicySetting cmdlet to get current audit policy settings
* Add Invoke-Elevated cmdlet to execute elevated scripts (alias: sudo)
* Add Test-Credential cmdlet for local and Active Directory verification


## Contribute

Please feel free to contribute by opening new issues or providing pull requests.
For the best development experience, open this project as a folder in Visual
Studio Code and ensure that the PowerShell extension is installed.

* [Visual Studio Code]
* [PowerShell Extension]

This module is tested with the PowerShell testing framework Pester. To run all
tests, just start the included test script `.\Scripts\test.ps1` or invoke Pester
directly with the `Invoke-Pester` cmdlet. The tests will automatically download
the latest meta test from the claudiospizzi/PowerShellModuleBase repository.

To debug the module, just copy the existing `.\Scripts\debug.default.ps1` file
to `.\Scripts\debug.ps1`, which is ignored by git. Now add the command to the
debug file and start it.



[PowerShell Gallery]: https://www.powershellgallery.com/packages/SecurityFever
[PowerShellGet]: https://technet.microsoft.com/en-us/library/dn807169.aspx

[GitHub Releases]: https://github.com/claudiospizzi/SecurityFever/releases
[Installing a PowerShell Module]: https://msdn.microsoft.com/en-us/library/dd878350

[Visual Studio Code]: https://code.visualstudio.com/
[PowerShell Extension]: https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell
