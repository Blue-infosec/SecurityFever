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


## Cmdlets

* **Get-SecurityActivity**


* **Get-SecurityAuditPolicy**

  List the current local security audit policy settings. It will execute the
  auditpol.exe command and parse the result into objects.

* **Get-SecurityAuditPolicySetting**

  Return the value of one security audit policy setting. It will use the
  Get-SecurityAuditPolicy cmdlet and just filter and expand the result. 

* **Invoke-Elevated**  
  Invoke a script block or an executable in an elevated session. It will handle
  the parameter passing into the elevated session and return the result as
  object to the caller. Because it's running in a different elevated process,
  XML serialization is used to return the result. The cmdlet has the alias
  **sudo**, as used on *nix systems.

* **Test-Credential**  
  With this cmdlet, credential objects or username and password pairs can be
  tested, if they are valid. With the method parameter, it's possible to choose
  how the credentials are validated (start process, Active Directory). Be aware,
  multiple testing with wrong credentials can lock out the used account
  depending on your security settings. 


## Requirements

The following minimum tested requirements are necessary to use this module:

* Windows PowerShell 3.0
* Windows Server 2008 R2 / Windows 7


## Installation

With PowerShell 5.0, the new [PowerShell Gallery] and the Install-Module cmdlet were introduced. Install this module automatically from the PowerShell Gallery
to your local system:

```powershell
Install-Module OperationsManagerFever
```

Alternative, download the latest release from GitHub and install the module
manually on your local system:

* Download the latest release from GitHub as a ZIP file
* Extract the downloaded module into one of your module paths


tbd


## Versions

### unreleased

* Add Invoke-Elevated cmdlet with sudo alias


## Contribute

Please feel free to contribute by opening new issues or providing pull requests.
For the best development experience, open this project as a folder in Visual
Studio Code and ensure that the PowerShell extension is installed.

* [Visual Studio Code](https://code.visualstudio.com/)
* [PowerShell Extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell)

This module is tested with the PowerShell testing framework Pester. To run all
tests, just start the included test script `.\Scripts\test.ps1` or invoke Pester
directly with the `Invoke-Pester` cmdlet. The tests will automatically download
the latest meta test from the claudiospizzi/PowerShellModuleBase repository.


[PowerShell Gallery]: https://www.powershellgallery.com/packages/SecurityFever
