
$modulePath = Resolve-Path -Path "$PSScriptRoot\..\..\.." | Select-Object -ExpandProperty Path
$moduleName = Resolve-Path -Path "$PSScriptRoot\..\.." | Get-Item | Select-Object -ExpandProperty BaseName

Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
Import-Module -Name "$modulePath\$moduleName" -Force

Describe 'Remove-TrustedHosts' {

    Context 'Not Administrator' {

        Mock 'Test-AdministratorRole' -ModuleName $moduleName { $false }

        It 'should throw an exception' {

            # Arrange, Act, Assert
            { Remove-TrustedHosts -ComputerName $Env:COMPUTERNAME } | Should Throw
        }
    }

    Context 'Is Administrator' {

        Mock 'Test-AdministratorRole' -ModuleName $moduleName { $true }

        Mock 'Get-Item' -ModuleName $ModuleName {
            [PSCustomObject] @{ Value = '10.0.0.1,SERVER,10.0.0.2,10.0.0.3,*.contoso.com' }
        }

        Mock 'Set-Item' -ModuleName $ModuleName -Verifiable -ParameterFilter {
            $Path -eq 'WSMan:\localhost\Client\TrustedHosts' -and $Value -eq '10.0.0.1,10.0.0.2,*.contoso.com'
        } { }

        It 'should add two entries via parameter' {

            # Arrange
            $list = 'SERVER', '10.0.0.3'

            # Act
            Remove-TrustedHosts -ComputerName $list

            # Assert
            Assert-MockCalled 'Set-Item' -ModuleName $moduleName -Times 1 -Exactly
        }

        It 'should add two entries via pipeline' {

            # Arrange
            $list = 'SERVER', '10.0.0.3'

            # Act
            $list | Remove-TrustedHosts

            # Assert
            Assert-MockCalled 'Set-Item' -ModuleName $moduleName -Times 2 -Exactly
        }
    }
}