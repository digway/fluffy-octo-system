function New-IgPassword {
    <#
    .Synopsis
        Generates a new password.
    .DESCRIPTION
        GeneratePassword() takes two arguments, length and complexity.
        The first sets the length of the password.
        The second sets the number of non-alphanumeric characters that you want in it.
        The complexity number cannot be greater than the lenth.
        Can verify that the Password meets most AD requirements for complexity by using the "VerifyAD" switch.
    .EXAMPLE
        New-IgPassword
        Will generate a 10 character password with at least 4 Complexities.
    .EXAMPLE
        New-IgPassword -Length 20 -Complexity 5
        Will generate a 20 character password with at least 5 Complexities.
    .EXAMPLE
        New-IgPassword -VerifyAD
        Will generate a 10 character password with at least 4 Complexities.
        It will also make sure that the PW has at least 1 lower case letter, 1 upper case letter and 1 number.
        That will meet most AD requirements for complexity.
    .EXAMPLE
        New-IgPassword -VerifyAD -Verbose
        Will generate a 10 character password with at least 4 Complexities.
        It will also make sure that the PW has at least 1 lower case letter, 1 upper case letter and 1 number.
        That will meet most AD requirements for complexity.    .Notes
        Created by Donald Jacobs
    .Link
        http://www.powershellusers.com
    #>
    [CmdletBinding(DefaultParameterSetName='DefParamSet',
        SupportsShouldProcess=$true,
        PositionalBinding=$false,
        ConfirmImpact='Medium')]
    [OutputType([string])]
    Param (
        # The length of the password.
        [Parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [ValidateRange(1,128)]
        [int]$Length = 10,

        # The number of non-alphanumeric characters that you want to include in the password.
        # List of complexities: !@#$%^&*()_-+=[{]};:<>|./?
        # No hidden or non-printable control characters are included in the generated password.
        [Parameter(Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            Position=1)]
        [ValidateRange(0,20)]
        [int]$Complexity = 4,

        # If you want to verify that the password generated has at least
        # -> 1 lower case letter
        # -> 1 upper case letter
        # -> 1 number
        [switch]$VerifyAD
    )

    Begin {
        if ($Complexity -gt $Length) {
            Write-Error -Message "The Complexity cannot be greater than the Length of the Password." -ErrorAction Stop
        }
    }
    Process {
        $Assembly = Add-Type -AssemblyName System.Web
        if ($VerifyAD) {
            $badPW = $true
            while ($badPW) {
                $pw = [System.Web.Security.Membership]::GeneratePassword($length,$complexity)
                if ($pw -cmatch '[a-z]' -and $pw -cmatch '[A-Z]' -and $pw -match '[0-9]') {
                    Write-Verbose "Good: $pw"
                    $badPW = $false
                } else {
                    Write-Verbose "This PW: '$pw' is bad, try again."
                }
            }
            $pw
        } else {
            [System.Web.Security.Membership]::GeneratePassword($length,$complexity)
        }
    }
    End { }
}