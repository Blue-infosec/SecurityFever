<#
    .SYNOPSIS
        .

    .DESCRIPTION
        .

    .INPUTS
        .

    .OUTPUTS
        .

    .EXAMPLE
        PS C:\> ssh admin@192.168.1.1 "tail -f /var/log/messages" | ConvertFrom-USGFirewallLog | Out-GridView
        This command will open an ssh session to the USG 192.168.1.1 and grab
        all log entries. The entries are converted by this function and shown
        in a grid view.

    .NOTES
        Author     : Claudio Spizzi
        License    : MIT License

    .LINK
        https://github.com/claudiospizzi/SecurityFever
#>
function ConvertFrom-UniFiSecurityGatewayFirewallLog
{
    [CmdletBinding()]
    [Alias('ConvertFrom-USGFirewallLog')]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $InputObject
    )

    begin
    {
        $udpRegex = '^([a-zA-Z]{3} [0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) \S+ \S+: \[(\S+)-(\S+)-([A|D])]IN=(\S*) OUT=(\S*) MAC=(\S*) SRC=(\S*) DST=(\S*) LEN=(\S*) TOS=(\S*) PREC=(\S*) TTL=(\S*) ID=(\S*) PROTO=(\S*) SPT=(\S*) DPT=(\S*) LEN=(\S*)'
        $tcpRegex = '^([a-zA-Z]{3} [0-9]{1,2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) \S+ \S+: \[(\S+)-(\S+)-([A|D])]IN=(\S*) OUT=(\S*) MAC=(\S*) SRC=(\S*) DST=(\S*) LEN=(\S*) TOS=(\S*) PREC=(\S*) TTL=(\S*) ID=(\S*) DF PROTO=(\S*) SPT=(\S*) DPT=(\S*) WINDOW=(\S*) RES=(\S*) ([A-Z ]*) URGP=(\S*)'

        function Convert-USGAction($Action)
        {
            switch ($Action)
            {
                'A'     { 'Allow' }
                'D'     { 'Deny' }
                default { $Action }
            }
        }
    }

    process
    {
        if ($InputObject -match $udpRegex)
        {
            # Parse date and time
            $date = [DateTime] $Matches[1]
            $time = [DateTime] $Matches[2]

            [PSCustomObject] [Ordered] @{
                PSTypeName           = 'UniFiSecurityGateway.Firewall.Log.Udp'
                DateTime             = $date.AddHours($time.Hour).AddMinutes($time.Minute).AddSeconds($time.Second)
                Type                 = $Matches[3]
                Rule                 = $Matches[4]
                Action               = Convert-USGAction $Matches[5]
                SourceInterface      = $Matches[6]         # IN
                DestinationInterface = $Matches[7]         # OUT
                MAC                  = $Matches[8]         # MAC
                SourceIP             = $Matches[9]         # SRC
                DestinationIP        = $Matches[10]        # DST
                LEN        = $Matches[11]
                TOS        = $Matches[12]
                PREC       = $Matches[13]
                TTL        = $Matches[14]
                ID         = $Matches[15]
                PROTO      = $Matches[16]
                SourcePort           = $Matches[17]
                DestinationPort      = $Matches[18]
                WINDOW     = ''
                RES        = ''
                STATE      = ''
                URGP       = ''
                LEN2       = $Matches[19]
            }
        }

        if ($InputObject -match $tcpRegex)
        {
            # Parse date and time
            $date = [DateTime] $Matches[1]
            $time = [DateTime] $Matches[2]

            [PSCustomObject] [Ordered] @{
                DateTime = $date.AddHours($time.Hour).AddMinutes($time.Minute).AddSeconds($time.Second)
                Type     = $Matches[3]
                Rule     = $Matches[4]
                Action   = $(if ($Matches[5] -eq 'A') { 'Allow' } elseif ($Matches[5] -eq 'D') { 'Deny' } else { $Matches[5] })
                IN       = $Matches[6]
                OUT      = $Matches[7]
                MAC      = $Matches[8]
                SRC      = $Matches[9]
                DST      = $Matches[10]
                LEN      = $Matches[11]
                TOS      = $Matches[12]
                PREC     = $Matches[13]
                TTL      = $Matches[14]
                ID       = $Matches[15]
                PROTO    = $Matches[16]
                SPT      = $Matches[17]
                DPT      = $Matches[18]
                WINDOW   = $Matches[19]
                RES      = $Matches[20]
                STATE    = $Matches[21]
                URGP     = $Matches[22]
                LEN2     = ''
            }
        }
    }
}




#     begin
#     {
#         $regexSimple  = '^[A-Z][a-z]{2} [0-9 ]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} casausg01 kernel: \['
#         $regexComplex = '^[A-Z][a-z]{2} [0-9 ]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} casausg01 kernel: \[(?<ZONE>[A-Z_]*)-(?<RULE>[a-zA-Z0-9]*)-(?<ACTION>A|D)\]IN=(?<IN>[a-z0-9.]*) OUT=(?<OUT>[a-z0-9.]*) MAC=(?<MAC>[0-9a-f:]*) SRC=(?<SRC>[0-9.]*) DST=(?<DST>[0-9.]*) LEN=(?<LEN>[0-9]*) TOS=(?<TOS>[0-9x]*) PREC=(?<PREC>[0-9x]*) TTL=(?<TTL>[0-9]*) ID=(?<ID>[0-9]*) D?F? ?PROTO=(?<PROTO>TCP|UDP) SPT=(?<SPT>[0-9]*) DPT=(?<DPT>[0-9]*)'
#     }

#     process
#     {
#         if ($InputObject -match $regexComplex)
#         {
#             [PSCustomObject] @{
#                 ZONE   = $Matches.ZONE
#                 RULE   = $Matches.RULE
#                 ACTION = $Matches.ACTION
#                 IN     = $Matches.IN
#                 OUT    = $Matches.OUT
#                 MAC    = $Matches.MAC
#                 SRC    = $Matches.SRC
#                 DST    = $Matches.DST
#                 LEN    = $Matches.LEN
#                 TOS    = $Matches.TOS
#                 PREC   = $Matches.PREC
#                 TTL    = $Matches.TTL
#                 ID     = $Matches.ID
#                 PROTO  = $Matches.PROTO
#                 SPT    = $Matches.SPT
#                 DPT    = $Matches.DPT
#             }
#         }
#         elseif ($InputObject -match $regexSimple)
#         {
#             Write-Warning "Not parsed: $InputObject"
#         }
#     }
# }

# Get-Content /var/log/messages -Wait -Last 1 | Convert-FirewallLog

# function ConvertFrom-UnifiLog
# {
#     [CmdletBinding()]
#     param
#     (
#         [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
#         [System.String]
#         $InputObject
#     )

# }


