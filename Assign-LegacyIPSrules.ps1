<#
Run this script as .\Assign-LegacyIPSrules "secretkey" "<full path to csv file>"
Example: .\Assign-LegacyIPSrules "31:Aab1254fgjkdfgkhdfg=" "c:\scripts\mycsvfile.csv"
The script file location is not mandatory.  It can be specified below instead.
#>
param (
    [Parameter(Mandatory=$true)][string]$secretkey,
    [Parameter(Mandatory=$false)][string]$csvfile
)

#Alternatively enter the csv file location here
#$csvfile = "c:\scripts\csv\machinetoPolicy.csv"
#enter the timeout for REST queries here
$resttimeout = 30
#Enter the full path to the logfile here without the slash at the end
$logfilepath = "C:\scripts\log"
#URL must include HTTPS:// and finish with a /
#e.g. $DSmanager = "https://app.deepsecurity.trendmicro.com/"
$DSmanager = "https://app.deepsecurity.trendmicro.com/"
$date = ( get-date ).ToString('yyyyMMddhhmmss')
$logfile = New-Item -type file "$logfilepath\Assign-LegacyIPSrules-$date.txt"
$dropapptypes = "Web Client Common", "Web Client Internet Explorer/Edge", "Web Client Mozilla Firefox", "Microsoft Office"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
            'Content-Type' = 'application/json'
            'API-Secret-Key' = $secretkey
            'API-Version' = 'v1'
            }
Add-Content $logfile "Assignment of Legacy IPS rules started - DS manager URL - $DSmanager"

Function Get-IpsAppTypeIDs
    {
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline)]
        [string[]]$dropapptypearray
    )
    BEGIN
        {
        write-host "Begin"
        write-host $dropapptypearray
        $apptypesearchuri = $dsmanager + 'api/applicationtypes/search/'
        $apptypeidarray = @()
        }
    PROCESS
        {
        write-host "Process"
        ForEach ($dropapptype in $dropapptypearray)
            {
            $json = @{
                    "maxItems" = 2
                    "searchCriteria" = @{
                                        "fieldName" = "name"
                                        "stringTest" = "equal"
                                        "stringValue" = $dropapptype
                                        }
                    "sortByObjectID" = "true"
                  } | ConvertTo-Json
            Write-Host "App type to drop is $dropapptype"
            $apptypeobject = Invoke-RestMethod -Headers $headers -method Post -Uri $apptypesearchuri -body $json -TimeoutSec $resttimeout
                if ($apptypeobject.applicationTypes.Count -gt 1)
                    {write-host "more than 1 match"
                    write-host $apptypeobject.applicationTypes.Count
                    Add-Content $logfile "More than 1 Application Type object returned for search $dropapptype"
                    }
                else
                    {
                    $apptypeid = $apptypeobject.applicationTypes.ID
                    Add-Content $logfile "App Type Search is: $dropapptype"
                    Add-Content $logfile "App Type ID is: $apptypeid"
                    $apptypeidarray = $apptypeidarray += $apptypeobject.applicationTypes.ID
                    }
            
            }
        }
    END
        {
        write-host "End"
        Add-Content $logfile "App Tpye ID list is: $apptypeidarray"
        write-host "App Type ID list is: $apptypeidarray"
        return $apptypeidarray
        }
    }

Function Apply-AppropriateRules
    {
    #Input Array Of Computer ID's, Min CVE Severity adn Array of Application Types to Exclude
    #For Each Computer ID, get list of recommended for assignment, recommended for unassignment
    ##Check Application ID and Severity for Each recommended for assignment rule against excluded.  Remove from array if excluded
    ##unnasign recommneded for unassignment
    ##assign recommended with list that has exclusions removed
    ##Log Everything
    }

Function Get-PoliciestoApply
    {
    #Load CSV
    #For Each line
    ##retrieve array of computer ID's to which the policy applies
    ##Apply-AppropriateRules $ComputerIDarray $minseverity $DropAppTypes
    ##Modify Policy Description with updated datetime when script ran.  Maybe check for pointer and only keep last 2 runs
    }
$apptypeids = Get-IpsAppTypeIDs $dropapptypes
write-host "Function returned $apptypeids"
#Get-PoliciestoApply -csvfile $csvfile -apptypeIDs $apptypeids

