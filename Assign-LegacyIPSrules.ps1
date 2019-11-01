<#
Run this script as .\Assign-LegacyIPSrules "secretkey" "<full path to csv file>"
Example: .\Assign-LegacyIPSrules "31:Aab1254fgjkdfgkhdfg=" "c:\scripts\mycsvfile.csv"
The script file location is not mandatory.  It can be specified below instead.
#>
param (
    [Parameter(Mandatory=$true)][string]$secretkey,
    [Parameter(Mandatory=$true)][string]$csvfile
)

#Alternatively enter the csv file location here
#$csvfile = "c:\scripts\csv\machinetoPolicy.csv"
#enter the timeout for REST queries here
$resttimeout = 30
#Enter the full path to the logfile here without the slash at the end
$logfilepath = "C:\scripts\log"
#URL must include HTTPS:// and finish with a /
#e.g. $DSmanager = "https://app.deepsecurity.trendmicro.com/"
$dsmanager = "https://app.deepsecurity.trendmicro.com/"
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
Function Update-ComputerDescription
    {
    #Function takes a policy ID and updates its description to state this script has been ran and when.
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [int32]$computerID
        )
    BEGIN
        {
        #https://dsm.example.com:4119/api/policies/{policyID}
        $datenow = get-date
        $computerdescription = "Computer IPS rules updated by Assign-LegacyIPSrules on $datenow"
        $json = @{
          "description" = $computerdescription
                } | ConvertTo-Json
        }
    PROCESS
        {
        $computerchangeuri = $dsmanager + 'api/computers/' + $computerID
        Invoke-RestMethod -Headers $headers -method Post -Uri $computerchangeuri -body $json -TimeoutSec $resttimeout
        Add-Content $logfile "Computer ID $computerID had description changed on $datenow"
        }
    END
        {
        return $policydescription
        }
    }

Function Update-PolicyDescription
    {
    #Function takes a policy ID and updates its description to state this script has been ran and when.
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [int32]$policyID
        )
    BEGIN
        {
        #https://dsm.example.com:4119/api/policies/{policyID}
        $datenow = get-date
        $policydescription = "Policy Members IPS rules updated by Assign-LegacyIPSrules on $datenow"
        $json = @{
          "description" = $policydescription
                } | ConvertTo-Json
        }
    PROCESS
        {
        $policychangeuri = $dsmanager + 'api/policies/' + $policyID
        Invoke-RestMethod -Headers $headers -method Post -Uri $policychangeuri -body $json -TimeoutSec $resttimeout
        Add-Content $logfile "Policy ID $policyID had description changed on $datenow"
        }
    END
        {
        return $policydescription
        }
    }

Function Get-ComputersByPolicyID
    {
    #Function takes a single Policy ID and returns an array of computer objects that policy applies to
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [int32]$policyID
        )
    BEGIN
        {
        $computersearchuri = $dsmanager + 'api/computers/search/'
        }
    PROCESS
        {
        Add-Content $logfile "Procedding Policy: $policyname ID:$policyID"
        Write-host "Processing Policy ID:$policyID"
        $json = @{
                  "maxItems" = 1000
                  "searchCriteria" = @{
                                      "fieldName" = "policyID"
                                      "numericTest" = "equal"
                                      "numericValue" = $policyID
                                      }
                  "sortByObjectID" = "true"
                 } | ConvertTo-Json 
        $computerobjectarray = Invoke-RestMethod -Headers $headers -method Post -Uri $computersearchuri -body $json -TimeoutSec $resttimeout
        }
    END
        {
        $computerlist = $computerobjectarray.computers.hostName
        Add-Content $logfile "Computer Object Array: $computerlist"
        Write-host "Computer Object Array: $computerlist"
        return $computerobjectarray
        }
    }

Function Get-IpsAppTypeIDs
    {
    #Function takes an Array of IPS Application Types by name and returns an array of Application Type ID's
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

Function Apply-LegacyRulesToComputers
    {
    #Function takes in an array of cumputer objects, an array of App type ID's and a minimum severity setting.
    #It then takes recommendation scan results, removes any "recommended to remove" rules
    #Then takes all rules applied and adds them to all rules recommended to apply
    #it them removes all rules below the minsevertiy setting from the array of rules.
    #it them removes all rules with application types that match the application type array
    #It then applies all of the rules left over
    #It then updates the computer description with time, date and the fact that this script has applied.
    [CmdletBinding()]
    Param
        (
        [Parameter(ValueFromPipeline=$true,mandatory=$true)]
        [object[]]$computerlist,
        [Parameter(mandatory=$true)]
        [int32[]]$apptypeids,
        [Parameter(mandatory=$true)]
        [string]$minseverity
        )
    BEGIN
        {
        write-host $computerlist.computers.hostname
        write-host $computerlist.computers.count

        }
    PROCESS
        {
        ForEach ($computerobject in $computerlist.computers)
            {
            write-host "Foreach start"
            write-host $computerobject.hostname
            write-host $computerobject.count
            Update-ComputerDescription -computerID $computerobject.ID
            $ipsuri = $dsmanager + 'api/computers/' + $computerobject.ID + '/intrusionprevention/assignments'
            $rulesassigned = Invoke-RestMethod -Headers $headers -Uri $ipsuri -TimeoutSec $resttimeout
            $rulenumbersassigned = $rulesassigned.assignedRuleIDs
            $recoscanstatus = $rulesassigned.recommendationScanStatus
            $recoscandateinmilliseconds = $rulesassigned.lastRecommendationScanDate
            $rulestoassign = $rulesassigned.recommendedToAssignRuleIDs
            $rulestoremove = $rulesassigned.recommendedToUnassignRuleIDs
            Add-Content $logfile "IPS Rules Assigned: $rulenumbersassigned"
            Add-Content $logfile "Recommendation Scan Status: $recoscanstatus"
            Add-Content $logfile "Recommendation Scan date in milliseconds since epoch: $recoscandateinmilliseconds"
            Add-Content $logfile "Rules recommended to Assign to computer: $rulestoassign"
            Add-Content $logfile "Rules Recommended to remove from computer: $rulestoremove"
            $fullruleset = $rulenumbersassigned + $rulestoassign | where {$rulestoremove -notcontains $_}
            Add-Content $logfile "Fullruleset: $fullruleset"
            write-host $rulenumbersassigned
            write-host "Foreach end"
            }
        }
    END
        {

        }
    #Input Array Of Computer ID's, Min CVE Severity and Array of Application Types to Exclude
    #For Each Computer ID, get list of recommended for assignment, recommended for unassignment
    ##Check Application ID and Severity for Each recommended for assignment rule against excluded.  Remove from array if excluded
    ##unnasign recommneded for unassignment
    ##assign recommended with list that has exclusions removed
    ##Log Everything
    }

Function Apply-LegacyRulesToPolicyMembers
    {
    #Function takes in an Array of Application Type ID's and the csv file and for each line in the CSV:
    #gets a list of computers to which the policy applies
    #Runs the function Apply-LegacyRulesToComputers to apply recommended IPS rules minus the ones that match application types or are below minseverity..
    [CmdletBinding()]
    Param
        (
        [Parameter(ValueFromPipeline)]
        [string[]]$apptypeids,
        [Parameter(mandatory=$true)][string]$csvfile
        )
    BEGIN
        {
        $policylist = Import-CSV $csvfile
        $computersearchuri = $dsmanager + 'api/computers/search/'
        $policysearchuri = $dsmanager + 'api/policies/search/'
        }
    PROCESS
        {
        ForEach ($policynameID in $policylist)
            {
            $minseverity = $policynameID.MinSeverity
            if ($policynameID.PolicyIDYes -eq 0)
                {
                $policyname = $policynameID.PolicynameID
                $json = @{
                        "maxItems" = 2
                        "searchCriteria" = @{
                                            "fieldName" = "name"
                                            "stringTest" = "equal"
                                            "stringValue" = $policyname
                                            }
                        "sortByObjectID" = "true"
                        } | ConvertTo-Json 
                 $policyobject = Invoke-RestMethod -Headers $headers -method Post -Uri $policysearchuri -body $json -TimeoutSec $resttimeout
                 if ($policyobject.policies.count -gt 1)
                    {
                    Add-Content $logfile "Policy Name: $policyname has more than one match.  Skipping"
                    Write-host "Policy Name: $policyname has more than one match.  Skipping"
                    }
                 Else
                    {
                    $policyID = $policyobject.policies.ID
                    Add-Content $logfile "Processing Policy: $policyname ID:$policyID"
                    }
                 }         
            else
                {
                    $policyID = $policynameID
                    Add-Content $logfile "Procedding Policy: $policyname ID:$policyID"
                }
            Write-host "Processing Policy ID:$policyID"
            $computerobjectarray  = Get-ComputersByPolicyID -policyID $policyID
            Update-PolicyDescription -policyID $policyID
            Apply-LegacyRulesToComputers -computerlist $computerobjectarray -apptypeids $apptypeids -minseverity $minseverity
            }
        }
    END
        {

        }

    #Load CSV
    #For Each line
    ##retrieve array of computer ID's to which the policy applies
    ##Apply-AppropriateRules $ComputerIDarray $minseverity $DropAppTypes
    ##Modify Policy Description with updated datetime when script ran.  Maybe check for pointer and only keep last 2 runs
    }
$apptypeids = Get-IpsAppTypeIDs $dropapptypes
write-host "Function returned $apptypeids"
Apply-LegacyRulesToPolicyMembers -apptypeIDs $apptypeids -csvfile $csvfile

