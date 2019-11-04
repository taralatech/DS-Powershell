<#
Run this script as .\Assign-LegacyIPSrules "secretkey" "<full path to csv file>"
Example: .\Assign-LegacyIPSrules "31:Aab1254fgjkdfgkhdfg=" "c:\scripts\mycsvfile.csv"
The script file location is not mandatory.  It can be specified below instead.

todo:
*As each computers rule assignments are checked for severtiy and application type, add to global list of IPS rules if not already present.
 Check each rule for severity.  Store results in hashtable that includes severity and whether it matches a "banned" application type.
 Use hasbtable to lookup severity when filtering rules per computer rather than doing API call.
 check line 242 for progress

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
$ipsruletable = @{}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
            'Content-Type' = 'application/json'
            'API-Secret-Key' = $secretkey
            'API-Version' = 'v1'
            }
Add-Content $logfile "Assignment of Legacy IPS rules started - DS manager URL - $DSmanager"

Function Get-IPSrulesfromDSM
    {
    #Function takes an array of IPS rule ID's and outputs a hashtable of rule ID's and their severity
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [int32[]]$ruleids
        )
    BEGIN
        {
        $iruletable = @{}
        }
    PROCESS
        {
        ForEach ($ruleid in $ruleids)
            {
            $json = @{
                      "maxItems" = 1
                      "searchCriteria" = @{
                                          "fieldName" = "ID"
                                          "numericTest" = "equal"
                                          "numericValue" = $ruleid
                                          }
                      "sortByObjectID" = "true"
                     } | ConvertTo-Json  
            $ipsruleuri = $dsmanager + 'api/intrusionpreventionrules/' + $ruleid
            $ipsruleobject = Invoke-RestMethod -Headers $headers -method Get -Uri $ipsruleuri -TimeoutSec $resttimeout
            $iruletable.Add($ipsruleobject.ID,$ipsruleobject.severity)           
            }
        }
    END
        {
        return $iruletable
        }
    }
 

Function Update-IPSruletable
    {
    #adds two hashtables together.  Outputs a hashtable without duplicates
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [hashtable]$ruletable,
        [Parameter(mandatory=$true)]
        [hashtable]$rulestoadd
        )
    PROCESS
        {
        ForEach ($ruletoadd in $rulestoadd.keys)
            {
            if ($ruletable.ContainsKey($ruletoadd) -ne $true)
                {
                $ruletable.Add($ruletoadd,"banned")
                }
            }
        }
    END
        {
        return $ruletable
        }
    }
 

Function Get-RuleIDsfromapptypes
    {
    #input array of app type ID's
    #return array if IPS rule ID's that use any of those Application types.
    #$apptypeids =int32 array
    #Assumes that an IPS rule is only returned once.  I.e. no duplicate rules due to duplicate App types
    Param
        (
        [Parameter(mandatory=$true)]
        [int32[]]$apptypeids
        )
    BEGIN
        {
        $apptypesearchuri = $dsmanager + 'api/intrusionpreventionrules/search/'
        $fullipsrulehashtable = @{}
        }
    PROCESS
        {
        ForEach ($apptypeid in $apptypeids)
            {
            $json = @{
                    "maxItems" = 4000
                    "searchCriteria" = @{
                                        "fieldName" = "applicationTypeID"
                                        "numericTest" = "equal"
                                        "numericValue" = $apptypeid
                                        }
                    "sortByObjectID" = "true"
                    } | ConvertTo-Json 
            $ipsruleobjects = Invoke-RestMethod -Headers $headers -method Post -Uri $apptypesearchuri -body $json -TimeoutSec $resttimeout
            $ipsruleobjects.intrusionPreventionRules | ForEach {$fullipsrulehashtable.Add($_.ID,"banned")}
            }
        }
    END
        {
        return $fullipsrulehashtable
        }
    }

Function Remove-ClientAndBelowSeverityrules
    {
    #Function takes in an Array of Rules recommended to assign, assigned, recommended to unassign, Application type ID's and Minimum severity.
    Param
        (
        [Parameter(mandatory=$false)]
        [AllowEmptyCollection()]
        [int32[]]$recotoassign,
        [Parameter(mandatory=$true)]
        [AllowEmptyCollection()]
        [int32[]]$assigned,
        [Parameter(mandatory=$true)]
        [AllowEmptyCollection()]
        [int32[]]$recotounassign,
        [Parameter(mandatory=$true)]
        [AllowEmptyCollection()]
        [hashtable]$ipsruletable,
        [Parameter(mandatory=$true)]
        [string]$minseverity,
        [Parameter(mandatory=$true)]
        [int32]$computerID
        )

    BEGIN
        {
        if($minseverity = "low")
            {
            $acceptableseverity = "low" , "medium" , "high" , "critical"
            }
        elseif($minseverity = "medium")
            {
            $acceptableseverity = "medium" , "high" , "critical"
            }
        elseif($minseverity = "high")
            {
            $acceptableseverity = "high" , "critical"
            }
       elseif($minseverity = "critical")
            {
            $acceptableseverity = "critical"
            }
        $rulestoadd = [System.Collections.ArrayList]@()
        $rulestoremove = [System.Collections.ArrayList]@()
        }
    PROCESS
        {
        #$recotoassign - remove unneeded rules
        ForEach ($ruleid in $recotoassign)
            {
            if ($ipsruletable.ContainsKey($ruleid))
                {
                #check rule is not "banned" or below threshold.  If not, add to $rulestoadd
                $severity = $ipsruletable.$ruleid
                if (($acceptableseverity | ForEach{$severity.contains($_)}) -contains $true)
                    {
                    write-host "Rule ID $ruleid is acceptable on Computer ID $computerid with severity $severity"
                    Add-Content $logfile "Rule ID $ruleid is acceptable on Computer ID $computerid with severity $severity"
                    $rulestoadd.Add($ruleid)
                    }
                }
            else
                {
                Write-host "This should not be happening.  The ruleid $ruleid being processed does not exist in the ipsruletable."
                add-content $logfile "This should not be happening.  The ruleid $ruleid being processed does not exist in the ipsruletable."
                }
            }
        #assigned - find assigned rules that do not meed threshold and are not from banned app types and add to $rulestoremove
        ForEach ($ruleid in $assigned)
            {
            if ($ipsruletable.ContainsKey($ruleid))
                {
                #check rule is "banned" or below threshold.  If so, add to $rulestoremove - test this below code
                $severity = $ipsruletable.$ruleid
                if (($acceptableseverity | ForEach{$severity.contains($_)}) -notcontains $true)
                    {
                    write-host "Rule ID $ruleid is assigned to Computer ID $computerid with severity $severity and needs to be removed"
                    Add-Content $logfile "Rule ID $ruleid is assigned to Computer ID $computerid with severity $severity and needs to be removed"
                    $rulestoremove.Add($ruleid)
                    }
                else
                    {
                    write-host "Rule ID $ruleid is assigned to Computer ID $computerid with severity $severity and is acceptable"
                    Add-Content $logfile "Rule ID $ruleid is assigned to Computer ID $computerid with severity $severity and is acceptable"
                    $rulestoadd.Add($ruleid)
                    }
                }
            else
                {
                Write-host "This should not be happening.  The ruleid $ruleid being processed does not exist in the ipsruletable."
                add-content $logfile "This should not be happening.  The ruleid $ruleid being processed does not exist in the ipsruletable."
                }
            }
        ForEach ($ruleid in $recotounassign)
            {
            $rulestoremove.Add($ruleid)
            }
        write-host "Computer ID: $computerID has the following rules to assign: $rulestoadd and the following rules to unassign: $rulestoremove"
        Add-Content $logfile "Computer ID: $computerID has the following rules to assign: $rulestoadd and the following rules to unassign: $rulestoremove"
        }
    END
        {
        #apply only $rulestoadd to the computer on Deep Security"
#https://dsm.example.com:4119/api/computers/{computerID}/intrusionprevention/assignments
        $ipsseturi = $DSmanager + "api/computers/" + $computerID + "/intrusionprevention/assignments"
        $json = @{
                "ruleIDs" = $rulestoadd
                 } | ConvertTo-Json
        $computerruleset = Invoke-RestMethod -Headers $headers -method Put -Uri $ipsseturi -body $json -TimeoutSec $resttimeout
        Add-Content $logfile "Computer ID: $computerID has been processed.  Rule ID's set are $computerruleset"
        }
    }

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
            #write-host $computerobject.count
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
            #update ips rule table for all rules
            #$fullruleset = $rulenumbersassigned + $rulestoassign | where {$rulestoremove -notcontains $_}
            #$ipsruletable.keys
            $unknownipsrules = $fullruleset | where {$ipsruletable.keys -notcontains $_}
            if ($unknownipsrules -ne $null) {$unknownipsruletable = Get-IPSrulesfromDSM -ruleids $unknownipsrules}
            $ipsruletable = Update-IPSruletable -ruletable $ipsruletable -rulestoadd $unknownipsruletable
            $rulestochange = Remove-ClientAndBelowSeverityrules -recotoassign $rulestoassign -assigned $rulenumbersassigned -recotounassign $rulestoremove -minseverity $minseverity -computerID $computerobject.ID -ipsruletable $ipsruletable
            # replace-computeripsrules #need to create this function
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
$ipsruleswithbannedapptypes = Get-RuleIDsfromapptypes -apptypeids $apptypeids
$ipsruletable = Update-IPSruletable -ruletable $ipsruletable -rulestoadd $ipsruleswithbannedapptypes

Apply-LegacyRulesToPolicyMembers -apptypeIDs $apptypeids -csvfile $csvfile
