<#
Description here
This scrips needs refactoring.  Originally it used the add-dsobjects function, however that was not suitable for IPS and policies.  add-dsobjectsfrompscustom was created
to deal with the huge number of IPS rules without hammering the API.  Whilst writing that function, it became obvious that there was a lot of chescing/replacing of lists
and that functionality should be performed by another function.  There are three completely different ways of adding objects the the new DSM as a result and its overcomplicated.

For the export script, it will need another whole round of API queries - Policy.IPSrules, policy.fireawall rules etc as overrides to individual rules aren't exported.
IPS rules - boost performance by creating a new hashtable that only has ID and Identifier and searching that?
also, bug - If a custom IPS rule with same name exists, it doesn't append the prefix - why not?
Need to add logging to compare-dsobject
#>
param (
    [Parameter(Mandatory=$true)][string]$secretkey,
    [Parameter(Mandatory=$false)][string]$inputdir,
    [Parameter(Mandatory=$false)][string]$dsmanager,
    [Parameter(Mandatory=$false)][string]$logfilepath,
    [Parameter(Mandatory=$false)][string]$prefix,
    [Parameter(Mandatory=$false)][string]$loadfile
)


#For testing
$inputdir = "C:\scripts\log\export-DSM"
$dsmanager = "https://deepsec.tarala.me.uk:4119/"
$logfilepath = "C:\scripts\log"
$prefix = "tst2"
#$loadfile = "C:\scripts\log\Output-DSPolicies-20200228053138-1.json"
#end testing

#enter the timeout for REST queries here
$resttimeout = 30
#Enter the delay in seconds if there are API errors (such as "too many API requests")
$backoffdelay = 1
#URL must include HTTPS:// and finish with a /
#e.g. $DSmanager = "https://app.deepsecurity.trendmicro.com/"
#$dsmanager = "https://app.deepsecurity.trendmicro.com/"
$date = ( get-date ).ToString('yyyyMMddhhmmss')
$logfile = New-Item -type file "$logfilepath\Import-DSPolicies-$date.txt"
#Create the table for looking up ID's against API calls
$lookuptable = @{
"sourceIPListID" = "iplists"
"sourceMACListID" = "maclists"
"sourcePortListID" = "portlists"
"destinationIPListID" = "iplists"
"destinationMACListID" = "maclists"
"destinationPortListID" = "portlists"
"portListID" = "portlists"
"directoryListID" = "directorylists"
"fileExtensionListID" = "fileextensionlists"
"excludedDirectoryListID" = "directorylists"
"excludedFileListID" = "filelists"
"excludedFileExtensionListID" = "fileextensionlists"
"excludedProcessImageFileListID" = "filelists"
"applicationTypeID" = "applicationtypes"
"contextID" = "contexts"
"scheduleID" = "schedules"
"realTimeScanConfigurationID" = "antimalwareconfigurations"
"manualScanConfigurationID" = "antimalwareconfigurations"
"realTimeScanScheduleID" = "schedules"
"scheduledScanConfigurationID" = "schedules"
"globalStatefulConfigurationID" = "statefulconfigurations"
#These are not "direct" lookups - they are ruleids concatenated with the policy element that uses the ruleIDs because Firewall, IPS, IM and LI engines all just use ruleIDs
#all of the below are realted to policies only
"firewallruleIDs" = "firewallrules"
"intrusionPreventionruleIDs" = "intrusionpreventionrules"
#IM - insert here
#LI - insert here
#these are direct lookups.  They're here for readability because They're related to policies
"applicationTypeIDs" = "applicationtypes"
"parentID" = "policies"
#these are used to identify lists one level below for policies
"antiMalware" = "nested"
"firewall" = "firewallrules"
"intrusionPrevention" = "intrusionpreventionrules"
"integrityMonitoring" = "nested"
"applicationControl" = "nested"
"ruleIDs" = "array"
}
$arraysubobjectidlist = @('ruleIDs','applicationTypeIDs') # List of arrays of ID's
$nestedobjectpropertylist = @('policySettings','antiMalware','webReputation','firewall','intrusionPrevention','integrityMonitoring','applicationControl','SAP','logInspection') #list of properties that contain sub properties
$propertiestoskip = @('originalIssue','lastUpdated','description','sensingMode','containerControl','ID') #ignore these properties for comparison
$global:irreconcilabledifferences = @{}
#Create a PScustomObject to store the Object ID mappings - a table to lookup "old" object ID's against the new ID's created on the new DSM
$masteridmappings = [PSCustomObject]@{}

if ($inputdir -eq "")
    {
    Add-Content $logfile "Output directory not specified within script or as a parameter.  Run the script as Output-DSPolicies secretkey <full path to output directory>"
    throw "Output Directory Not specified"
    }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
            'Content-Type' = 'application/json'
            'API-Secret-Key' = $secretkey
            'API-Version' = 'v1'
            }
Add-Content $logfile "Import of DS Policies started - DS manager URL - $DSmanager"

#Functions

function Call-Dsapi
    {
    #Function simply calls the API using the parameters supplied.  If it gets an error, it retries 50 times waiting $backoffdelay between each attempt
param (
    [Parameter(Mandatory=$true)][hashtable]$headers,
    [Parameter(Mandatory=$true)][string]$method,
    [Parameter(Mandatory=$true)][string]$uri,
    [Parameter(Mandatory=$false)][string]$body,
    [Parameter(Mandatory=$true)][int32]$resttimeout,
    [Parameter(Mandatory=$true)][int32]$backoffdelay
    )
    BEGIN
        {
        #check that the request is formatted properly
        $alloweddmethods = @('get','post','delete')
        if ($method -notin $alloweddmethods)
            {
            throw "Method Specified does not match get, post or delete"
            }
        if (($method -eq "post") -and ($body -eq $null))
            {
            throw "Method is post but no body present"
            }
        }
    PROCESS
        {
        $count = 1
        switch ($method)
            {
            "get"
                {
                $dsobject = Invoke-RestMethod -Headers $headers -method Get -Uri $uri -TimeoutSec $resttimeout
                if ($dsobject)
                    {
                    Write-Host "ID: $uri Connected! Call-Dsapi" -Foregroundcolor Green
                    }
                else
                    {
                    Write-Host "ID: $uri Error! Assume API overload for Call-Dsapi" -ForegroundColor Yellow
                    do
                        {
                        Start-Sleep -Seconds $backoffdelay
                        $dsobject = Invoke-RestMethod -Headers $headers -method Get -Uri $uri -TimeoutSec $resttimeout
                        $count ++
                        }
                    while ((-Not $dsobject) -and ($count -lt 50))
                    write-host "Call-Dsapi Error handling complete - URI is: $uri" -ForegroundColor Yellow
                    if (! $dsobject)
                        {
                        write-host "Count: $count" -ForegroundColor DarkRed
                        write-host "Headers: $headers" -ForegroundColor DarkRed
                        write-host "Method: Get" -ForegroundColor DarkRed
                        write-host "URI: $uri" -ForegroundColor DarkRed                     
                        throw "API still failing after 50 attempts"
                        }
                    }
                }
            "post"
                {
                $dsobject = Invoke-RestMethod -Headers $headers -method Post -Uri $uri -body $body -TimeoutSec $resttimeout
                if ($dsobject)
                    {
                    Write-Host "ID: $uri Connected! Call-Dsapi" -Foregroundcolor Green
                    }
                else
                    {
                    Write-Host "ID: $uri Error! Assume API overload for Call-Dsapi" -ForegroundColor Yellow
                    do
                        {
                        Start-Sleep -Seconds $backoffdelay
                        $dsobject = Invoke-RestMethod -Headers $headers -method Post -Uri $uri -body $body -TimeoutSec $resttimeout
                        $count ++
                        }
                    while ((-Not $dsobject) -and ($count -lt 50))
                    write-host "Call-Dsapi Error handling complete - URI is: $uri" -ForegroundColor Yellow
                    if (! $dsobject)
                        {
                        write-host "Count: $count" -ForegroundColor DarkRed
                        write-host "Headers: $headers" -ForegroundColor DarkRed
                        write-host "Method: Post" -ForegroundColor DarkRed
                        write-host "URI: $uri" -ForegroundColor DarkRed
                        write-host "Body: $body" -ForegroundColor DarkRed
                        throw "API still failing after 50 attempts"
                        }
                    }
                }
            "delete"
                {
                write-host "Not used this yet" -ForegroundColor Yellow
                throw "Sorry this bit isn't ready"
                <#
                $dsobject = Invoke-RestMethod -Headers $headers -method Delete -Uri $uri -TimeoutSec $resttimeout
                if ($dsobject)
                    {
                    Write-Host "ID: $uri Connected! Call-Dsapi" -Foregroundcolor Green
                    }
                else
                    {
                    Write-Host "ID: $uri Error! Assume API overload for Call-Dsapi" -ForegroundColor Yellow
                    do
                        {
                        Start-Sleep -Seconds $backoffdelay
                        $dsobject = Invoke-RestMethod -Headers $headers -method Delete -Uri $uri -TimeoutSec $resttimeout
                        $count ++
                        }
                    while ((-Not $dsobject) -and ($count -lt 50))
                    write-host "Call-Dsapi Error handling complete - URI is: $uri" -ForegroundColor Yellow
                    if (! $dsobject) {throw "API still failing after 50 attempts"}
                    }
                #>
                }
            Default
                {throw "Method Specified does not match get, post or delete"}
            }
        }
    END
        {
        return $dsobject
        }
    }

Function Merge-DSobjects
    {
    #Merges two objects
    Param (
          [Parameter(mandatory=$true)]$dsobject1, 
          [Parameter(mandatory=$true)]$dsobject2,
          [Parameter(mandatory=$true)]$uripart
          )
    PROCESS
        {
        $dsmembers = [Pscustomobject]@{}
        $dsmembers | add-member -MemberType NoteProperty -Name $uripart -value @()
        $dsmembers.$uripart += $dsobject1.$uripart
        $dsmembers.$uripart += $dsobject2.$uripart
        }
    END
        {
        return $dsmembers
        }
    }

Function Get-DSObjects
    {
    #Due to 5000 Item limit, requests need to be split.  This is used to perform multiple API calls and combine the results into one object.
    #Uses functions call-dsapi and merge-dsobjects
    #Request is split into multiple requests for up to 1000 records.
    [CmdletBinding()]
    Param
        (
        [Parameter(Mandatory=$true)][string]$dsmanager,
        [Parameter(Mandatory=$true)][string]$uripart,
        [Parameter(Mandatory=$true)][int32]$resttimeout,
        [Parameter(Mandatory=$true)][int32]$backoffdelay,
        [Parameter(Mandatory=$false)][string]$parameters
        )
    BEGIN
        {
        if ($parameters)
            {
            $geturi = $dsmanager + 'api/' + $uripart + '/search/' + $parameters
            }
        else
            {
            $geturi = $dsmanager + 'api/' + $uripart + '/search/'
            }
        }
    PROCESS
        {
        $startid = 0
        $dsobjects = $null
        do
            {
            $json = @{
                        "maxItems" = 1000
                        "searchCriteria" = @{
                                            "fieldName" = "ID"
                                            "idValue" = $startid
                                            "idTest" = "greater-than"
                                            }
                        "sortByObjectID" = "true"
                      } | ConvertTo-Json
            if ($startid -eq 0)
                {
                $dsobjects = Call-Dsapi -headers $headers -method Post -Body $json -uri $geturi -resttimeout $resttimeout -backoffdelay $backoffdelay
                $dsfullobjects = $dsobjects
                }
            else
                {
                $dsobjects = Call-Dsapi -headers $headers -method Post -Body $json -uri $geturi -resttimeout $resttimeout -backoffdelay $backoffdelay
                write-host "merge $dsobjects $dsfullobjects $uripart" -ForegroundColor Yellow -BackgroundColor Blue
                $dsfullobjects = Merge-DSobjects $dsobjects $dsfullobjects $uripart
                }
            write-host "$startid - start id"
            $dsobjectscount = $dsobjects.$uripart.Count
            write-host "$dsobjectscount - DSobjectscount"
            $startid = $startid + 1000
            }
        #until ($dsobjects.$uripart.Count -eq 0)
        until ($dsobjects.$uripart.Count -lt 999)
        }
    END
        {
        return $dsfullobjects
        }
    }

function Get-DSfilelist
    {
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [string]$inputdir,
        [Parameter(mandatory=$true)]
        [string]$uripart
        )
    BEGIN
        {
        $importdir = $inputdir + "\" + $uripart + "\"
        write-host "Import directory = $importdir"
        Add-Content $logfile "Processing directory - $importdir"
        }
    PROCESS
        {
        $childobjects = Get-ChildItem $importdir
        }
    END
        {
        #Add-Content $logfile "Output list - $childobjects"
        #write-host "Output list - $childobjects"
        return $childobjects
        }
    }

function compare-andcreatedsobject
    {
    #compare $importobject to $newdsmobject - if they are the same, return only the new DSM object ID.
    #If they are different, create a new object with the prefix and return the new object ID
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$importobject,
        [Parameter(mandatory=$true)]
        [pscustomobject]$newdsmobject,
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$true)]
        [string]$prefix,
        [Parameter(mandatory=$true)]
        [int32]$level
        )
    PROCESS
        {
        $newID = $newdsmobject.ID.psobject.Copy()
        $newdsmobject.psobject.Properties.Remove('ID')
        $diffoutput = Compare-Object -DifferenceObject $newdsmobject -ReferenceObject $importobject
        if ($diffoutput -and ($level -eq 1))
            {
            #Objects do not have the same properties - this should never happen
            write-host "Something is very wrong.  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" $importobject.name -ForegroundColor Red
            $logcontent = "ERROR: Something is very wrong.  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" + $importobject.name
            Add-Content $logfile $logcontent
            }
        elseif ($diffoutput -and ($level -eq 2))
            {
            write-host "Objects to be compared have different properties. New Object ID: $newID Imported Object name:" $importobject.name -ForegroundColor Red
            $logcontent = "DUPLICATE_DIFFER:  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" + $importobject.name
            Add-Content $logfile $logcontent
            $duplicate = $true
            create-newdsmobject $importobject $uripart $prefix $level $duplicate
            throw "create-newdsmobject not created yet.  Perhaps its not needed"
            }
        else
            {
            #We know that all of the properties are the same.  Loop through the values comparing.  Set $identical to $false if any properties differ.
            $objproperties = $newdsmobject.psobject.Properties.Name
            $identical = $true
            ForEach ($objproperty in $objproperties)
                {
                $propcompare = Compare-Object -ReferenceObject $importobject -DifferenceObject $newdsmobject -Property $objproperty
                if ((($propcompare) -and ($objproperty -ne 'originalIssue') -and ($objproperty -ne 'lastUpdated') -and ($objproperty -ne 'description') -and $level -eq 1))
                    {
                    write-host "Properties $objproperty Differ. New DSM Object ID: $newID, Imported Object Name:" $importobject.name -ForegroundColor Cyan
                    $logcontent = "DUPLICATE_DIFFER: Properties $objproperty Differ. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                    Add-Content $logfile $logcontent
                    $identical = $false
                    }
                elseif (($level -eq 2) -or ($level -eq 3))
                    {
                    #write-host "objproperty is $objproperty , "
                    #lookup $objproperty in lookuptable
                    #if entry exists,
                        #lookup ID in $masteridmappings (convert to/from strings - check whether int32 or string for entries)
                        #and replace ID with updated entry then compare ID's
                        #if they differ then $identical = $false - log and write-host
                    if ($lookuptable.$objproperty)
                        {
                        #ID looked ip form the table - to compare to what's been pulled from the dsm
                        #$oldidconverted has the value of what the list ID should be if the list is the same.  i.e. $oldidconverted should match the list ID of the object currently
                        #on the DSM if tehy are identical.  If not, they are different lists.
                        $oldidconverted = $masteridmappings.($lookuptable.$objproperty).($importobject.$objproperty.ToString())
                        #this is not needed - it's a false comparison.  Need to get the list ID from the current DSM object to compare. $newdsmobject is the object imported
                        #from the new dsm
                        #$newlistid = $importobject.$objproperty.ToString()
                        $newlistid = $newdsmobject.$objproperty.ToString()
                        $importeditemid = $importobject.$objproperty #just for confirming logic is fixed
                        #write-host "newlistid = $newlistid"
                        #write-host "oldidconverted = $oldidconverted"
                        #write-host "importeditemid = $importeditemid"
                        if ($oldidconverted -ne $newlistid)
                            {
                            #properties differ - create new object by setting $identical to $false
                            #then change the list ID on the object to be created to match the new list
                            $correctid = $oldidconverted/1 #Convert from string to Int32
                            $importobject.$objproperty = $correctid
                            if ($level -eq 2) {$identical = $false}
                            #write-host "newid = $newid"
                            $logcontent = "DUPLICATE_DIFFER: Property $objproperty is a list and the lists are have different contents. Imported Object ID: " + $newid + ", changed to " + $correctid
                            Add-Content $logfile $logcontent
                            write-host "Property $objproperty is a list and the lists have different contents.  Imported Object ID: $newid , changed to $correctid" -ForegroundColor Cyan
                            if ($level -eq 3)
                                {
                                write-host "Rule has a differing list property but is an IPS rule.  These cannot be created unless they are a custom rule"
                                #check for property: template - if it exists, it is a custom rule and can be created.
                                if ($importobject.template)
                                    {$identical = $false}
                                else
                                    {
                                    write-host "Property cannot be set $objproperty" -ForegroundColor Yellow 
                                    $global:irreconcilabledifferences.add($newdsmobject.Name,$objproperty)

                                    }
                                }
                            }
                        else
                            {
                            #write-host "Property $objproperty is a list and the lists are identical - ID $newid" -ForegroundColor Green
                            #Add-Content $logfile "DUPLICATE_IDENTICAL: Property $objproperty is a list and the lists are identical - ID $newid"
                            }
                        }
                    elseif (($propcompare) -and ($objproperty -ne 'originalIssue') -and ($objproperty -ne 'lastUpdated') -and ($objproperty -ne 'description')`
                     -and ($objproperty -ne 'dependsOnRuleIDs') -and ($objproperty -ne 'CVE') -and ($objproperty -ne 'CVSSScore'))
                        {
                        $logcontent = "DUPLICATE_DIFFER: Properties $objproperty Differ. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                        Add-Content $logfile $logcontent
                        $identical = $false
                        }
                    else
                        {
                        if ($objproperty -eq 'dependsOnRuleIDs')
                            {
                            write-host "L3 Property is dependsOnRuleIDs Skipping tests. New DSM Object ID: $newID, Imported Object Name:" $importobject.name -ForegroundColor yellow
                            $logcontent = "DUPLICATE_SKIPPED: L Property s dependsOnRuleIDs Skipping tests. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                            Add-Content $logfile $logcontent
                            $global:irreconcilabledifferences.add($newdsmobject.Name,$objproperty)
                            }
                        else
                            {
                            #write-host "L2 Properties $objproperty are identical. New DSM Object ID: $newID, Imported Object Name:" $importobject.name -ForegroundColor Green
                            #$logcontent = "DUPLICATE_IDENTICAL: L2 Properties $objproperty are identical. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                            #Add-Content $logfile $logcontent
                            }
                        
                        }
                    #note that the above covers all l2 situations (property has an entry, property is different but no entry and property is the same but has no entry
                    }
                else
                    {
                    #write-host "Properties $objproperty are identical. New DSM Object ID: $newID, Imported Object Name:" $importobject.name -ForegroundColor Green
                    #$logcontent = "DUPLICATE_IDENTICAL: Properties $objproperty are identical. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                    #Add-Content $logfile $logcontent
                    }
                }
            if ($identical -eq $false)
                {
                $importobject.name = $prefix + "_" + $importobject.name
                $searchjsonname = $importobject.name
                #
                $searchjson = @{
                            "maxItems" = 1
                            "searchCriteria" = @{
                                                "fieldName" = "name"
                                                "stringTest" = "equal"
                                                "stringValue" = "%$searchjsonname%"
                                                }
                            "sortByObjectID" = "true"
                          } | ConvertTo-Json
                $dssearchuri = $dsobjuri + "/search"
                #
                $body = $importobject | convertto-json

                if ($level -eq 3)
                    {
                    #breakpoint
                    }
                $searchobject = Call-Dsapi -headers $headers -method Post -Body $searchjson -uri $dssearchuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                if ($searchobject.$uripart.Count -ne 0)
                    {
                    $logname = $searchobject.$uripart.name
                    write-host "Search for object has found the new prefixed object exists - Name: $logname" -ForegroundColor Yellow
                    $logcontent = "ERROR: Prefixed Object exists. Name is: $logname Assuming it is correct.  If this script has not been run before, there is a problem."
                    Add-Content $logfile $logcontent
                    $dsobject = $searchobject.$uripart
                    }
                else
                    {
                    $dsobject = Call-Dsapi -headers $headers -method Post -Body $body -uri $dsobjuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                    }
                if (! $dsobject)
                    {
                    write-host "Error for Object $uripart " $importobject.name -ForegroundColor Red -BackgroundColor Black
                    $logcontent = "ERROR: for Object $uripart " + $importobject.name
                    Add-Content $logfile $logcontent
                    }
                else
                    {
                    $newID = $dsobject.ID
                    write-host "New Object created - Name: "$importobject.name "Object ID: $newID" -ForegroundColor Cyan
                    $logcontent = "DUPLICATE_DIFFER: New Object created - Name: " + $importobject.name + "Object ID: $newID"
                    Add-Content $logfile $logcontent
                    }
                }
            else
                {
                write-host "Obects are identical.  Make no changes and return existing object ID - Name: "$importobject.name "Object ID: $newID" -ForegroundColor Green
                $logcontent = "DUPLICATE_IDENTICAL: Obects are identical.  Make no changes and return existing object ID - Name: " + $importobject.name + "Object ID: $newID"
                Add-Content $logfile $logcontent
                }
            }
        }
    END
        {
        return $newID
        }
    }

function create-dsobject
    {
    #Checks for an identically namked object on the DSM.  If the identical object exists, adds the prefix to the name of the object and searches again.
    #If there is an Identical object, assumes they are the same as this should not happen unless this script is being ran against the "new" DS
    #multiple times which shouldn't happen
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$importobject,
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$true)]
        [string]$prefix
        )
    BEGIN
        {
        $searchjsonname = $importobject.name
        $searchjson = @{
                    "maxItems" = 1
                    "searchCriteria" = @{
                                        "fieldName" = "name"
                                        "stringTest" = "equal"
                                        "stringValue" = "%$searchjsonname%"
                                        }
                    "sortByObjectID" = "true"
                  } | ConvertTo-Json
        $dssearchuri = $dsmanager + 'api/' + $uripart + '/search'
        }
    PROCESS
        {
        $body = $importobject | convertto-json
        $searchobject = Call-Dsapi -headers $headers -method Post -Body $searchjson -uri $dssearchuri -resttimeout $resttimeout -backoffdelay $backoffdelay
        if ($searchobject.$uripart.Count -ne 0)
            {
            $logname = $searchobject.$uripart.name
            write-host "Search for object has found the new object exists - Name: $logname" -ForegroundColor Yellow
            write-host "Adding prefix to name $prefix" -ForegroundColor Yellow
            $logcontent = "WARNING: Object exists. Name is: $logname . Adding prefix"
            Add-Content $logfile $logcontent
            $importobject.name = $prefix + "_" + $importobject.name
            $searchjsonname = $importobject.name
            $searchjson = @{
                        "maxItems" = 1
                        "searchCriteria" = @{
                                            "fieldName" = "name"
                                            "stringTest" = "equal"
                                            "stringValue" = "%$searchjsonname%"
                                            }
                        "sortByObjectID" = "true"
                      } | ConvertTo-Json
            $body = $importobject | convertto-json
            $searchobject = Call-Dsapi -headers $headers -method Post -Body $searchjson -uri $dssearchuri -resttimeout $resttimeout -backoffdelay $backoffdelay
            if ($searchobject.$uripart.Count -ne 0)
                 {
                 $logname = $searchobject.$uripart.name
                 write-host "Search for object has found the new prefixed object exists - Name: $logname" -ForegroundColor Yellow
                 $logcontent = "ERROR: Prefixed Object exists. Name is: $logname Assuming it is correct.  If this script has not been run before, there is a problem."
                 Add-Content $logfile $logcontent
                 $newID = $searchobject.$uripart.ID
                 }
            else
                {
                $dsobject = Call-Dsapi -headers $headers -method Post -Body $body -uri $dsobjuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                $newID = $dsobject.ID #check what this returns
                }

            }

        else
            {
            $dsobject = Call-Dsapi -headers $headers -method Post -Body $body -uri $dsobjuri -resttimeout $resttimeout -backoffdelay $backoffdelay
            $newID = $dsobject.ID #check what this returns
            }
        }
    END
        {
        return $newID
        }
    }

function compare-dsobject
    {
    #compare $importobject to $newdsmobject - if they are the same, return $true, otherwise $false
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$importobject,
        [Parameter(mandatory=$true)]
        [pscustomobject]$newdsmobject
        )
    PROCESS
        {
        $diffoutput = Compare-Object -DifferenceObject $newdsmobject -ReferenceObject $importobject
        if ($diffoutput -and ($level -eq 1))
            {
            #Objects do not have the same properties - this should never happen
            write-host "Something is very wrong.  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" $importobject.name -ForegroundColor Red
            $logcontent = "ERROR: Something is very wrong.  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" + $importobject.name
            Add-Content $logfile $logcontent
            throw "Objects do not have the same properties - this should never happen"
            }
        else
            {
            #We know that all of the properties are the same.  Loop through the values comparing.  Set $identical to $false if any properties differ.
            $objproperties = $newdsmobject.psobject.Properties.Name
            $identical = $true
            ForEach ($objproperty in $objproperties)
                {
                #write-host "checking $objproperty"
                if($objproperty -in $nestedobjectpropertylist)
                    {
                    #loop through subproperties
                    write-host "It's got subproperties"
                    $subproperties = $newdsmobject.$objproperty.psobject.Properties.Name
                    ForEach ($subproperty in $subproperties)
                        {
                        if ($subproperty -in $arraysubobjectidlist)
                            {
                            write-host "compare the arrays" -ForegroundColor Yellow
                            if ($importobject.$objproperty.$subproperty -and $newdsmobject.$objproperty.$subproperty)
                                {
                                $subpropcompare = Compare-Object -ReferenceObject $importobject.$objproperty.$subproperty -DifferenceObject $newdsmobject.$objproperty.$subproperty #using -property decides the objects are different if the contents of the array are in a different order
                                if ($subpropcompare)
                                    {
                                    write-host "array subproperty $subproperty differs" -ForegroundColor Red
                                    $identical = $false
                                    }
                                else
                                    {
                                    write-host "array subproperty $subproperty is the same" -ForegroundColor Cyan
                                    }                               
                                }
                            elseif ($importobject.$objproperty.$subproperty -and !($newdsmobject.$objproperty.$subproperty))
                                {
                                write-host "array subproperty $subproperty exists on the import file but not the destination object" -ForegroundColor Red
                                $identical = $false
                                }
                            elseif (!($importobject.$objproperty.$subproperty) -and $newdsmobject.$objproperty.$subproperty)
                                {
                                write-host "array subproperty $subproperty exists on the destination object but not the import file" -ForegroundColor Red
                                $identical = $false
                                }
                            else
                                {
                                write-host "array subproperty $subproperty does not exist on either object.  They are the same"
                                }
                            }
                        else
                            {
                            $subpropcompare = Compare-Object -ReferenceObject $importobject.$objproperty -DifferenceObject $newdsmobject.$objproperty -Property $subproperty
                            write-host "comparing $subproperty"
                            if ($subpropcompare)
                                {
                                $identical = $false
                                write-host "subproperty $subproperty differs"
                                }
                            }
                        }
                    }
                elseif ($objproperty -notin $propertiestoskip)
                    {
                    $propcompare = Compare-Object -ReferenceObject $importobject -DifferenceObject $newdsmobject -Property $objproperty
                    if ($propcompare)
                        {
                        $identical = $false
                        write-host "Objects to be compared have different properties. New Object ID: $newID Imported Object name:" $importobject.name -ForegroundColor Red
                        write-host "differing property is: $objproperty" -ForegroundColor Red
                        $logcontent = "DUPLICATE_DIFFER:  Objects have different properties. New Object ID: $newID Imported Object name:" + $importobject.name + "Property:" + $objproperty
                        Add-Content $logfile $logcontent
                        }
                    else
                        {
                        #write-host "property $objproperty is identical"
                        }
                    }
                else
                    {
                    #log that property is skipped
                    }
            
                }
            }
        }
    END
        {
        #write-host "end compare-dsobject"
        return $identical
        }
    }

function replace-dslists
    {
    [CmdletBinding()]
    #function takes an object property that refers to an ID and replaces the ID reference to the correct reference for the new manager using the lookup table.
    #If the function is passed RuleIDs then it needs to take in an array.  Each element needs to be updated and an array with the new values returned.
    #The listcheck is the object name in $masteridmappings that the array of rules are checked against.
    Param
        (
        [Parameter(mandatory)]
        [string]$listcheck,
        [Parameter(mandatory,ParameterSetName = 'IndividualID')]
        [int32]$listID,
        [Parameter(mandatory,ParameterSetName = 'ArrayOfIDs')]
        [array]$listIDArray
        #Look into param if or etc for using the array as a different variable instead.
        )
    BEGIN
        {
        $arrayidobjectlist = @('firewallrules','applicationtypes','intrusionpreventionrules') #List the properties that need to go a layer deeper
        }
    PROCESS
        {
        if ($arrayidobjectlist -contains $listcheck)
            {
            #For Each elelment in the array, replace with the ID from the New DSM
            $updatedlistID = $listIDArray | ForEach {$_ = [int]$masteridmappings.$listcheck.($_.ToString());$_}
            #
            }
        else
            {
            $updatedlistID = $masteridmappings.($lookuptable.$listcheck).($listID.ToString())
            #$oldidconverted = $masteridmappings.($lookuptable.$objproperty).($checkobject.$objproperty.ToString())
            #change the list ID on the object to be created to match the new list
            }
        }
    END
        {
        return $updatedlistID
        }
    }

function replace-dsnestedlists
    {
    [CmdletBinding()]
    #Function check each property using $lookuptable - if there is a match on $lookuptable,
    #use $masteridmappings replace the value from the old DSM with the value for the object created on the new DSM
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$checkobject
        )  
    BEGIN
        {
        #search for lists within the object and replace old values with new
        $objproperties = $checkobject.psobject.Properties.Name
        #$arrayidobjectlist = @('nested','antiMalware','firewallrules','applicationtypes','intrusionpreventionrules') #List the properties that need to go a layer deeper
        #$arraysubobjectidlist = @('ruleIDs','applicationTypeIDs') # Now defined at beginning of script
        }            
    PROCESS
        {
        ForEach ($objproperty in $objproperties)
            {
            #check to see if the property contains multiple child properties that may contain lists that need replacing.
            #if ($arrayidobjectlist -contains $lookuptable.$objproperty) #old-remove
            if ($objproperty -in $nestedobjectpropertylist)
                {
                $subproperties = $checkobject.$objproperty.psobject.Properties.Name
                #loop through each property.  Check to see if it's to be have its lists changed
                ForEach ($subproperty in $subproperties)
                    {
                    #if ($lookuptable.$subproperty -eq "array")
                    #if ($arraysubobjectidlist -contains $subproperty)
                    if ($subproperty -eq "ruleIDs")
                        {
                        #Its an array of firewall rules, IPS rules, IM or LI rules
                        $listcheck = $lookuptable.$objproperty #provide replace-dslists information on which object in $masteridmappings to search
                        $checkobject.$objproperty.$subproperty = replace-dslists -listcheck $listcheck -listIDArray $checkobject.$objproperty.$subproperty
                        }
                    elseif ($subproperty -eq "applicationTypeIDs")
                        {
                        #It's an array of Application types for a policy
                        $checkobject.$objproperty.$subproperty = replace-dslists -listcheck $lookuptable.$subproperty -listIDArray $checkobject.$objproperty.$subproperty
                        }
                    elseif ($lookuptable.$subproperty)
                        {
                        #it's not an array
                        $checkobject.$objproperty.$subproperty = replace-dslists -listcheck $subproperty -listID $checkobject.$objproperty.$subproperty
                        }
                    }
                }
            #see if the property is a list that needs replacing
            elseif ($lookuptable.$objproperty)
                {
                $checkobject.$objproperty = replace-dslists -listcheck $objproperty -listID $checkobject.$objproperty
                }
            }
        }
    END
        {
        return $checkobject
        }                    
    }

function Add-Dsobjects
	{
    [CmdletBinding()]
    #Function only imports individual .json files, strips away the object ID and then adds the object.  A better version would be fed a PScustom object
    # and iterate through that to create new objects.  Another function should read the filesystem and where there are multiple files, combine them into a single PScustomobject.
    #for now, I will create the new function just to deal with intrusion prevention rules and policies.  Ideally, this function would be removed.
    Param
        (
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$true)]
        [array]$filedirlist,
        [Parameter(mandatory=$true)]
        [string]$prefix,
        [Parameter(mandatory=$true)]
        [int32]$level
        )
    BEGIN
        {
        $IDmappings = @{}
        write-host "Processing add-dsobjects URIpart =  $uripart, prefix = $prefix, level = $level"
        Add-Content $logfile "Processing add-dsobjects URIpart =  $uripart, prefix = $prefix, level = $level"
        $dsobjuri = $dsmanager + 'api/' + $uripart + '/'
        $dssearchuri = $dsmanager + 'api/' + $uripart + '/search'
        if (($level -gt 3) -or ($level -lt 1))
            {
            write-host "level is not 1, 2 or 3"
            Add-Content $logfile "add-dsobjects called with an invalid level. uripart = $uripart level = $level"
            throw "Level is not 1, 2 or 3.  This function only works at 3 levels"
            }
        }
    PROCESS
        {
        ForEach ($filedir in $filedirlist)
            {
            $add = $true
            $dsimportfile = $filedir.VersionInfo.FileName
            #write-host "ds import file: $dsimportfile"
            if ($dsimportfile)
                {
                #write-host "DS Import file path = $dsimportfile"
                Add-Content $logfile "DS Import file path = $dsimportfile"
                $psobjectfromjson = Get-Content -Raw -Path $dsimportfile | ConvertFrom-Json
                $originalid = $psobjectfromjson.ID
                $psobjectfromjson.psobject.Properties.Remove('ID')
                #check if object with same name exists
                $searchname = $psobjectfromjson.name
                $searchjson = @{
                            "maxItems" = 1
                            "searchCriteria" = @{
                                                "fieldName" = "name"
                                                "stringValue" = $searchname
                                                "stringTest" = "equal"
                                                }
                            "sortByObjectID" = "true"
                          } | ConvertTo-Json
                $searchobject = Call-Dsapi -headers $headers -method Post -Body $searchjson -uri $dssearchuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                if ($searchobject.$uripart.Count -eq 1)
                    {
                    write-host "Duplicate name $uripart " $psobjectfromjson.name " ID of dupe:" $searchobject.$uripart.ID
                    $logcontent = "DUPLICATE_NAME: $uripart " + $psobjectfromjson.name + " ID of dupe:" + $searchobject.$uripart.ID
                    Add-Content $logfile "$logcontent"
                    #This is bad.  I know but I couldn't get the array returned as a property of the pscustomobject returned into a pscustomobject with less code.
                    $newdsmjson =  $searchobject.$uripart | Convertto-Json
                    $newdsmpsobject = $newdsmjson | convertfrom-json
                    $newID = compare-andcreatedsobject $psobjectfromjson $newdsmpsobject $uripart $prefix $level
                    }
                else
                    {
                    write-host "Original name $uripart " $psobjectfromjson.name " ID of dupe:" $searchobject.$uripart.ID #There may be a bug here.  Possible that there is never a dupe.
                    $logcontent = "ORIGINAL_NAME: $uripart " + $psobjectfromjson.name + " ID of dupe:" + $searchobject.$uripart.ID
                    Add-Content $logfile "$logcontent"
                    if ($level -eq 2)
                        {
                        #search for lists within the object and replace old values with new
                        #use replace-dslists instead here
                        $objproperties = $psobjectfromjson.psobject.Properties.Name
                        ForEach ($objproperty in $objproperties)
                            {
                            if ($lookuptable.$objproperty)
                                {
                                $oldidconverted = $masteridmappings.($lookuptable.$objproperty).($psobjectfromjson.$objproperty.ToString())
                                #change the list ID on the object to be created to match the new list
                                $correctid = $oldidconverted/1 #Convert from string to Int32
                                $oldid = $psobjectfromjson.$objproperty
                                $psobjectfromjson.$objproperty = $correctid
                                $logcontent = "OBJECT_PROPERTY_CHANGE: Imported Object ID: " + $objproperty + ", changed to " + $correctid
                                Add-Content $logfile $logcontent

                                write-host "OBJECT_PROPERTY_CHANGE: Property: $objproperty Imported Object ID: $oldid , changed to $correctid"
                                }
                            }
                        }

                    $body = $psobjectfromjson | convertto-json
                    #$dsobject = Invoke-RestMethod -Headers $headers -method Post -Body $body -ContentType 'application/json' -Uri $dsobjuri -TimeoutSec $resttimeout
                    $dsobject = Call-Dsapi -headers $headers -method Post -body $body -uri $dsobjuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                    $newID = $dsobject.ID
                    }
                    #write-host "OriginalID "$originalid
                    #write-host "New ID" $newID
                $IDmappings.Add($originalid.ToString(),$newID.ToString())
                }
            else
                {
                write-host "$filedir is not a file"
                Add-Content $logfile "$filedir is not a file"
                }
            }
        }
    END
        {
        return $IDmappings
        }
    }

function Add-DsobjectsFromPScustom
	{
    [CmdletBinding()]
    #Function takes a PScustomObject containing all of the objects to be added.  Depending on whether the level is 1, 2 or 3 it either just:
    # adds the objects after removing the ID's (Level 1)
    # Modifies the references to other objects that now have new ID's (level 2)
    # I'm trying to work out why level 3 objects don't need their references to other objects rewriting.  Is it a bug?
    #The prefix is used when a Duplicate object is found.  It's added to the new object.
    #Due to the new functios replace-dsnestedlists being created, I have added a new variable to track when this newer, simpler way of working is being used. $dslists = 1
    #This function needs significant refactoring to just use replace-dsnestedlists, compare-dsobject and create-dsobject.  compare-andcreatedsobject is a badly written function.
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$importobjects,
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$true)]
        [string]$prefix,
        [Parameter(mandatory=$true)]
        [int32]$level
        )
    BEGIN
        {
        $IDmappings = @{}
        $searchobject = @{}
        write-host "Processing Add-DsobjectsFromPScustom URIpart =  $uripart, prefix = $prefix, level = $level"
        Add-Content $logfile "Processing Add-DsobjectsFromPScustom URIpart =  $uripart, prefix = $prefix, level = $level"
        $dsobjuri = $dsmanager + 'api/' + $uripart + '/'
        $dssearchuri = $dsmanager + 'api/' + $uripart + '/search'
        if (($level -gt 9) -or ($level -lt 1))
            {
            write-host "level is not between 1 and 9 inclusive"
            Add-Content $logfile "Add-DsobjectsFromPScustom called with an invalid level. uripart = $uripart level = $level"
            throw "Level is not between 1 and 9 inclusive.  This function only works at those levels"
            }
        }
    PROCESS
        {
        #Importobjects is the pscustomobject loaded from the file and passed into this function
        #$objectfromdsm is the full set of objects on the new DSM to be compared to
        $objectfromdsm = Get-DSObjects $dsmanager $uripart $resttimeout $backoffdelay -parameters '?overrides=true'
        if ($level -eq 2)
            {
            $filteredrules = $importobjects.$uripart
            ForEach ($ruleobject in $filteredrules)
                {
                $updatedobject = replace-dsnestedlists $ruleobject
                }
            $dslists = 1
            }
        if ($level -eq 3)
            {
            #prepare variables for easy comparison
            $oldobjects = $importobjects.$uripart
            $newobjects = $objectfromdsm.$uripart
            $oldipshash = @{}
            $newipshash = @{}
            #lookup the new rule ID's
            add-content $logfile "Processing IPS rules"
            add-content $logfile "---------------------------------------------------------"
            #Filter out custom IPS rules.  For the Trend IPS rules we just need to map the old ID's to the new ID's
            $oldstdipsrules = $oldobjects | where type
            write-host "There are $oldstdipsrules.count IPS Rules"
            #####################Begin much faster code
            ForEach ($oldipsrule in $oldstdipsrules)
	            {
	            $oldipshash.Add($oldipsrule.identifier, $oldipsrule.ID)
	            }
            $newipsrules = $newobjects | where type
            ForEach ($newipsrule in $newipsrules)
            	{
            	$newipshash.Add($newipsrule.identifier, $newipsrule.ID)
            	}
            $counter = 1
            ForEach ($ruletoadd in $oldipshash.keys)
            	{
            	$counter++
            	write-host $counter
            	$newipsruleID = $newipshash.$ruletoadd
            	$oldipsruleid = $oldipshash.$ruletoadd
            	$IDmappings.Add($oldipsruleid.ToString(),$newipsruleID.ToString())
            	}
            #####################end much faster code
            <#
            #####################begin removed slower code
            $ipscounter = 0
            ForEach ($oldipsrule in $oldstdipsrules)
                {
                write-host $ipscounter
                $ipscounter++
                #then compare the objects
                $newipsrule = $newobjects | where identifier -eq $oldipsrule.identifier
                $originalid = $oldipsrule.ID
                $newID = $newipsrule.ID
                $ipsrulename = $oldipsrule.name
                Write-Host "Original Rule ID: $originalid , new ID: $newID , Name: $ipsrulename"
                add-content $logfile "Original Rule ID: $originalid , new ID: $newID , Name: $ipsrulename"
                #update masterIDmappings
                $IDmappings.Add($originalid.ToString(),$newID.ToString())
                }
            ########################End removed slower code
            #>
            #Now to the lookup/add where necessary only for th custom IPS rules
            $filteredrules = $oldobjects | where template
            $dslists = 1
            }
        if ($level -eq 4)
            {
            $filteredrules = $importobjects.$uripart | where parentID -eq $null
            #create uripart array.  array to contain 
            ForEach ($ruleobject in $filteredrules)
                {
                $updatedobject = replace-dsnestedlists $ruleobject
                }
            $dslists = 1 #mark that the lists have already been replaced
            }
        if ($level -gt 4)
            {
            $filteredrules = $importobjects.$uripart | where parentID -in $masteridmappings.policies.keys
            write-host "Beginning policies at level $level" -ForegroundColor Yellow
            #create uripart array.  array to contain 
            ForEach ($ruleobject in $filteredrules)
                {
                $updatedobject = replace-dsnestedlists $ruleobject
                }
            $dslists = 1 #mark that the lists have already been replaced
            }
        #Search the Fileterd rules individualy.  There aren't lots of them so the multiple API calls isn't much of a time waster.
        ForEach ($ruleobject in $filteredrules)
            {
            write-host $ruleobject.name
            write-host "------------------"
            $originalid = $ruleobject.ID
            $ruleobject.psobject.Properties.Remove('ID')
            #check if object with same name exists
            #############################################################################Second API call - not needed
            $searchname = $ruleobject.name
            $searchjson = @{
                        "maxItems" = 1
                        "searchCriteria" = @{
                                            "fieldName" = "name"
                                            "stringValue" = $searchname
                                            "stringTest" = "equal"
                                            }
                        "sortByObjectID" = "true"
                      } | ConvertTo-Json
            #$searchobject = Call-Dsapi -headers $headers -method Post -Body $searchjson -uri $dssearchuri -resttimeout $resttimeout -backoffdelay $backoffdelay #why call the API twice?$ob
            #Above replaced with below to avoid unnecessary API query
            
            $searchobject.$uripart = $objectfromdsm.$uripart | where name -EQ $ruleobject.name # this is maintained to avoid refactoring rest of code for now
            $newdsmobject = $objectfromdsm.$uripart | where name -EQ $ruleobject.name
            #If a search for the object by name returns an object, there is a duplicate.  Compare the duplicate and if the same, just update.  If different, create a new object
            #For Polices as they have already used replace-dsnestedlists
            ################################begin
            if (($dslists -eq 1) -and $newdsmobject) #will need to add logic for multiple matches
                {
                $identical = compare-dsobject -importobject $ruleobject -newdsmobject $newdsmobject
                if ($identical -eq $true)
                    {
                    $newid = $newdsmobject.ID
                    }
                else
                    {
                    $newID = create-dsobject -importobject $ruleobject -uripart $uripart -prefix $prefix
                    }
                }
            elseif ($dslists -eq 1)
                {
                $newID = create-dsobject -importobject $ruleobject -uripart $uripart -prefix $prefix
                }
            ################################end
            elseif (($searchobject.$uripart.Count -eq 1) -and ($dslists -ne 1)) #was originally just an if statement
                {
                write-host "Duplicate name $uripart " $ruleobject.name " ID of dupe:" $searchobject.$uripart.ID
                $logcontent = "DUPLICATE_NAME: $uripart " + $ruleobject.name + " ID of dupe:" + $searchobject.$uripart.ID
                Add-Content $logfile "$logcontent"
                #This is bad.  I know but I couldn't get the array returned as a property of the pscustomobject returned into a pscustomobject with less code.
                $newdsmjson =  $searchobject.$uripart | Convertto-Json
                $newdsmpsobject = $newdsmjson | convertfrom-json
                $newID = compare-andcreatedsobject $ruleobject $newdsmpsobject $uripart $prefix $level
                }
            #If the search does not return an object, create a new one.  There are no dupes
            else
                {
                write-host "New Object to be created: $uripart " $ruleobject.name
                $logcontent = "New Object to be created: $uripart " + $ruleobject.name
                Add-Content $logfile "$logcontent"
                #If level is 2 or 3, the object will contain lists and they will have incorrect values.  Replace the "old" values from the Old DSM to the values on the new DSM.
                if (($level -eq 2)-or ($level -eq 3))
                    {
                    #search for lists within the object and replace old values with new
                    #use replace-dslists to do the propery replacement $ruleobject = replace-dslists $ruleobject
                    $objproperties = $ruleobject.psobject.Properties.Name
                    ForEach ($objproperty in $objproperties)
                        {
                        if ($lookuptable.$objproperty)
                            {
                            $oldidconverted = $masteridmappings.($lookuptable.$objproperty).($ruleobject.$objproperty.ToString())
                            #change the list ID on the object to be created to match the new list
                            $correctid = $oldidconverted/1 #Convert from string to Int32
                            $oldid = $ruleobject.$objproperty
                            $ruleobject.$objproperty = $correctid
                            $logcontent = "OBJECT_PROPERTY_CHANGE: Imported Object ID: " + $objproperty + ", changed to " + $correctid
                            Add-Content $logfile $logcontent
                            write-host "OBJECT_PROPERTY_CHANGE: Property: $objproperty Imported Object ID: $oldid , changed to $correctid"
                            }
                        }
                    }
                #Now the Object has been updated If necessary, create it on the DSM
                $body = $ruleobject | convertto-json
                $dsobject = Call-Dsapi -headers $headers -method Post -body $body -uri $dsobjuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                $newID = $dsobject.ID
                }
            $IDmappings.Add($originalid.ToString(),$newID.ToString())
            #breakpoint
            }
        }
    END
        {
        return $IDmappings
        }
    }


#Main body
#Level One - Import objects with no links to other objects
#Forget IM, LI and AC for now.
if (! $loadfile) {$loneobjects = @('directorylists','contexts','fileextensionlists','filelists','iplists','maclists','portlists','schedules','statefulconfigurations')}
else {$loneobjects = $null}
    
#if (! $loadfile){$loneobjects = @('portlists')}
ForEach ($uripart in $loneobjects)
    {
    $dsimportobjects = get-dsfilelist $inputdir $uripart
    if ($dsimportobjects)
        {
        $idmappings = add-dsobjects $uripart $dsimportobjects $prefix  1
        }
    else
        {
        write-host "Empty Directory for $uripart" -ForegroundColor Yellow
        Add-Content $logfile "Empty Directory for $uripart"
        }
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    }

#Level 2 - Import objects with dependencies to only level One objects
#Firewall rules (port lists, ip lists, mac lists)
#IPS application types (port lists)
#AM scan configs (File, extension and directory lists)
<#
if (! $loadfile) {$ltwoobjects = @('firewallrules','antimalwareconfigurations')}
#
ForEach ($uripart in $ltwoobjects)
    {
    $dsimportobjects = get-dsfilelist $inputdir $uripart
    if ($dsimportobjects)
        {
        $idmappings = add-dsobjects $uripart $dsimportobjects $prefix  2
        }
    else
        {
        write-host "Empty Directory for $uripart" -ForegroundColor Yellow
        Add-Content $logfile "Empty Directory for $uripart"
        }
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    }
    #>
#Level 2 part 2 - applicationtypes are now exported as a signle file
if (! $loadfile) {$ltwoobjects = @('firewallrules','antimalwareconfigurations','applicationtypes')}
ForEach ($uripart in $ltwoobjects)
    {
    $dsimportobject = get-dsfilelist $inputdir $uripart
    $dsimportfile = $dsimportobject.VersionInfo.FileName
    Add-Content $logfile "DS Import file path = $dsimportfile"
    #load the IPS object from the filesystem
    $objectfromfile = Get-Content -Raw -Path $dsimportfile | ConvertFrom-Json
    if ($dsimportobject.count -eq 1)
        {
        $idmappings = Add-DsobjectsFromPScustom -importobjects $objectfromfile -uripart $uripart -prefix $prefix -level 2
        }
    else
        {
        write-host "Directory does not have only one file $uripart" -ForegroundColor Yellow
        Add-Content $logfile "Directory does not have only one file for $uripart"
        }
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    }






#level 3 - Import rules.
#Ips Rules (ips application types)
#IPS rules are imported as a single file as individual files simply take too long.
#the masterIDmapping table needs to be updated so each rule needs to be checked.  The best way to do this in reasonable time is to export
# all of the IPS rules from the manager and process within this script.  Then just add the custom IPS rules.
if (! $loadfile) {$lthreeobjects = @('intrusionpreventionrules')}
ForEach ($uripart in $lthreeobjects)
    {
    $dsimportobject = get-dsfilelist $inputdir $uripart
    $dsimportfile = $dsimportobject.VersionInfo.FileName
    Add-Content $logfile "DS Import file path = $dsimportfile"
    #load the IPS object from the filesystem
    $objectfromfile = Get-Content -Raw -Path $dsimportfile | ConvertFrom-Json
    if ($dsimportobject.count -eq 1)
        {
        $idmappings = Add-DsobjectsFromPScustom -importobjects $objectfromfile -uripart $uripart -prefix $prefix -level 3
        }
    else
        {
        write-host "Directory does not have only one file $uripart" -ForegroundColor Yellow
        Add-Content $logfile "Directory does not have only one file for $uripart"
        }
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    }


if ($loadfile)
    {
    $masteridmappings = Get-Content -Raw -Path $loadfile | ConvertFrom-Json
    }
else
    {
    $masteridmappings = $masteridmappings | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    }





#Level 4 - Import the policies

#Import all policies into a PSCustomObject
#work through the object and create a hashtable where each policy OLD ID is paired with it's "level" Base policies are level 1, children of those are level 2, etc  detect when there are no more polieies (e.g. nothing beyond level 3)
#Forget levels.  Just use masteridmappings.  Split the PScustomobject into two objects for each level - start by using  where-object
#Split to where (! parent policyID) and another object where (parent policy ID)
#loop through levels splitting to where (parent policy ID exists in IDmappings) and where (!parent policy ID exists in IDmappings)
#send split pscustomobject to $policyIDmappings = new-dsobjectfrompscustom
#add the objects together using Merge-DSobjects.  Merge-dsobjects needs a uripart so it will be object.policies.hashtable
#once complete, update $masteridmappings

if ($loadfile)
    {
    $masteridmappings = Get-Content -Raw -Path $loadfile | ConvertFrom-Json
    }
$uripart = 'policies'
$dsimportobject = get-dsfilelist $inputdir $uripart
$dsimportfile = $dsimportobject.VersionInfo.FileName
Add-Content $logfile "DS Import file path = $dsimportfile"
#load the Policies object from the filesystem
$fullobjectfromfile = Get-Content -Raw -Path $dsimportfile | ConvertFrom-Json
if ($dsimportfile.count -eq 1)
    {
    $idmappings = Add-DsobjectsFromPScustom -importobjects $fullobjectfromfile -uripart $uripart -prefix $prefix -level 4
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    $policyloop = 5 #start at 5 as level 4 is already done
    do
        {
        $idmappings = Add-DsobjectsFromPScustom -importobjects $fullobjectfromfile -uripart $uripart -prefix $prefix -level $policyloop
        $noteproperty = $uripart + "Level" + $policyloop
        $masteridmappings | Add-Member -NotePropertyName $noteproperty -NotePropertyValue $idmappings
        $policieslevel = "policiesLevel" + $policyloop
        $masteridmappings.$policieslevel.Keys | foreach {$masteridmappings.policies.add($_, $masteridmappings.$policieslevel.$_)}
        $policyloop++
        }
    until ($policyloop -ge 10)
    #end add the loop
    }
else
    {
    write-host "Directory does not have only one file $uripart" -ForegroundColor Yellow
    Add-Content $logfile "Directory does not have only one file for $uripart"
    }



##############################################################

#save the mapping table to disk
$savejson = $masteridmappings | ConvertTo-Json
$savejsonfile = New-Item -type file "$logfilepath\Output-DSPolicies-$date-1.json"
Add-Content $savejsonfile $savejson
#Write the list of problematic rule imports to disk
if ($global:irreconcilabledifferences.keys.Count -gt 0)
    {
    $difffile = New-Item -type file "$logfilepath\Output-DSPolicies-Failedimports-$date.json"
    $savediff = $global:irreconcilabledifferences | ConvertTo-Json
    Add-Content $difffile $savediff
    }
Write-host "-----------------------------------------Complete-----------------------------------------------" -ForegroundColor DarkBlue -BackgroundColor White