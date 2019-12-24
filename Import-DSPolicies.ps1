<#
Description here
$masteridmappings.$uripart.Item($number)
gets the value for the key.  using $masteridmappings.$uripart.number doesn't work for first item.
test: $masteridmappings.$uripart.'number'


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
$prefix = "tst1"
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
}
$global:irreconcilabledifferences = @{}

#Create a PScustomObject to store the Object ID mappings
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

function Add-Dsobjects
	{
    [CmdletBinding()]
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
                #$searchobject = Invoke-RestMethod -Headers $headers -method Post -Body $searchjson -ContentType 'application/json' -Uri $dssearchuri -TimeoutSec $resttimeout
                $searchobject = Call-Dsapi -headers $headers -method Post -Body $searchjson -uri $dssearchuri -resttimeout $resttimeout -backoffdelay $backoffdelay
                if ($searchobject.$uripart.Count -eq 1)
                    {
                    write-host "Duplicate name $uripart " $psobjectfromjson.name " ID of dupe:" $searchobject.$uripart.ID
                    $logcontent = "DUPLICATE_NAME: $uripart " + $psobjectfromjson.name + " ID of dupe:" + $searchobject.$uripart.ID
                    Add-Content $logfile "$logcontent"
                    #New function here - compare objects - if the same, output just the new object ID.  If different, create new object with prefix and output new object ID
                    #Input is imported object and object from API.  Output is Object ID of unmodified/new object.
                    #This is bad.  I know but I couldn't get the array returned as a property of the pscustomobject returned into a pscustomobject with less code.
                    $newdsmjson =  $searchobject.$uripart | Convertto-Json
                    $newdsmpsobject = $newdsmjson | convertfrom-json
                    $newID = compare-andcreatedsobject $psobjectfromjson $newdsmpsobject $uripart $prefix $level
                    #$newID = $dsobject.ID
                    }
                else
                    {
                    write-host "Original name $uripart " $psobjectfromjson.name " ID of dupe:" $searchobject.$uripart.ID
                    $logcontent = "ORIGINAL_NAME: $uripart " + $psobjectfromjson.name + " ID of dupe:" + $searchobject.$uripart.ID
                    Add-Content $logfile "$logcontent"
                    if ($level -eq 2)
                        {
                        #search for lists within the object and replace old values with new
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
                    write-host "OriginalID "$originalid
                    write-host "New ID" $newID
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


#Main body
#Level One - Import objects with no links to other objects
#Forget IM, LI and AC for now.
if (! $loadfile){$loneobjects = @('directorylists','contexts','fileextensionlists','filelists','iplists','maclists','portlists','schedules','statefulconfigurations')}

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
if (! $loadfile) {$ltwoobjects = @('firewallrules','applicationtypes','antimalwareconfigurations')}

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




#level 3 - Import rules.
#Ips Rules (ips application types)
if (! $loadfile) {$lthreeobjects = @('intrusionpreventionrules')}
ForEach ($uripart in $lthreeobjects)
    {
    $dsimportobjects = get-dsfilelist $inputdir $uripart
    if ($dsimportobjects)
        {
        $idmappings = add-dsobjects $uripart $dsimportobjects $prefix  3
        }
    else
        {
        write-host "Empty Directory for $uripart" -ForegroundColor Yellow
        Add-Content $logfile "Empty Directory for $uripart"
        }
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    }


if ($loadfile)
    {
    $importmappings = $inputdir + "\" + $loadfile
    $mappingsobject = Get-Content -Raw -Path $importmappings | ConvertFrom-Json
    }
else
    {
    $mappingsobject = $masteridmappings | ConvertTo-Json | ConvertFrom-Json
    }
#Level 4 - Import the policies

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