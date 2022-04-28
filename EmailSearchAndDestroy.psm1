﻿Function Prompt {
    Write-Host "[PS] " -NoNewline -ForegroundColor Yellow
    Write-Host "S&D [$($ProductVersion)]" -NoNewline -ForegroundColor White -BackgroundColor DarkRed
    Write-Host " $($executionContext.SessionState.Path.CurrentLocation)>" -NoNewline -ForegroundColor White

    return " "
}

Function Init-SDWorkspace {
    clear

    Write-Host "$ProductName [$ProductVersion]" -ForegroundColor Black -BackgroundColor Gray

    Write-Host "Initializing..."

    $Connected = $false

    #Connect to Exchange
    #Write-JustifiedStatusOutput -Message "Connecting to Microsoft Exchange" -Pending
    $SearchMailboxTest = Get-Command Search-Mailbox -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if($SearchMailboxTest -eq $null) {
        $Creds = Get-Credential -Message "Exchange Administrative Account"

        #Try to connect
        $Servers = @(
            "server1.domain.local",
            "server2.domain.local",
            "server3.domain.local"
        )
        $i = 0

        while($Connected -eq $false) {
            if($i -ge $Servers.Count) {
                #Write-JustifiedStatusOutput -Message "Connecting to Microsoft Exchange" -Failed
                Write-Host "FATAL: Unable to connect to Microsoft Exchange." -ForegroundColor DarkRed
                break
            }

            $Session = New-PSSession -Name E19 -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$($Servers[$i])/powershell/" -Credential $Creds -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

            if($Session -ne $null) {
                #Treat as success, import the session
                Import-PSSession $Session -AllowClobber -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

                #Check for the module
                $CommandTest = Get-Command -Module tmp_* -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                if($CommandTest.Name -ne $null) {
                    #We connected, check permissions
                    if($CommandTest.Name.Contains("Search-Mailbox") -and
                    $CommandTest.Name.Contains("Get-Mailbox") -and
                    $CommandTest.Name.Contains("New-Mailbox") -and
                    $CommandTest.Name.Contains("Add-MailboxPermission") -and
                    $CommandTest.Name.Contains("Remove-Mailbox") -and
                    $CommandTest.Name.Contains("Get-ExchangeServer") -and
                    $CommandTest.Name.Contains("Get-TransportService") -and
                    $CommandTest.Name.Contains("Get-MessageTrackingLog")) {
                        #Permissions confirmed
                        #Write-JustifiedStatusOutput -Message "Connecting to Microsoft Exchange"
                        #Write-Host ""
                        $Connected = $true
                        break
                    }
                }
            }

            $i++
        }
    } else {
        #We already have a session
        #Write-JustifiedStatusOutput -Message "Connecting to Microsoft Exchange"
        #Write-Host ""

        $Connected = $true
    }

    if($Connected) {
        #Write welcome
        clear
        Write-Host "$ProductName [$ProductVersion]" -ForegroundColor Black -BackgroundColor Gray

        Write-Host ""

        Write-Host "  ____                           _         "
        Write-Host " / ___|   ___   __ _  _ __  ___ | |__      "
        Write-Host " \___ \  / _ \ / _` || '__|/ __|| '_ \     "
        Write-Host "  ___) ||  __/| (_| || |  | (__ | | | |    "
        Write-Host " |____/  \___| \__,_||_|   \___||_| |_|    "
        Write-Host "        ___                                "
        Write-Host "       ( _ )                               "
        Write-Host "       / _ \/\                             "
        Write-Host "      | (_>  <                             "
        Write-Host "  ____ \___/\/      _                      "
        Write-Host " |  _ \   ___  ___ | |_  _ __  ___   _   _ "
        Write-Host " | | | | / _ \/ __|| __|| '__|/ _ \ | | | |"
        Write-Host " | |_| ||  __/\__ \| |_ | |  | (_) || |_| |"
        Write-Host " |____/  \___||___/ \__||_|   \___/  \__, |"
        Write-Host "                                     |___/ "

        Write-Host ""

        Write-Host "You are connected to Microsoft Exchange and ready to perform search and destroy operations.  The fast track for this process is:"
        Write-Host "   1. Create the workspace and perform the preview search." -NoNewline
            Write-Host "   NOTE: The CSV file must contain a column named exactly " -NoNewline -ForegroundColor Yellow
            Write-Host "MessageID" -ForegroundColor Black -BackgroundColor Yellow -NoNewline
            Write-Host "."
            Write-Host ""
            Write-Host "           > " -NoNewline
            Write-Host "New-SDSearchRequest" -ForegroundColor Yellow -NoNewline
                Write-Host " -TicketNumber" -ForegroundColor DarkGray -NoNewline
                    Write-Host " <TicketNumber>" -ForegroundColor White -NoNewline
                Write-Host " -Requester" -ForegroundColor DarkGray -NoNewline
                    Write-Host " your@email.here" -ForegroundColor White -NoNewline
                Write-Host " -CsvFilePath" -ForegroundColor DarkGray -NoNewline
                    Write-Host " `"C:\Folder\file.csv`"" -ForegroundColor White
            Write-Host ""

        Write-Host "   2. Check the discovery mailbox in Outlook to verify the search preview matches what you want to purge."
        Write-Host "       !!! WARNING !!!  Purge is a destructive operation that cannot be undone.  You will be held responsible for the results." -ForegroundColor Red
        Write-Host ""
        Write-Host "   3. Execute the search and destroy which will purge the matching messages and clean up the search environment."
            Write-Host ""
            Write-Host "           > " -NoNewline
            Write-Host "Execute-SDPurgeRequest" -ForegroundColor Yellow -NoNewline
                Write-Host " -TicketNumber" -ForegroundColor DarkGray -NoNewline
                    Write-Host " <TicketNumber>" -ForegroundColor White -NoNewline
                Write-Host " -CsvFilePath" -ForegroundColor DarkGray -NoNewline
                    Write-Host " `"C:\Folder\file.csv`"" -ForegroundColor White
            Write-Host ""

        Write-Host ""
        Write-Host "---------------------------------------------------------------------------------------------------------------------------------------------"
        Write-Host ""

    }
}

Function Write-JustifiedStatusOutput ([string]$Message, [switch]$Failed, [switch]$Pending, [switch]$LastLine) {
    $StatusBlock = "[      ]"
    $StatusBlockLength = 8
    
    $MyWidth = $(Get-Host).UI.RawUI.WindowSize.Width
    if($MyWidth -eq $null) { $MyWidth = 100 }

    $Cursor = $Host.UI.RawUI.CursorPosition

    if(($Message.Length + $StatusBlockLength + 1) -ge $MyWidth) {
        $Message = $Message.Substring(0, $MyWidth - 12) + "..."
    } # else {
    #    $Message = $Message.PadRight(($MyWidth - $Message.Length - $StatusBlockLength - 1), " ")
    #}

    if($Pending.IsPresent) {
        Write-Host "$StatusBlock" -NoNewline
        Write-Host "$Message" -NoNewline
    } elseif ($Failed.IsPresent) {
        Write-Host "[ " -NoNewline
        Write-Host "FAIL" -ForegroundColor Red -NoNewline
        Write-Host " ]" -NoNewline

        Write-Host "$Message"
    } else {
        Write-Host "[  " -NoNewline
        Write-Host "OK" -ForegroundColor Green -NoNewline
        Write-Host "  ]" -NoNewline

        Write-Host "$Message"
    }
}

<#
    .Synopsis
    Creates a new search and destroy workspace.

    .Description
    This will return a discovery mailbox used for future searches under an incident.

    .Parameter TicketNumber
    Accepts a string representing the FrostNow ticket number for the incident.

    .Example
    $Incident = New-SDWorkspace -TicketNumber INC0000000
#>
Function New-SDWorkspace {

    PARAM(
            [Parameter(Mandatory=$true)]
            [string]$TicketNumber
         )

    $TicketNumber = $TicketNumber.Replace(" ","")

    New-Mailbox `
        -Discovery `
        -Name "Discovery for Security Incident $TicketNumber" `
        -DisplayName "Discovery for Security Incident $TicketNumber" `
        -Alias "Discovery_SecInc_$($TicketNumber)"
}

<#
    .Synopsis
    Removes a workspace.

    .Description
    This will remove any permissions and discovery mailboxes associated with the workspace.

    .Parameter TicketNumber
    Accepts a string representing the FrostNow ticket number for the incident.

    .Parameter Silent
    Suppresses the confirmation prompt before deleting an incident.  This should only be used by automation.

    .Example
    Remove-SDWorkspace -TicketNumber INC0000000
#>
Function Remove-SDWorkspace {
    PARAM(
            [Parameter(Mandatory=$true)]
            [string]$TicketNumber,
        
            [switch]$Silent
        )

    $TicketNumber = $TicketNumber.Replace(" ","")

    $Mailbox = Get-Mailbox "Discovery_SecInc_$TicketNumber" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    if($Mailbox -ne $null) {
        if($Silent.IsPresent -ne $true) {
            $Verify = Read-Host "Discovery mailbox `"$($Mailbox.DisplayName)`" will be permanently deleted.  Are you sure?  Type YES to proceed"

            if($Verify.ToLower() -eq "yes") {
                $Mailbox |Remove-Mailbox -Confirm:$false
            } else {
                Write-Host "Cleanup canceled by user request."
                exit
            }
        } else {
            $Mailbox |Remove-Mailbox -Confirm:$false
        }
        
    } else {
        Write-Host "FATAL ERROR: Unable to clean up INC$($TicketNumber) because the mailbox does not exist."
        throw "FATAL ERROR: Mailbox not found exception."
    }
}


Function Get-SDWorkspace {
    PARAM(
        [string]$TicketNumber = "*"
    )

    $Mailbox = Get-Mailbox "Discovery_SecInc_$TicketNumber" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    if($Mailbox -ne $null) {
        $Mailbox
    } else {
        throw "No open security incident found matching ticket $TicketNumber."
    }
}

<#
    .Synopsis
    Identifies messages by their message ID.

    .Description
    Identifies messages by their message ID.

    .Parameter MessageID
    Accepts a string representing the MessageID to search logs for.

    .Example
    Find-MessageFromMessageId -MessageID "<1234567890@sender.com>"
#>
Function Find-MessageFromMessageId ([string]$MessageID) {
    Write-Host "Searching logs for $MessageID..."
    
    #Try to get an external source
    $Results = Get-TransportService |%{
        Get-MessageTrackingLog `
            -Server $($_.Name) `
            -MessageId $MessageId `
            -WarningAction SilentlyContinue `
            -EventId DELIVER
        }

    if($Results -eq $null) {
        #Try to get an internal source
        $InternalResults = Get-TransportService |%{ Get-MessageTrackingLog `
            -Server $($_.Name) `
            -MessageId $MessageID `
            -WarningAction SilentlyContinue `
            -Source STOREDRIVER `
            -EventId SUBMIT
        }

        if($InternalResults -ne $null) {
            $InternalResults
        } else {
            Write-Warning -Message "No results found for $MessageID."
        }
    } else {
        $Results
    }
}


<#
    .Synopsis
    Searches for a copy of a message.

    .Description
    Stores a copy of a message found using Find-MessageFromMessageId and optionally purges it from the source mailbox.

    .Parameter Message
    Accepts a message tracking log entry.

    .Parameter Delete
    Purges the messages that match the search.

    .Parameter Silent
    Suppresses the confirmation prompt before deleting matches.  This should only be used by automation.

    .Example
    $Workspace = New-SDWorkspace -TicketNumber INC0000000
    $Message = Find-MessageFromMessageId -MessageID "<1234567890@sender.com>"
    New-SDSearch -Message $Message -TicketNumber INC0000000 -Delete
#>
Function New-SDSearch {

    PARAM(
            $Message,

            [Parameter(Mandatory=$true)]
            $TicketNumber,

            [switch]$Fuzzy,
            [switch]$FuzzyOnly,
            [string]$FuzzySender,
            [string]$FuzzyRecipient,
            [string]$FuzzySubject,

            [switch]$Delete,
            [switch]$Silent,
            [switch]$Testing
        )

    $FunctionName = "New-SDSearch"

    $IncidentResponseMailbox = Get-SDWorkspace -TicketNumber $TicketNumber

    if($IncidentResponseMailbox -eq $null) {
        throw "No active workspace found matching ticket number $TicketNumber.  Did you create one using New-SDWorkspace?"
    }

    if($Fuzzy.IsPresent -and $Message -ne $null) {
        throw "A message cannot be supplied with a fuzzy search."
    }

    if($Fuzzy.IsPresent -and ($FuzzySender -eq $null -or $FuzzyRecipient -eq $null `
                                -or $FuzzySender -notlike "*@*" -or $FuzzyRecipient -notlike "*@*" `
                                -or $FuzzySubject -eq $null)) {
        Write-Host "Fuzzy searches require an email address for -FuzzySender and -FuzzyRecipient and a subject supplied with -FuzzySubject." -ForegroundColor Red
        throw "Invalid fuzzy search parameter set."
    }

    #Check for multiple messages matching ID
    if($Message.Count -eq $null) {
        #It's a single message so convert it to an array

        if($Testing.IsPresent) {
            Write-Host "[DEBUG] Single message result converted to array." -ForegroundColor Yellow
        }

        $MessageList = @($Message)
    } else {
        #It has multiple results so just map them
        if($Testing.IsPresent) {
            Write-Host "[DEBUG] Multi-message result mapped to array." -ForegroundColor Yellow
        }

        $MessageList = $Message
    }
 
    $MessageList |%{
        $Message = $_

            if($Fuzzy.IsPresent) {
                $Sender = $FuzzySender
                $Recipients = $FuzzyRecipient

                $Subject = $FuzzySubject
            } else {
            $Sender = $Message.Sender
            $Recipients = $Message.Recipients

            $Subject = $Message.MessageSubject
        }

        #Sanitize Subject
        $global:ForbiddenCharacters |%{
            $Subject = $Subject.Replace($_, "``$_")
        }

        #$Subject = $Subject.Replace(" ", " AND ")

        #$Received = $Message.Timestamp.ToString("MM/dd/yyyy")

        $SearchString = "From:$Sender AND Subject:`"$Subject`""
        $SearchQuery = [scriptblock]::Create($SearchString)

        if($Testing.IsPresent) {
            Write-Host "[DEBUG] Function:     $FunctionName" -ForegroundColor Yellow
            Write-Host ""

            Write-Host "[DEBUG] Message" -ForegroundColor Yellow
            Write-Host "[DEBUG]     Sender:          $($Message.Sender)" -ForegroundColor Yellow
            Write-Host "[DEBUG]     Recipients:      $($Message.Recipients)" -ForegroundColor Yellow
            Write-Host "[DEBUG]     Subject:         $($Message.MessageSubject)" -ForegroundColor Yellow
            Write-Host ""        

            Write-Host "[DEBUG] Sanitizer" -ForegroundColor Yellow
            Write-Host "[DEBUG]     Sender:       $Sender" -ForegroundColor Yellow
            Write-Host "[DEBUG]     Recipients:   $Recipients" -ForegroundColor Yellow
            Write-Host "[DEBUG]     Subject:      $Subject" -ForegroundColor Yellow
            Write-Host "[DEBUG]     SearchQuery:  $SearchQuery" -ForegroundColor Yellow
        }

        if($Delete.IsPresent) {
            if($Silent.IsPresent -ne $true) {
                Write-Host "Discovery has completed.  Please check $($IncidentResponseMailbox.DisplayName) to verify that the identified messages are correct."
                Write-Host "WARNING: MESSAGES WILL BE DELETED IF YOU PROCEED.  ONCE DELETED, THEY CANNOT BE RECOVERED.  DO NOT PROCEED UNTIL YOU HAVE VERIFIED THE RESULTS IN THE $($IncidentResponseMailbox.DisplayName) MAILBOX." -ForegroundColor White -BackgroundColor DarkRed
                $Verify = Read-Host -Prompt "Type DELETE to proceed or anything else to cancel"
        
                if($Verify.ToUpper() -ne "DELETE") {
                    Write-Host "Delete operation aborted at user request."
                    break
                }
            }

            $Recipients |%{
                $Recipient = $_
                Search-Mailbox `
                    $_ `
                    -SearchQuery $SearchQuery `
                    -DeleteContent `
                    -Force `
                    -SearchDumpster
            }
        } else {
            Write-Host "Performing discovery for $Recipient..."
            $Recipients |%{
                $Recipient = $_
                Search-Mailbox `
                    $_ `
                    -SearchQuery $SearchQuery `
                    -TargetMailbox $($IncidentResponseMailbox.Alias) `
                    -TargetFolder "Incident Response Results"
            }
        }
    }   
}


<#
    .Synopsis
    Searches for a copy of the messages with message IDs supplied by a CSV file.

    .Description
    Searches for a copy of the messages with message IDs supplied by a CSV file and optionally purges them from the source mailboxes.

    .Parameter CsvFilePath
    Accepts a fully qualified path to a CSV file.  The CSV file must contain a column named MessageID.  This column name is not case sensitive.

    .Parameter Delete
    Purges the messages that match the search.

    .Parameter Silent
    Suppresses the confirmation prompt before deleting matches.  This should only be used by automation.

    .Example
    New-SDSearchBatch -CsvFilePath "C:\Path\To\File.csv" -TicketNumber INC0000000 -Delete
#>
Function New-SDSearchBatch {

    PARAM(
        [Parameter(Mandatory=$true)]
        [string]$CsvFilePath,
        
        [Parameter(Mandatory=$true)]
        $TicketNumber,
        
        [switch]$Fuzzy,
        [switch]$FuzzyOnly,
        [switch]$Delete,
        [switch]$Silent,
	    [switch]$DebugOutput,
        [switch]$Testing
    )

    if($DebugOutput.IsPresent) {
        Write-DebugMessage -Message "Initializing search..."
    }

    $IncidentResponseMailbox = Get-SDWorkspace -TicketNumber $TicketNumber -Testing

    if($IncidentResponseMailbox -eq $null) {
        throw "A security incident cannot be found for ticket number $TicketNumber."
    } else {
        if($DebugOutput.IsPresent) {
            Write-DebugMessage -Message "Identified mailbox for $($IncidentResponseMailbox.Alias)"
        }
    }

    if((Test-Path -Path $CsvFilePath) -eq $false) {
        throw "$CsvFilePath could not be found or access was denied."
    }

    $SearchRequestDef = Import-Csv -Path $CsvFilePath

    if($SearchRequestDef.MessageId -eq $null) {
        throw "Unable to process CSV file.  No data found in column MessageId."
    } else {
        if($DebugOutput.IsPresent) {
            Write-DebugMessage -Message "CSV imported:"
            $SearchRequestDef |FT
        }
    }

    #If we're deleting, we need to verify the user owns the deletion results
    if($Delete.IsPresent) {
        if($Silent.IsPresent -ne $true) {
            Write-Host "Discovery has completed.  Please check $($IncidentResponseMailbox.DisplayName) to verify that the identified messages are correct."
            Write-Host "WARNING: MESSAGES WILL BE DELETED IF YOU PROCEED.  ONCE DELETED, THEY CANNOT BE RECOVERED.  DO NOT PROCEED UNTIL YOU HAVE VERIFIED THE RESULTS IN THE $($IncidentResponseMailbox.DisplayName) MAILBOX." -ForegroundColor White -BackgroundColor DarkRed
            $Verify = Read-Host -Prompt "Type DELETE to proceed or anything else to cancel"
        
            if($Verify.ToUpper() -ne "DELETE") {
                Write-Host "Delete operation aborted at user request."
                break
            }
        }
    }

    $SearchRequestDef |%{
        if($_.MessageID -eq $null -or $_.MessageID -notlike "*@*") {
            Write-Host "Skipping record due to invalid value in MessageID field."
        } else {
            $Message = Find-MessageFromMessageId -MessageID $($_.MessageId)

            if($Fuzzy.IsPresent -and $Message -eq $null) {
                Write-Host "Attempting fuzzy search since no match was found in logs."
                Write-Host "!!! WARNING !!! Fuzzy search does not have safety constraints.  Be very careful that your results do not target undesired data." -ForegroundColor White -BackgroundColor DarkRed

                #Deletes
                if($Delete.IsPresent) {
                    if($DebugOutput.IsPresent) {
                        New-SDSearch -Fuzzy `
                            -FuzzySender $_.Sender `
                            -FuzzyRecipient $_.Recipient `
                            -FuzzySubject $_.Subject `
                            -TicketNumber $TicketNumber `
                            -Delete `
                            -Testing `
                            -Silent
                    } else {
                        New-SDSearch -Fuzzy `
                            -FuzzySender $_.Sender `
                            -FuzzyRecipient $_.Recipient `
                            -FuzzySubject $_.Subject `
                            -TicketNumber $TicketNumber `
                            -Delete `
                            -Silent
                    }

                } else {
                    if($DebugOutput.IsPresent) {
                        New-SDSearch -Fuzzy `
                            -FuzzySender $_.Sender `
                            -FuzzyRecipient $_.Recipient `
                            -FuzzySubject $_.Subject `
                            -TicketNumber $TicketNumber `
                            -Testing `
                            -Silent
                    } else {
                        New-SDSearch -Fuzzy `
                            -FuzzySender $_.Sender `
                            -FuzzyRecipient $_.Recipient `
                            -FuzzySubject $_.Subject `
                            -TicketNumber $TicketNumber `
                            -Silent
                    }
                }
            } else {
                if($Message -ne $null) {
        
                    if($DebugOutput.IsPresent) {
                        New-SDSearch `
                            -Message $Message `
                            -TicketNumber $TicketNumber `
                            -Testing
                    } else {
                        New-SDSearch `
                            -Message $Message `
                            -TicketNumber $TicketNumber
                    }
                }
            }
        }
    }
}

Function New-SDSearchRequest ([Parameter(Mandatory=$true)][string]$TicketNumber, [Parameter(Mandatory=$true)][string]$Requester, [Parameter(Mandatory=$true)][string]$CsvFilePath, [switch]$Fuzzy, [string]$FuzzyOnly, [switch]$DebugOutput) {
    #Validate
    $RequesterMbx = Get-Mailbox $Requester -ErrorAction SilentlyContinue
    $CsvData = Import-Csv -Path $CsvFilePath -ErrorAction SilentlyContinue

    if($RequesterMbx -eq $null) {
        throw "The request cannot be completed because the recipient `"$Requester`" cannot be found."
    }

    if($CsvData -eq $null) {
        throw "The request cannot be completed because the CSV file, `"$CsvFilePath`" cannot be successfully loaded."
        break
    } else {
        if($CsvData.MessageID -eq $null) {
            throw "The request cannot be completed because the CSV does not include a column named MessageID."
            break
        }
    }

    #Prepare environment
    $Incident = New-SDWorkspace -TicketNumber $TicketNumber
    $Incident |Add-MailboxPermission -User $Requester -AccessRights FullAccess

    if($DebugOutput.IsPresent) {
        #Execute pre-search
        if($Fuzzy.IsPresent) {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -DebugOutput -Fuzzy
        } else {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -DebugOutput
        }
    } else {
        #Execute pre-search
        if($Fuzzy.IsPresent) {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -Fuzzy
        } else {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath
        }
    }
}

Function Execute-SDPurgeRequest ([Parameter(Mandatory=$true)][string]$TicketNumber, [Parameter(Mandatory=$true)][string]$CsvFilePath, [switch]$Fuzzy, [switch]$Silent, [switch]$PreserveWorkspace) {
    #Validate
    $CsvData = Import-Csv -Path $CsvFilePath -ErrorAction SilentlyContinue

    if($CsvData -eq $null) {
        throw "The request cannot be completed because the CSV file, `"$CsvFilePath`" cannot be successfully loaded."
        break
    } else {
        if($CsvData.MessageID -eq $null) {
            throw "The request cannot be completed because the CSV does not include a column named MessageID."
            break
        }
    }

    #Execute purge
    if($Silent.IsPresent) {
        if($Fuzzy.IsPresent) {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -Delete -Silent -Fuzzy
        } else {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -Delete -Silent
        }
    } else {
        if($Fuzzy.IsPresent) {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -Fuzzy -Delete
        } else {
            New-SDSearchBatch -TicketNumber $TicketNumber -CsvFilePath $CsvFilePath -Delete
        }
    }

    #Remote workspace
    if($PreserveWorkspace.IsPresent -eq $false) {
        Get-SDWorkspace -TicketNumber $TicketNumber |Remove-Mailbox -Confirm:$false -Force
    }
}

Function Write-DebugMessage {
    Param(
        [string]$Message = "This is a debug message."
    )

    Write-Host "[DEBUG]    $Message" -ForegroundColor Yellow -BackgroundColor Black

}

Function Get-SDModuleVersion {
    Write-Host $ProductVersion
}

Function Reload-SDModule {
    $Path = (Get-Module "EmailSearchAndDestroy").Path

    Remove-Module "EmailSearchAndDestroy" -Force
    #Import-Module $Path -Force -WarningAction SilentlyContinue

    [string]$Cmd = "Import-Module `"$Path`""
    [string]$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Cmd))
    $argList = "-ExecutionPolicy Bypass -NoExit -NoLogo -encodedCommand $encodedCommand"
    Start-Process powershell.exe -ArgumentList $argList
    
    exit
}

Function Get-SDWorkspaceStatus ([switch]$Email, [string[]]$EmailAddresses) {
    #Get the list of workspaces
    $Workspaces = Get-SDWorkspace

    #Store the report
    [System.Collections.Generic.List[psobject]]$WorkspaceReport = [System.Collections.Generic.List[psobject]]::new()

    $Workspaces |Sort-Object Alias |%{
        $Workspace = $_

        #Define the report entry
        [psobject]$Entry = [psobject]::new()
        
        #Ticket number
        $TicketNumber = $($_.Alias).Replace("Discovery_SecInc_INC_","").Replace("Discovery_SecInc_","")
        $Entry |Add-Member -NotePropertyName TicketNumber -NotePropertyValue $TicketNumber

        #Workspace Opened
        $Entry |Add-Member -NotePropertyName Opened -NotePropertyValue $Workspace.WhenCreated

        #Discovery Mailbox
        $Entry |Add-Member -NotePropertyName DiscoveryMailbox -NotePropertyValue $Workspace.DisplayName

        #Delegate
        $Delegates = $Workspace |Get-MailboxPermission |Where {$_.IsInherited -eq $false -and $_.User -ne "NT AUTHORITY\SELF"}

        if($Delegates -eq $null) {
            #Couldn't find an assigned delegate
            $Entry |Add-Member -NotePropertyName Delegate -NotePropertyValue "Undefined"
        } else {
            if($Delegates.Count -eq $null) {
                #Only a single delegate was found since we don't have an array to count
                $Delegate = Get-User $Delegates.User
                $Entry |Add-Member -NotePropertyName Delegate -NotePropertyValue "$($Delegate.DisplayName) [$($Delegate.SamAccountName)]"
            } else {
                #Multiple people have delegate rights; we can't say for sure which one was the original requester, so we'll report that there's multiple
                $Entry |Add-Member -NotePropertyName Delegate -NotePropertyValue "Ambiguous: $($Delegates.Count) records found"
            }
        }

        #Check if a search was already performed
        $ItemCount = ($Workspace |Get-MailboxFolderStatistics -ErrorAction SilentlyContinue |Where {$_.Name -eq "Top of Information Store"}).ItemsInFolderAndSubfolders

        if($ItemCount -eq $null -or $ItemCount -le 1) {
            $Entry |Add-Member -NotePropertyName Preview -NotePropertyValue $False
        } else {
            $Entry |Add-Member -NotePropertyName Preview -NotePropertyValue $True
        }

        $WorkspaceReport.Add($Entry)
    }

    $WorkspaceReport |FT
}

$global:ForbiddenCharacters = @("``", "[", "]", "(", ")", ":", "$", "@", "{", "}", "`"", "`'")
$ProductName = "Search and Destroy Module"
$ProductVersion = "1.2.5.0189"

#Set background
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"

Write-Host "$ProductName [$ProductVersion]" -ForegroundColor Black -BackgroundColor Gray
Init-SDWorkspace