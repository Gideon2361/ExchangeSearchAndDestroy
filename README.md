# ExchangeSearchAndDestroy
Search and Destroy functionality for emails in Microsoft Exchange 2019

# Setup Before Use
If your account does not have sufficient rights in Active Directory to read the Exchange configuration objects, you can manually enter your Exchange servers in this variable.

> $global:ExchangeServers = @(\
>             "server1.domain.local",\
>            "server2.domain.local",\
>            "server3.domain.local"\
>        )

Set your email server to use for email reports with the following global variable.
> $global:SmtpServer = $null
        
Set the email address to send emails from here.
> $global:MailFrom = \"from@email.com\"

Enable or disable Exchange server autodiscovery from Active Directory with the below variable.  $true enables it, $false disables it.
> $global:UseAutoDiscovery = $true

Enable or disable the use of inherited credentials.  If this is set to $true, the module will use the credentials provided by the Windows session rather than prompting for credentials.  This is useful for automation tasks that can't supply credentials, or in environments where the user account used to log into Windows has rights to manage Exchange.
> $global:InheritCredentials = $false

# Usage Instructions
To manually import into PowerShell, you must first set your Execution Policy to bypass.  The below command will do so temporarily only for the PowerShell session you're running in without affecting the overall security posture of your machine.
  > Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

The following can be used as a shortcut or in Windows Terminal to import the module for you automatically:
  > C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NoExit -Command "& {Import-Module C:\PathTo\EmailSearchAndDestroy.psm1}"

# Performing a Standard Search & Destroy
> <b>CSV File Sample Format</b>\
> \
> MessageID\
> \<message1@domain.com\>\
> \<message2@domain.com\>\
> \<message3@domain.com\>\
> ...

To perform a standard search using the Exchange message tracking logs to sanitize, you must have a CSV file which contains a column named MessageID (no spaces).  All columns other than MessageID are ignored by a standard search.  With the prepared CSV, perform the following steps:
   1. Create the workspace and perform the preview search.   NOTE: The CSV file must contain a column named exactly MessageID.

           > New-SDSearchRequest -TicketNumber <TicketNumber> -Requester your@email.here -CsvFilePath "C:\Folder\file.csv"

   2. Check the discovery mailbox in Outlook to verify the search preview matches what you want to purge.
       !!! WARNING !!!  Purge is a destructive operation that cannot be undone.  You will be held responsible for the results.

   3. Execute the search and destroy which will purge the matching messages and clean up the search environment.

           > Execute-SDPurgeRequest -TicketNumber <TicketNumber> -CsvFilePath "C:\Folder\file.csv"

# Performing a Fuzzy Search
> <b>CSV File Sample Format</b>\
>\
> MessageID,Sender,Recipient,Subject\
> \<message1@domain.com\>,sender@badactor.com,recipient1@mydomain.com,Arabian prince looking for heir\
> \<message2@domain.com\>,sender@porn.com,recipient2@mydomain.com,Pu$$y p1cs f0r y0u\
> \<message3@domain.com\>,sender@virus.com,recipient3@mydomain.com,I love you\
> ...

Sometimes the message tracking logs don't contain the emails you're looking for anymore, such as if the logs have rotated or been cleared manually.  In this situation, you can use the fuzzy search option to directly specify search and destroy criteria from your CSV file.  The CSV file must contain a MessageID, a Sender, a Recipient, and a Subject column and those columns must be named exactly as written.  No column may contain multiple values.  For example, if a message went to 3 recipients, you must list each recipient in a separate row.

   1. Create the workspace and perform the preview search.

           > New-SDSearchRequest -TicketNumber <TicketNumber> -Requester your@email.here -CsvFilePath "C:\Folder\file.csv" -Fuzzy

   2. Check the discovery mailbox in Outlook to verify the search preview matches what you want to purge.
       <span style="color: rgb(75,0,0)">!!! WARNING !!!  Purge is a destructive operation that cannot be undone.</span>

   3. Execute the search and destroy which will purge the matching messages and clean up the search environment.

           > Execute-SDPurgeRequest -TicketNumber <TicketNumber> -CsvFilePath "C:\Folder\file.csv" -Fuzzy

# Performing a Manual Fuzzy Search
If you need to purge a specific email and don't wish to supply a CSV input, you can perform a fuzzy search using the following commands.

   1. Create the workspace.

           > $NewWorkspace = New-SDWorkspace -TicketNumber <TicketNumber>

   2. Assign permissions to the workspace so you can review the results.

           > $NewWorkspace |Add-MailboxPermission -User <your@email.com> -AccessRights FullAccess

   3. Perform the preview search.  NOTE: If the subject contains any apostraphes ('), you must escape them (`'), otherwise they will cause unreliable behavior.

           > New-SDSearch -TicketNumber <TicketNumber> -Fuzzy -FuzzySender <sender@domain.com> -FuzzyRecipient <recipient@domain.com> -FuzzySubject '<Subject>'

   4. After you review the results, perform the purge with the following command.

           > New-SDSearch -TicketNumber <TicketNumber> -Fuzzy -FuzzySender <sender@domain.com> -FuzzyRecipient <recipient@domain.com> -FuzzySubject '<Subject>' -Delete
  
   5. Remove the workspace.
  
           > Remove-SDWorkspace -TicketNumber <TicketNumber>
