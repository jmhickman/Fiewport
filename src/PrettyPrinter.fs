namespace Fiewport


open System
open Fiewport.LDAPConstants
open Fiewport.ADData
open Spectre.Console
open SpectreCoff

[<AutoOpen>]
module PrettyPrinter =
    
    let private panelFormat =
        { defaultPanelLayout with
            Sizing = SizingBehaviour.Expand
            BorderColor = Some Color.White
            Padding = Padding.AllEqual 0 }

    ///
    /// MS uses int64s to store these 'tick' values, instead of using unix timestamps like everyone else.
    /// Handles the max-value case and otherwise returns a date stamp.
    /// 
    let returnTicksAfterEpoch ticks =
        match ticks with
        | Int64.MaxValue -> "no expiry"
        | _ -> 
            DateTime (1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            |> fun epoch ->
                epoch.AddTicks ticks
                |> fun date -> date.ToShortDateString ()
            
    let returnTimespan ticks =        
        match ticks with
        | Int64.MinValue -> "No limit"
        | _ -> TimeSpan.FromTicks (abs ticks) |> fun time -> time.TotalHours.ToString ()


    ///
    /// Some int64 values encode data, usually a timestamp of some sort. This function handles those cases, and passes
    /// through the ones that don't. This won't handle every case, because I'm not manually trawling through 1500
    /// LDAP attributes to find all the ticks and weird values. I'll add handlers as cases come up.
    /// 
    let handleInt64s key (value: int64) =
        match key with
        | "accountExpires" | "badPasswordTime" | "creationTime"
        | "lastLogoff" | "lastLogon" | "pwdLastSet"
        | "lastLogonTimestamp" ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ returnTicksAfterEpoch value}")] |> Many) []
        | "forceLogoff" | "lockoutDuration" | "lockOutObservationWindow" | "maxPwdAge"
        | "minPwdAge"  ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ returnTimespan value} hrs")] |> Many) []
        | _ -> node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
    
    
    ///
    /// Some int values encode data, usually a enum/bitfield some sort. This function handles those cases, and passes
    /// through the ones that don't. This won't handle every case, because I'm not manually trawling through 1500
    /// LDAP attributes to find all the everything. I'll add handlers as cases come up.
    /// 
    let handleInts key (value: int) =        
        match key with
        | "adminCount" ->
            node ([MC (Color.Red, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
        | "groupType" ->
            groupTypeList // in LDAPConstants
            |> List.filter (fun enum -> (value &&& int enum) = int enum)
            |> List.map (fun enum -> enum.ToString())
            |> fun enum -> node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in enum do yield node (MC (Color.White, $"{item}")) []]
        | "systemFlags" ->
            systemFlagsList
            |> List.filter (fun enum -> (value &&& int enum) = int enum)
            |> List.map (fun enum -> enum.ToString())
            |> fun enum -> node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in enum do yield node (MC (Color.White, $"{item}")) []]
        | "userAccountControl" ->
            node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in (ADData.readUserAccountControl value) do yield node (MC (Color.White, $"{item}")) []]
        | "sAMAccountType" ->
            sAMAccountTypesList
            |> List.filter (fun enum -> (value &&& int enum) = int enum)
            |> List.map (fun enum -> enum.ToString())
            |> fun enum -> node ([MC (Color.Blue, $"{key}: ")] |> Many) [for item in enum do yield node (MC (Color.White, $"{item}")) []]
        | "msDS-SupportedEncryptionTypes" ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ADData.readmsDSSupportedEncryptionTypes value}")] |> Many) []
        | _ -> node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
        
    
    ///
    /// Bytes values appear in the LDAP results as pure encodings of various pieces of data. This function handles these
    /// cases.
    /// 
    let handleBytes key (value: byte array) =
        match key with
        | "objectSid" ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ADData.readSID value}") ] |> Many) []
        | "nTSecurityDescriptor" ->
            let descriptor = ADData.readSecurityDescriptor value
            node ([MC (Color.Blue, $"{key}:")] |> Many)
                [node
                    ( [ MC (Color.White, $"owner: {matchKnownSids descriptor.owner}");NL
                        MC (Color.White, $"group: {matchKnownSids descriptor.group}");NL
                        MC (Color.White, "DACLs") ] |> Many)
                        [for item in descriptor.dacl do yield node (MC (Color.White, $"{item}")) [] ] ]
        | "userCertificate" ->
            let issue, sub, pubkey = ADData.readX509Cert value
            node
                ([MC (Color.Blue, $"{key}:")] |> Many)
                [node
                     ( [ MC (Color.White, $"Issuer: {issue}"); NL
                         MC (Color.White, $"Subject: {sub}"); NL
                         MC (Color.White, $"PublicKey: {pubkey}") ] |> Many)
                         [] ]
        | _ ->
            node ([MC (Color.Grey, $"{key}:"); MC (Color.White, $"{value |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}") ] |> Many) []
    
    
    let handleStrings key (value: string list) =
        match key with
        | "wellKnownObjects" |"otherWellKnownObjects" ->
            node ([MC (Color.Blue, $"{key}(strings):")] |> Many)
                [ for item in value do
                      let splits = item.Split ':'
                      let guid = Guid.Parse(splits[2])
                      let dn = splits[3]
                      yield node ([MC (Color.White, $"{guid} -> {dn}")] |> Many) [] ]
        | _ ->
            node ([MC (Color.Blue, $"{key}(strings):")] |> Many) [ for item in value do yield node ([MC (Color.White, $"{item}")] |> Many) [] ]
    
    ///
    /// Does the heavy lifting of creating the formatting for all of the datatypes that Fiewport encounters.
    let private printFormatter key (datum: ADDataTypes) =
        match datum with
        | ADBool x ->
             node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{x}")] |> Many) []
        | ADString x ->
             if x.StartsWith "***HIT COLLECTION " then node ([MC (Color.Red, x)] |> Many ) [] 
             else node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{x}")] |> Many) []
        | ADInt x ->
            handleInts key x
        | ADInt64 x ->
            handleInt64s key x
        | ADBytes x ->
            handleBytes key x
        | ADDateTime x ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{x.ToShortDateString ()}")] |> Many) []
        | ADStringList x ->
            handleStrings key x
        | ADBytesList x ->
            node ([MC (Color.Blue, $"{key}:")] |> Many) [ for item in x do yield handleBytes key item ]
        | ADDateTimeList x ->
            node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in x do yield node (MC (Color.White, $"{item.ToShortDateString ()}")) []]  
    
    ///
    /// Simple MailboxProcessor for handling printing. All console output from the library flows through here, so there
    /// is no locking. Users might stomp on this when doing their own printing in a script, but w/e.
    /// 
    let private printer (mbox: MailboxProcessor<LDAPSearchResult>) =
        
        let rec ringRing () = async {
            let! msg = mbox.Receive ()
            let keys = [for key in msg.lDAPData.Keys do yield key]
            let _data = keys |> List.map (fun key -> key, msg.lDAPData[key])
            
            let domainComponent =
                msg.objectCategory.Split ',' |> Array.filter (fun p -> p.StartsWith("DC=")) |> String.concat ","
            let containers =
                msg.objectCategory.Split ',' |> Array.filter (fun p -> p.StartsWith("CN=")) |> String.concat ","
            
            [ MC (Color.Gold1, $"Object Category: {containers}"); NL
              MC (Color.Grey, $"Domain Components: {domainComponent}"); NL
              MC (Color.Gold1, $"""Object Classes: {msg.objectClass |> String.concat ", "}"""); NL
              MC (Color.Gold1, $"objectGUID: {msg.objectGUID}"); NL
              tree (V "attributes") (_data |> List.map (fun (key, datum) -> printFormatter key datum)) ]
            |> Many
            |> toConsole
            
            do! ringRing ()
        }

        ringRing ()
    
    
    ///
    /// Starts the MailboxProcessor 
    let private pPrinter =
        // Stupid bodge to deal with nonsense. Spectre will not emit any markup text 
        // from inside the MailboxProcessor without first printing it _outside_ the mailbox.
        // It doesn't make any sense. So I print a black line. 🙄🙄
        Many [MC (Color.Black, "")] |> toConsole       
        MailboxProcessor.Start printer
        
    
    ///
    /// <summary>
    /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the library,
    /// use this. Just stick it on the end of whatever pipeline you have.
    /// <code>
    /// let config = { properties = [||]
    ///                filter = "objectCategory=*"
    ///                scope = SearchScope.Subtree
    ///                ldapDomain = "LDAP://somedomain.local"
    ///                username = "username"
    ///                password = "password" }
    /// [config]
    /// |> Searcher.getDomainObjects
    /// |> Filter.attributePresent "msDS-SupportedEncryptionTypes"
    /// |> PrettyPrinter.prettyPrint
    /// </code>
    /// </summary>
    /// 
    let public prettyPrint (res: LDAPSearchResult list) =
        res |> List.iter (fun r ->
            pPrinter.Post r
            // I have to sleep here because otherwise the main thread risks exiting before the printer prints.
            // I tried forcing synchronous execution, but that didn't seem to do anything at all about the issue.
            System.Threading.Thread.Sleep 40) 
        