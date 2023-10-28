namespace Fiewport


open System
open Fiewport.LDAPConstants
open Fiewport.ADData
open Spectre.Console
open SpectreCoff

[<AutoOpen>]
module PrettyPrinter =


    ///
    /// MS uses int64s to store these 'tick' values, instead of using unix timestamps like everyone else.
    /// Handles the max-value case and otherwise returns a date stamp.
    /// 
    let private returnTicksAfterEpoch ticks =
        match ticks with
        | Int64.MaxValue -> "no expiry"
        | _ -> 
            DateTime (1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            |> fun epoch ->
                epoch.AddTicks ticks
                |> fun date -> date.ToShortDateString ()
            
    let private returnTimespan ticks =        
        match ticks with
        | Int64.MinValue -> "No limit"
        | _ -> TimeSpan.FromTicks (abs ticks) |> fun time -> time.TotalHours.ToString ()


    ///
    /// Special treatment for int64 values that encode represent ticks.
    let private handleInt64s key (value: int64) =
        match key with
        | "accountExpires" | "badPasswordTime" | "creationTime"
        | "lastLogoff" | "lastLogon" | "pwdLastSet"
        | "lastLogonTimestamp" ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ returnTicksAfterEpoch value}")] |> Many) []
        | "forceLogoff" | "lockoutDuration" | "lockOutObservationWindow"
        | "maxPwdAge" | "minPwdAge"  ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ returnTimespan value} hrs")] |> Many) []
        | _ -> node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
    
    
    ///
    /// Special treatment for int values that encode enums, usually. 
    let private handleInts key (value: int) =        
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
    /// Special treatment for byte values that need it for additional display clarity.
    let private handleBytes key (value: byte array) =
        match key with
        | "objectSid" ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ADData.readSID value}") ] |> Many) []
        | "nTSecurityDescriptor" ->
            let descriptor = ADData.readSecurityDescriptor value
            node ([MC (Color.Blue, $"{key}:")] |> Many)
                [ node
                    ( [ MC (Color.White, $"owner: {matchKnownSids descriptor.owner}");NL
                        MC (Color.White, $"group: {matchKnownSids descriptor.group}");NL
                        MC (Color.White, "DACLs (CommonACE)") ] |> Many)
                        [for item in descriptor.dacl do yield node (MC (Color.White, $"{item}")) []] ]
        | "userCertificate" ->
            let issue, sub, pubkey = ADData.readX509Cert value
            node
                ([MC (Color.Blue, $"{key}:")] |> Many)
                [ node
                     ( [ MC (Color.White, $"Issuer: {issue}"); NL
                         MC (Color.White, $"Subject: {sub}"); NL
                         MC (Color.White, $"PublicKey: {pubkey}") ] |> Many)
                         [] ]
        | "objectGUID" ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value |> Guid}") ] |> Many) []
        | _ ->
            node ([MC (Color.Grey, $"{key}:"); MC (Color.White, $"{value |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}") ] |> Many) []
    
    
    ///
    /// Special treatment for string values that need it for additional display clarity.
    let private handleStrings key (value: string list) =
        match key with
        | "wellKnownObjects" |"otherWellKnownObjects" ->
            node ([MC (Color.Blue, $"{key}:")] |> Many)
                [ for item in value do //each of these just needs some values trimmed off and some type coercion 
                      let splits = item.Split ':'
                      let guid = Guid.Parse(splits[2])
                      let dn = splits[3]
                      yield node ([MC (Color.White, $"{guid} -> {dn}")] |> Many) [] ]
        | _ ->
            node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in value do yield node ([MC (Color.White, $"{item}")] |> Many) []]
    
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
            node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in x do yield handleBytes key item]
        | ADDateTimeList x ->
            node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in x do yield node (MC (Color.White, $"{item.ToShortDateString ()}")) []]  
    
    ///
    /// Simple MailboxProcessor for handling printing. All console output from the library flows through here, so there
    /// is no locking. Users might stomp on this when doing their own printing in a script, but w/e.
    /// 
    let private printer (mbox: MailboxProcessor<LDAPSearchResult * AsyncReplyChannel<unit>>) =
        
        let rec ringRing () = async {
            let! msg, channel = mbox.Receive ()
            let keys = [for key in msg.lDAPData.Keys do yield key]
            let _data = keys |> List.map (fun key -> key, msg.lDAPData[key])
                        
            match msg.lDAPSearcherError with
            | None ->
                [ MCD (Color.Blue, [Decoration.Underline], $"===Search: {msg.searchType}======"); NL
                  if msg.searchConfig.filter <> "" then MC (Color.Wheat1, $"[*] Your search filter: {msg.searchConfig.filter}"); NL
                  tree (V "attributes") (_data |> List.map (fun (key, datum) -> printFormatter key datum)) ]
                |> Many
                |> toConsole
            | Some err ->
                [ MC (Color.Wheat1, $"**Search config: {msg.searchConfig.ldapDomain}; {msg.searchConfig.username}; {msg.searchConfig.filter}"); NL
                  MC (Color.Red, err ) ]
                |> Many
                |> toConsole
            channel.Reply ()
            do! ringRing ()
        }
        
        ringRing ()
    
    
    ///
    /// Starts the MailboxProcessor 
    let private pPrinter = MailboxProcessor.Start printer
    

    type PrettyPrinter = class end

        with
        ///
        /// <summary>
        /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the library,
        /// use this. Just stick it on the end of whatever pipeline you have.
        /// <code>
        /// [someConfig]
        /// |> Searcher.getComputers
        /// |> PrettyPrinter.print
        /// </code>
        /// </summary>
        /// 
        static member public print (res: LDAPSearchResult list) =
            match res.Length with
            | x when x > 0 -> res |> List.iter (fun r -> pPrinter.PostAndReply (fun reply -> r, reply) )
            | _ -> MC (Color.Red, "No Results. If unexpected, check your script") |> toConsole
        
        ///
        /// <summary>
        /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the library,
        /// use this. This function is used with <c>Tee</c> to provide console output.
        /// </summary>
        /// 
        static member public action (res: LDAPSearchResult) =
            pPrinter.PostAndReply (fun reply -> res, reply)
