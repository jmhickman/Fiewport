namespace Fiewport

open System
open LDAPConstants
open ADUtils
open Spectre.Console
open SpectreCoff

[<AutoOpen>]
module PrettyPrinter = ()
    //
    //
    // ///
    // /// MS uses int64s to store these 'tick' values, instead of using unix timestamps like everyone else.
    // /// Handles the max-value case and otherwise returns a date stamp.
    // /// 
    // let private returnTicksAfterEpoch ticks =
    //     match ticks with
    //     | Int64.MaxValue -> "no expiry"
    //     | _ -> 
    //         DateTime (1601, 1, 1, 0, 0, 0, DateTimeKind.Utc) // TODO: Consider statically storing this value?
    //         |> fun epoch -> epoch.AddTicks ticks
    //         |> fun date -> date.ToShortDateString ()
    //         
    // let private returnTimespan ticks =
    //     match ticks with // TODO: Do we need to check the MaxValue case? I don't remember
    //     | Int64.MinValue -> "no expiry"
    //     | _ -> TimeSpan.FromTicks (abs ticks) |> fun time -> time.TotalHours.ToString ()
    //
    //
    // ///
    // /// Special treatment for int64 values that encode ticks.
    // let private handleInt64s key (value: int64) =
    //     match key with
    //     | "accountexpires" | "badpasswordtime" | "creationtime"
    //     | "lastlogoff" | "lastlogon" | "pwdlastset"
    //     | "lastlogontimestamp" ->
    //         node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ returnTicksAfterEpoch value}")] |> Many) []
    //     | "forcelogoff" | "lockoutduration" | "lockoutobservationwindow"
    //     | "maxpwdage" | "minpwdage"  ->
    //         node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ returnTimespan value} hrs")] |> Many) []
    //     | _ -> node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
    //
    //
    // ///
    // /// Special treatment for int values that encode enums, usually. 
    // let private handleInts key (value: int) =
    //     match key with
    //     | "admincount" ->
    //         node ([MC (Color.Red, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
    //     | "grouptype" ->
    //         groupTypeList // in LDAPConstants
    //         |> List.filter (fun enum -> (value &&& int enum) = int enum)
    //         |> List.map (fun enum -> enum.ToString())
    //         |> fun enum -> node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in enum do yield node (MC (Color.White, $"{item}")) []]
    //     | "systemflags" ->
    //         systemFlagsList
    //         |> List.filter (fun enum -> (value &&& int enum) = int enum)
    //         |> List.map (fun enum -> enum.ToString())
    //         |> fun enum -> node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in enum do yield node (MC (Color.White, $"{item}")) []]
    //     | "useraccountcontrol" ->
    //         node ([MC (Color.Blue, $"{key}:")] |> Many)
    //             [for item in (ADData.readUserAccountControl value) do
    //                  yield if item = "DONT_REQ_PREAUTH" then node (MC (Color.Red, $"{item}")) [] else node (MC (Color.White, $"{item}")) []]
    //     | "samaccounttype" ->
    //         sAMAccountTypesList
    //         |> List.filter (fun enum -> (value &&& int enum) = int enum)
    //         |> List.map (fun enum -> enum.ToString())
    //         |> fun enum -> node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in enum do yield node (MC (Color.White, $"{item}")) []] // TODO: How is this different from the systemflags case?
    //     | "msds-supportedencryptiontypes" ->
    //         node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ADData.readmsDSSupportedEncryptionTypes value}")] |> Many) []
    //     | _ -> node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value}")] |> Many) []
    //     
    //
    // ///
    // /// Special treatment for byte values that need it for additional display clarity.
    // let private handleBytes key (value: byte array) = // TODO Enable verbosity toggle to suppress ntsecuritydescriptor and usercertificate
    //     match key with
    //     | "objectsid" ->
    //         node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{ADData.readSID value}") ] |> Many) []
    //     | "ntsecuritydescriptor" ->
    //         let descriptor = ADData.readSecurityDescriptor value
    //         node ([MC (Color.Blue, $"{key}")] |> Many)
    //             [ node
    //                 ( [ MC (Color.White, $"owner: {matchKnownSids descriptor.owner}, group: {matchKnownSids descriptor.group}")
    //                     NL
    //                     MC (Color.White, "DACLs (Groups with rights on this object, and what rights)") ] |> Many)
    //                     [for item in descriptor.dacl do yield node (MC (Color.White, $"{item}")) []] ]
    //     | "usercertificate" ->
    //         let issue, sub, pubkey = ADData.readX509Cert value
    //         node ([MC (Color.Blue, $"{key}:")] |> Many)
    //             [ node
    //                  ( [ MC (Color.White, $"Issuer: {issue}"); NL
    //                      MC (Color.White, $"Subject: {sub}"); NL
    //                      MC (Color.White, $"PublicKey: {pubkey}") ] |> Many) [] ]
    //     | "objectguid" ->
    //         node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{value |> Guid}") ] |> Many) []
    //     | _ ->
    //         node ([MC (Color.Grey, $"{key}:")
    //                MC (Color.White, $"{value |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}") ] |> Many) []
    //
    //
    // ///
    // /// Special treatment for string values that need it for additional display clarity.
    // let private handleStrings key (value: string list) =
    //     match key with
    //     | "wellknownobjects" | "otherwellknownobjects" ->
    //         node ([MC (Color.Blue, $"{key}:")] |> Many)
    //             [ for item in value do //each of these just needs some values trimmed off and some type coercion 
    //                   let splits = item.Split ':'
    //                   let guid = Guid.Parse(splits[2])
    //                   let dn = splits[3]
    //                   yield node ([MC (Color.White, $"{guid} -> {dn}")] |> Many) [] ]
    //     | _ ->
    //         node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in value do yield node ([MC (Color.White, $"{item}")] |> Many) []]
    //
    // ///
    // /// Does the heavy lifting of creating the formatting for all the datatypes that Fiewport encounters.
    // let private printFormatter key (datum: ADDataTypes) =
    //     match datum with
    //     
    //     | ADString x ->
    //          if x.StartsWith "***HIT COLLECTION " then node ([MC (Color.Red, x)] |> Many ) [] 
    //          else node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{x}")] |> Many) []        
    //     | ADBytes x ->
    //         handleBytes key x
    //     
    //
    //
    // ///
    // /// Simple MailboxProcessor for handling printing. All console output from the library flows through here, so there
    // /// is no locking. Users might stomp on this when doing their own printing in a script, but w/e.
    // /// 
    // let private printer (mbox: MailboxProcessor<LDAPSearchResult * AsyncReplyChannel<unit>>) =
    //     let mutable lastSearch = ""
    //     let rec ringRing () = async {
    //         let! msg, channel = mbox.Receive ()
    //         let data = [for key in msg.lDAPData.Keys do yield key, msg.lDAPData[key]]
    //         
    //         if msg.searchType.ToString () <> lastSearch then
    //             lastSearch <- msg.searchType.ToString ()
    //             [MCD (Color.Wheat1, [Decoration.Underline], $"=======Search: {msg.searchType}======="); NL] |> Many |> toConsole
    //         
    //         match msg.lDAPSearcherError with
    //         | None ->
    //             [if msg.searchConfig.filter <> "" then MC (Color.Wheat1, $"[*] Your search filter: {msg.searchConfig.filter}"); NL
    //              tree (V "[+] Result attributes") (data |> List.map (fun (key, datum) -> printFormatter key datum)) |> toOutputPayload]
    //             |> Many
    //             |> toConsole
    //         | Some err ->
    //             [ MC (Color.Wheat1, $"**Search config: {msg.searchConfig.ldapDomain}; {msg.searchConfig.username}; {msg.searchConfig.filter}"); NL
    //               MC (Color.Red, err ) ]
    //             |> Many
    //             |> toConsole
    //         channel.Reply ()
    //         do! ringRing ()
    //     }
    //     
    //     ringRing ()
    //
    //
    // ///
    // /// Starts the MailboxProcessor 
    // let private pPrinter = MailboxProcessor.Start printer
    //
    //
    // type PrettyPrinter = class end
    //
    //     with
    //     ///
    //     /// <summary>
    //     /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the library,
    //     /// use this. Just stick it on the end of whatever pipeline you have.
    //     /// <code>
    //     /// [someConfig]
    //     /// |> Searcher.getComputers
    //     /// |> PrettyPrinter.print
    //     /// </code>
    //     /// </summary>
    //     /// 
    //     static member public print (res: LDAPSearchResult list) = // TODO Enable verbosity toggle to suppress ntsecuritydescriptor and usercertificate 
    //         match res with
    //         | [] -> MC (Color.Red, "No Results. If unexpected, check your script") |> toConsole
    //         | _ ->
    //             res |> List.iter (fun r -> pPrinter.PostAndReply (fun reply -> r, reply) )
    //             MC (Color.Green1, $"[*] Printed {res.Length} results") |> toConsole
    //     
    //     ///
    //     /// <summary>
    //     /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the library,
    //     /// use this. This function is used with <c>Tee</c> to provide console output.
    //     /// </summary>
    //     /// 
    //     static member public action (res: LDAPSearchResult) = // TODO: 'action' is probably not a very good verb here
    //         pPrinter.PostAndReply (fun reply -> res, reply)
