namespace Fiewport

module PrettyPrinter =

    open Spectre.Console
    open SpectreCoff


    let private printFormatter (map: Map<string, string list>) : TreeNode list =
        let keys = [for key in map.Keys do yield key]
        keys |> List.map (fun key -> node ([MCD (Color.LightCyan3, [Decoration.Bold], key); NL] |> Many) [for value in map[key] do yield node ([MC (Color.White, value)] |> Many) []])


    ///
    /// Simple MailboxProcessor for handling printing. All console output from the library flows through here, so there
    /// is no locking. Users might stomp on this when doing their own printing in a script, but w/e.
    /// 
    let private printer (mbox: MailboxProcessor<LDAPSearchResult * AsyncReplyChannel<unit>>) =
        let mutable lastSearch = ""
        let rec ringRing () = async {
            let! msg, channel = mbox.Receive ()
            let data = msg.ldapData
            
            if msg.searchType.ToString () <> lastSearch then
                lastSearch <- msg.searchType.ToString ()
                MCD (Color.PaleGreen3, [Decoration.Underline], $"======= Search: {msg.searchType} =======") |> toConsole

            match List.isEmpty msg.ldapReferrals with 
            | true -> ()
            | false ->            
                let refNodes = msg.ldapReferrals |> List.map (fun r -> node ([MC (Color.Yellow1, r)] |> Many) [])
                tree (V "[!] Referrals encountered") refNodes |> fun t -> t.Expanded <- true; t |> toOutputPayload
                |> ignore

            match msg.ldapSearcherError with
            | None ->
                match data.Length = 0 with
                | true -> 
                    MC (Color.Red, "No Results. If unexpected, check your script") |> toConsole
                | false ->
                    data |> List.map(fun d -> let t = tree (V "\n[+] Result attributes") (printFormatter d) in t.Expanded <- true; t |> toOutputPayload)
                    |> Many
                    |> toConsole
            | Some err ->
                [ MC (Color.PaleGreen3, $"[-]Search config: {msg.searchConfig.ldapHost} == {msg.searchConfig.username} == {msg.searchConfig.ldapDN}"); NL
                  MC (Color.Red, $"[{err.context}] {err.message}") ]
                |> Many
                |> toConsole
            channel.Reply ()
            return! ringRing ()
        }
        
        ringRing ()


    ///
    /// Starts the MailboxProcessor 
    let private pPrinter = MailboxProcessor.Start printer


    ///
    /// <summary>
    /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the
    /// library, use this. Just stick it on the end of whatever pipeline you have.
    /// <code>
    /// [someConfig]
    /// |> Searcher.getComputers
    /// |> PrettyPrinter.print
    /// </code>
    /// </summary>
    /// 
    let print (results: LDAPSearchResult list) = // TODO Enable verbosity toggle to suppress ntsecuritydescriptor and usercertificate 
        results |> List.iter (fun r -> pPrinter.PostAndReply (fun reply -> r, reply) )


    ///
    /// <summary>
    /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the
    /// library, use this. This function is used with <c>Tee</c> to provide console output.
    /// </summary>
    /// 
    let teePrint (results: LDAPSearchResult list) =
        results |> List.iter (fun result -> pPrinter.PostAndReply (fun reply -> result, reply))


    ///
    /// <summary>
    /// Use this to place delimiter text in between your outputs. Useful between multiple `Tee`s to break up the
    /// results. 
    /// </summary>
    let teeDelimiter delimiter (results: LDAPSearchResult list) =
        MC (Color.Blue, delimiter) |> toConsole
        results
