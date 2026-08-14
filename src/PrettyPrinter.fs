namespace Fiewport

module PrettyPrinter =

    open Spectre.Console
    open SpectreCoff


    let private printFormatter (map: LDAPEntryData) : TreeNode list =
        let keys = [for key in map.Keys do yield key]
        keys |> List.map (fun key -> node ([MCD (Color.LightCyan3, [Decoration.Bold], key); NL] |> Many) [for value in map[key] do yield node ([MC (Color.White, value)] |> Many) []])

    
    ///
    /// Format the authentication method for display on the info line.
    let private formatAuthMethod (authMethod: Fauli.Domain.AuthenticationMethod) : string =
        match authMethod with
        | Fauli.Domain.AuthenticationMethod.Kerberos -> "Kerberos TGS"
        | Fauli.Domain.AuthenticationMethod.NetNTLMv2 -> "NTLM"
        | _ -> authMethod.ToString()


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

            match msg.ldapSearcherError with
            | None ->
                match msg.authenticationMethod with
                | Some authMethod ->
                    MC (Color.DarkCyan, $"[i] Auth: {formatAuthMethod authMethod} to {msg.searchConfig.ldapHostname}") |> toConsole
                | None -> ()
                match data.Length = 0 with
                | true -> 
                    MC (Color.Red, "No Results. If unexpected, check your script") |> toConsole
                | false ->
                    data |> List.map(fun d -> let t = tree (V "\n[+] Result attributes") (printFormatter d) in t.Expanded <- true; t |> toOutputPayload)
                    |> Many
                    |> toConsole
            | Some err ->
                [ MC (Color.PaleGreen3, $"""[-]Search config: {msg.searchConfig.ldapHostname}/{msg.searchConfig.ldapIP} == {msg.searchConfig.ldapDN}"""); NL
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
    let print results = // TODO Enable verbosity toggle to suppress ntsecuritydescriptor and usercertificate 
        results |> List.iter (fun r -> pPrinter.PostAndReply (fun reply -> r, reply) )


    ///
    /// <summary>
    /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the
    /// library, use this. This function is used with <c>Tee</c> to provide console output.
    /// </summary>
    /// 
    let teePrint results =
        results |> List.iter (fun result -> pPrinter.PostAndReply (fun reply -> result, reply))


    ///
    /// <summary>
    /// Use this to place delimiter text in between your outputs. Useful between multiple `Tee`s to break up the
    /// results. 
    /// </summary>
    let teeDelimiter delimiter (results: LDAPSearchResult list) =
        MC (Color.Blue, delimiter) |> toConsole
        results


    ///
    /// <summary>
    /// Prints a flat string list as a labeled tree with a delimiter header. Useful for displaying
    /// the output of <c>Mold.extractOccurances</c>.
    /// <code>
    /// [config]
    /// |> Searcher.getUsers
    /// |> Mold.extractOccurances "distinguishedname"
    /// |> PrettyPrinter.listPrinter "Distinguished Names"
    /// </code>
    /// </summary>
    /// 
    let listPrinter label inputList =
        MCD (Color.PaleGreen3, [Decoration.Underline], $"======= {label} =======") |> toConsole
        let nodes = inputList |> List.map (fun s -> node ([MC (Color.White, s)] |> Many) [])
        tree (V $"[{inputList.Length}] {label}") nodes |> fun t -> t.Expanded <- true; t |> toOutputPayload
        |> toConsole
