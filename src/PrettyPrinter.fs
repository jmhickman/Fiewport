namespace Fiewport

[<AutoOpen>]
module PrettyPrinter =

    open Spectre.Console
    open SpectreCoff
    
    let printFormatter (map: Map<string, string list>) : TreeNode list =
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
                MCD (Color.PaleGreen3, [Decoration.Underline], $"=======Search: {msg.searchType}=======") |> toConsole
            
            match msg.ldapSearcherError with
            | None ->
                data |> List.map(fun d -> tree (V "\n[+] Result attributes") (printFormatter d) |> toOutputPayload)
                |> Many
                |> toConsole
            | Some err ->
                [ MC (Color.PaleGreen3, $"[-]Search config: {msg.searchConfig.ldapHost} == {msg.searchConfig.username} == {msg.searchConfig.ldapDN}"); NL
                  MC (Color.Red, err ) ]
                |> Many
                |> toConsole
            channel.Reply ()
            return! ringRing ()
        }
        
        ringRing ()
    
    
    ///
    /// Starts the MailboxProcessor 
    let private pPrinter = MailboxProcessor.Start printer
    
    
    type PrettyPrinter = class end
    
        with
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
        static member public print (results: LDAPSearchResult list) = // TODO Enable verbosity toggle to suppress ntsecuritydescriptor and usercertificate 
            match results with
            | [] -> MC (Color.Red, "No Results. If unexpected, check your script") |> toConsole
            | _ ->
                results |> List.iter (fun r -> pPrinter.PostAndReply (fun reply -> r, reply) )
        
        ///
        /// <summary>
        /// The PrettyPrinter does what it says on the tin. If you want structured, easy to digest output from the
        /// library, use this. This function is used with <c>Tee</c> to provide console output.
        /// </summary>
        /// 
        static member public teePrint (results: LDAPSearchResult list) =
            results |> List.iter (fun result -> pPrinter.PostAndReply (fun reply -> result, reply))
            
            
        ///
        /// <summary>
        /// Use this to place delimiter text in between your outputs. Useful between multiple `Tee`s to break up the
        /// results. 
        /// </summary>
        static member public teeDelimiter delimiter (results: LDAPSearchResult list) =
            MC (Color.Blue, delimiter) |> toConsole
            results
