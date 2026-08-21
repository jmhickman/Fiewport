namespace Fiewport

module PrettyPrinter =

    open System
    open Spectre.Console
    open SpectreCoff


    ///
    /// Format a single attribute value node. Values under ntsecuritydescriptor use
    /// Principal--Flags layout: principal is bright + bold, flags stay plain.
    ///
    let private formatAttributeValue (attrKey: string) (value: string) =
        match attrKey.Equals("ntsecuritydescriptor", StringComparison.OrdinalIgnoreCase) with
        | false ->
            node ([ MC (Color.White, value) ] |> Many) []
        | true ->
            match value.Split([| "--" |], 2, StringSplitOptions.None) with
            | [| principal; flags |] ->
                node
                    ([ MCD (Color.Yellow, [ Decoration.Bold ], principal)
                       MC (Color.White, $"--{flags}") ]
                     |> Many)
                    []
            | _ ->
                node ([ MC (Color.White, value) ] |> Many) []


    let private printFormatter (map: LDAPEntryData) : TreeNode list =
        map.Keys
        |> Seq.map (fun key ->
            let valueNodes =
                map[key]
                |> List.map (formatAttributeValue key)
            node ([ MCD (Color.LightCyan3, [ Decoration.Bold ], key); NL ] |> Many) valueNodes)
        |> List.ofSeq


    ///
    /// Tree root label; when member is present, include Count under Result attributes.
    ///
    let private resultAttributesLabel (map: LDAPEntryData) =
        match map.TryFind "member" with
        | Some members -> V $"\n[+] Result attributes\nCount: {members.Length}"
        | None -> V "\n[+] Result attributes"


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
                    data
                    |> List.map (fun d ->
                        let t = tree (resultAttributesLabel d) (printFormatter d)
                        t.Expanded <- true
                        t |> toOutputPayload)
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


    ///
    /// Emit a short line of help text.
    ///
    let private helpLine text =
        MC (Color.White, text) |> toConsole


    ///
    /// Emit a section header for help output.
    ///
    let private helpHeader text =
        MCD (Color.PaleGreen3, [ Decoration.Underline ], text) |> toConsole


    ///
    /// <summary>
    /// Prints a quick-reference of available Searchers, AttributeBatteries names,
    /// and notes on configuring <c>SearcherConfig</c>. Intended for scripts edited
    /// without a language server (vim/nano).
    /// </summary>
    ///
    let help () =
        helpHeader "======= Fiewport help ======="
        helpLine ""
        helpHeader "SearcherConfig"
        helpLine "  ldapDetails.properties  string[] — attributes to request (empty = server default)"
        helpLine "  ldapDetails.filter      string   — extra LDAP clause; AND/OR/ignore varies by Searcher"
        helpLine "  ldapDetails.ldapDN      string   — base DN, e.g. DC=contoso,DC=local"
        helpLine "  ldapDetails.scope       Base | OneLevel | Subtree"
        helpLine "  ldapDetails.ldapHostname string — FQDN (Kerberos SPN / session host)"
        helpLine "  ldapDetails.ldapIP      string  — IP (connect / KDC address); \"\" if unknown"
        helpLine "  ldapDetails.ldapPort    int     — 389 plain, 636 LDAPS"
        helpLine "  ldapDetails.useSsl      bool"
        helpLine "  credentials.username / password — bind principal"
        helpLine "  Tip: use getDomainObjects when you want full control of the LDAP filter."
        helpLine ""
        helpHeader "AttributeBatteries (string arrays)"
        helpLine "  AttributeBatteries.terse    — cn, name, sAMAccountName, DN, objectClass/Category"
        helpLine "  AttributeBatteries.standard — everyday user/group/OU/computer attrs"
        helpLine "  AttributeBatteries.verbose  — standard + SID/GUID/nTSD/delegation/LAPS (no certs)"
        helpLine "  Use in ldapDetails.properties or: results |> Filter.showMany AttributeBatteries.standard"
        helpLine ""
        helpHeader "Filters (client-side)"
        helpLine "  Filter.attributePresent attr"
        helpLine "  Filter.valueIs value"
        helpLine "  Filter.attributeIsValue attr value"
        helpLine "  Filter.byConfig ldapSearchConfig"
        helpLine "  Filter.showMany stringArray"
        helpLine "  Filter.attributeValueContains needle"
        helpLine ""
        helpHeader "Searchers"
        helpLine "  getUsers                      getComputers                 getSites"
        helpLine "  getOUs                        getGroups                    getGroup \"Name\""
        helpLine "  getGroupMembers               getDomainDNSZones            getDNSRecords"
        helpLine "  getDomainSubnets              getDFSShares                 getGroupPolicyObjects"
        helpLine "  getDomainTrusts               getDomainObjects             getDomainControllers"
        helpLine "  getHostsTrustedForDelegation  getReportedServersNotDC      getContainers"
        helpLine "  getUsersWithSPNs              getConstrainedDelegates      getASREPTargets"
        helpLine "  getKerberoastTargets          getProtectedUsers            getGroupsWithLocalAdminRights"
        helpLine "  dumpDomainObjects             getGMSAs                     getUsersWithSidHistory"
        helpLine "  getUsersWithAdminCount        getMachineAccountQuota       getForestDomains"
        helpLine "  getForestGlobalCatalogs       getForestTrusts              getDomainSID"
        helpLine "  getPasswordPolicy             getLaps                      lapsRights"
        helpLine ""
        helpHeader "LAPS notes"
        helpLine "  getLaps     — legacy MCS + Windows LAPS (cleartext and/or encrypted attrs)"
        helpLine "  lapsRights  — same set + nTSecurityDescriptor (ACL / who can read)"
        helpLine "  Cleartext: ms-mcs-admpwd, msLAPS-Password | Encrypted: msLAPS-Encrypted*"
        helpLine ""
