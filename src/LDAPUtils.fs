namespace Fiewport

module LDAPUtils =

    open Novell.Directory.Ldap
    open System.Threading
    open System.Threading.Tasks
    
    open Types
    open LDAPDataHandlers


    let private waitTask<'T> (t: Task<'T>) = t.GetAwaiter().GetResult()
    let private waitTaskUnit (t: Task) = t.GetAwaiter().GetResult()


    /// Resolve the port from the config — callers must set `ldapPort` explicitly.
    let private resolvePort (config: LdapSearchConfig) =
        config.ldapPort


    /// Create an SSL-enabled connection with certificate validation bypassed.
    let private createSslConnection () =
        new LdapConnectionOptions ()
        |> fun opts -> opts.UseSsl ()
        |> fun opts -> opts.ConfigureRemoteCertificateValidationCallback(fun _ _ _ _ -> true)
        |> fun opts -> new LdapConnection(opts)
        

    /// Build an LdapConnection, configure referral following, connect, and bind.
    let internal readyLDAPSearch (creds: LdapCredentials) (config: LdapSearchConfig) =
        let port = resolvePort config
        let conn =
            match config.useSsl with
            | true  -> createSslConnection ()
            | false -> new LdapConnection ()

        let constraints = new LdapConstraints ()
        constraints.ReferralFollowing <- true
        conn.set_Constraints constraints
        conn.ConnectAsync(config.ldapHost, port, CancellationToken.None) |> waitTaskUnit
        conn.BindAsync(creds.username, creds.password, CancellationToken.None) |> waitTaskUnit
        conn
    

    /// Ask for SecurityDescriptors, otherwise they won't be supplied
    let private createSDFlagControl () =
        // LDAP_SERVER_SD_FLAGS_OID: 1.2.840.113556.1.4.801
        // BER: SEQUENCE { INTEGER 7 } (7 = OWNER(1) | GROUP(2) | DACL(4))
        // SACL(8) omitted — requires SeSecurityPrivilege
        let sdFlags = [| 48uy; 3uy; 2uy; 1uy; 7uy |]
        new LdapControl("1.2.840.113556.1.4.801", true, sdFlags)
    

    ///
    /// Use manual paged results to retrieve all entries while preserving
    /// the SD flag control. The Novell extension method (SearchUsingSimplePagingAsync)
    /// creates a new LdapSearchConstraints internally, which drops our SD flag control.
    /// By paging manually we keep both controls active on every request.
    /// 
    let internal doLDAPSearch (conn: LdapConnection) config =
        let scope = 
            match config.scope with
            | Base -> LdapConnection.ScopeBase
            | OneLevel -> LdapConnection.ScopeOne
            | Subtree -> LdapConnection.ScopeSub

        let sdControl = createSDFlagControl ()
        // Paged results control OID: 1.2.840.113556.1.4.319
        let pageSize = 1000

        let rec loop cookie acc =
            let pagedControl = new Controls.SimplePagedResultsControl(pageSize, cookie)

            let searchConstraints = new LdapSearchConstraints ()
            searchConstraints.ReferralFollowing <- true
            searchConstraints.SetControls [| sdControl; pagedControl |]

            let results =
                conn.SearchAsync(
                    config.ldapDN, scope, config.filter,
                    config.properties, false,
                    searchConstraints, CancellationToken.None)
                |> waitTask

            // Collect entries from current page
            let entries =
                let rec collect acc' =
                    match results.HasMoreAsync() |> waitTask with
                    | false -> List.rev acc'
                    | true ->
                        let entry = results.NextAsync() |> waitTask
                        collect (entry :: acc')
                collect []

            // Extract response cookie from server controls. The server echoes back
            // The server echoes back the paged results control with a cookie for
            // the next page, or an empty cookie to signal completion.
            match
                results.ResponseControls
                |> Option.ofObj
                |> Option.bind (Array.tryPick (function
                        | :? Controls.SimplePagedResultsControl as c -> c.Cookie |> Some
                        | _ -> None))
                |> Option.filter (not << Array.isEmpty)
            with
            | Some next -> loop next (entries @ acc)
            | None -> entries @ acc

        loop null []


    let private runByteHandlers =
        handleNtSecurityDescriptor >> handleObjectSid >> handleDNSRecord >> handleSecurityIdentifier >> handleObjectGuid
        >> handlemsdfsrReplicationGroupGuid >> handlemsdsOptionalFeatureGuid >> handleInvocationId >> handleUserCertificate >> handleLogonHours >> handleDSASignature
        >> handleBigEndianIntegers


    let private runStringHandlers =
        handleGenericStrings >> handleThingsWithTicks >> handleThingsWithTimespans >> handleThingsWithZulus
        >> handleGroupType >> handleSystemFlags >> handleUserAccountControl >> handleSamAccountType
        >> handlemsdsSupportedEncryptionType >> handleWellKnownThings >> handleInstanceType >> handleRepSto
        >> handleTrustType >> handleTrustAttibutes >> handleTrustDirection
        >> handleGroupPolicyCseGuids


    /// Extract byte values from an LDAP attribute, handling the quirks of Novell's API:
    ///
    /// `ByteValueArray` can be null (no values), empty (no values), or contain null entries
    /// (mixed null/non-null). When it's null/empty/all-null, fall back to `ByteValue`
    /// (single-value attributes). When `ByteValue` is also null, the attribute is empty.
    /// Non-null entries in `ByteValueArray` become `ADBytes` values.
    let private extractAttributeValues (attr: LdapAttribute) =
        match attr.ByteValueArray with
        | null ->
            match attr.ByteValue with
            | null -> List.empty<ADDataTypes>
            | b -> [ADBytes b]
        | arr when arr.Length = 0 ->
            match attr.ByteValue with
            | null -> List.empty<ADDataTypes>
            | b -> [ADBytes b]
        | arr ->
            let nonNull = arr |> Array.filter (fun b -> b <> null)
            if nonNull.Length = 0 then
                match attr.ByteValue with
                | null -> List.empty<ADDataTypes>
                | b -> [ADBytes b]
            else
                nonNull |> Array.map ADBytes |> List.ofArray


    let internal doSearch creds config =
        let conn = readyLDAPSearch creds config
        try
            doLDAPSearch conn config |> Ok
        with
            exn -> Error { message = exn.Message; context = "search" }


    let internal createLDAPSearchResults searchType config (results: Result<LdapEntry list, LdapError>) =
        match results with
        | Ok entries ->
            let ldapData =
                entries
                |> List.map (fun entry ->
                    let attrSet = entry.GetAttributeSet()
                    let names = attrSet.Keys
                    names
                    |> Seq.map (fun name -> name, extractAttributeValues attrSet.[name])
                    |> Seq.toList
                    |> List.fold (fun acc (name, values) ->
                        if List.isEmpty values then acc
                        else Map.add (name.ToLowerInvariant()) values acc)
                        Map.empty<string, ADDataTypes list> )
                |> List.map runByteHandlers
                |> List.map runStringHandlers

            { searchType = searchType
              searchConfig = config
              ldapSearcherError = None
              ldapData = ldapData }

        | Error err ->
            { searchType = searchType
              searchConfig = config
              ldapSearcherError = Some err
              ldapData = [Map.empty] }
