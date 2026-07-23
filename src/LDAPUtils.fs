namespace Fiewport

module LDAPUtils =

    open Novell.Directory.Ldap
    open System.Threading
    open System.Threading.Tasks
    open Types
    open LDAPDataHandlers

    let private scopeToInt (s: SearchScope) =
        match s with
        | Base -> LdapConnection.ScopeBase
        | OneLevel -> LdapConnection.ScopeOne
        | Subtree -> LdapConnection.ScopeSub

    let private waitTask<'T> (t: Task<'T>) = t.GetAwaiter().GetResult()
    let private waitTaskUnit (t: Task) = t.GetAwaiter().GetResult()

    let private gatherEntries (results: ILdapSearchResults) =
        let rec loop acc referrals = task {
            let! more = results.HasMoreAsync()
            if more then
                try
                    let! entry = results.NextAsync()
                    return! loop (entry :: acc) referrals
                with
                | :? LdapReferralException as ex ->
                    let refs = ex.GetReferrals() |> List.ofArray
                    return Ok (List.rev acc, refs)
                | ex ->
                    return Error { message = $"LDAP iteration error: {ex.Message}"; context = "iterate" }
            else
            return Ok (List.rev acc, referrals)
        }
        loop [] [] |> waitTask

    let internal readyLDAPSearch config =
        let port = if config.ldapPort <> 0 then config.ldapPort else 389
        let conn =
            if config.useSsl then
                let opts = new LdapConnectionOptions()
                opts.UseSsl() |> ignore
                opts.ConfigureRemoteCertificateValidationCallback(fun _ _ _ _ -> true) |> ignore
                new LdapConnection(opts)
            else
                new LdapConnection()
        let constraints = new LdapConstraints()
        constraints.ReferralFollowing <- true
        conn.set_Constraints(constraints)
        conn.ConnectAsync(config.ldapHost, port, CancellationToken.None) |> waitTaskUnit
        conn.BindAsync(config.username, config.password, CancellationToken.None) |> waitTaskUnit
        conn

    let private createSDFlagControl () =
        // LDAP_SERVER_SD_FLAGS_OID: 1.2.840.113556.1.4.801
        // BER: SEQUENCE { INTEGER 7 } (7 = OWNER(1) | GROUP(2) | DACL(4))
        // SACL(8) omitted — requires SeSecurityPrivilege
        let sdFlags = [| 48uy; 3uy; 2uy; 1uy; 7uy |]
        new LdapControl("1.2.840.113556.1.4.801", true, sdFlags)

    let internal doLDAPSearch (conn: LdapConnection) config =
        let scope = scopeToInt config.scope
        let searchConstraints = new LdapSearchConstraints()
        searchConstraints.ReferralFollowing <- true
        searchConstraints.SetControls [| createSDFlagControl() |]
        let results = conn.SearchAsync(config.ldapDN, scope, config.filter, config.properties, false, searchConstraints, CancellationToken.None) |> waitTask
        match gatherEntries results with
        | Ok (entries, referrals) -> Ok (entries, referrals)
        | Error err -> Error err


    let private runByteHandlers =
        handleNtSecurityDescriptor >> handleObjectSid >> handleDNSRecord >> handleSecurityIdentifier >> handleObjectGuid
        >> handlemsdfsrReplicationGroupGuid >> handleUserCertificate >> handleLogonHours >> handleDSASignature
        >> handleBigEndianIntegers

    let private runStringHandlers =
        handleGenericStrings >> handleThingsWithTicks >> handleThingsWithTimespans >> handleThingsWithZulus
        >> handleGroupType >> handleSystemFlags >> handleUserAccountControl >> handleSamAccountType
        >> handlemsdsSupportedEncryptionType >> handleWellKnownThings >> handleInstanceType >> handleRepSto
        >> handleTrustType >> handleTrustAttibutes >> handleTrustDirection

    let internal doSearch config =
        let conn = readyLDAPSearch config
        try
            doLDAPSearch conn config
        with
            exn -> Error { message = exn.Message; context = "search" }


    let internal createLDAPSearchResults (searchType: LDAPSearchType) config (results: Result<LdapEntry list * string list, LdapError>) =
        match results with
        | Ok (entries, referrals) ->
            let ldapData =
                entries
                |> List.map (fun entry ->
                    let attrSet = entry.GetAttributeSet()
                    let names = attrSet.Keys :> seq<string>
                    names
                    |> Seq.map (fun name ->
                        let attr = attrSet.[name]
                        let values =
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
                                if nonNull.Length = 0 && arr.Length > 0 then
                                    match attr.ByteValue with
                                    | null -> List.empty<ADDataTypes>
                                    | b -> [ADBytes b]
                                else
                                    nonNull
                                    |> Array.map ADBytes
                                    |> List.ofArray
                        (name, values)
                    )
                    |> Seq.toList
                    |> List.fold (fun acc (name, values) ->
                        match values with
                        | [] -> acc
                        | _ -> acc |> Map.add (name.ToLowerInvariant()) values
                    ) Map.empty<string, ADDataTypes list>
                )
                |> List.map runByteHandlers
                |> List.map runStringHandlers

            { searchType = searchType
              searchConfig = config
              ldapSearcherError = None
              ldapData = ldapData
              ldapReferrals = referrals }

        | Error err ->
            { searchType = searchType
              searchConfig = config
              ldapSearcherError = Some err
              ldapData = [Map.empty]
              ldapReferrals = [] }
