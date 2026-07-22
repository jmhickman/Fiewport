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
        let rec loop acc = task {
            let! more = results.HasMoreAsync()
            if more then
                try
                    let! entry = results.NextAsync()
                    return! loop (entry :: acc)
                with
                | :? LdapReferralException -> return List.rev acc
                | ex -> return! failwithf "LDAP iteration error: %s" ex.Message
            else
                return List.rev acc
        }
        loop [] |> waitTask

    let internal readyLDAPSearch config =
        let conn = new LdapConnection()
        let constraints = new LdapConstraints()
        constraints.ReferralFollowing <- true
        conn.set_Constraints(constraints)
        conn.ConnectAsync(config.ldapHost, 389, CancellationToken.None) |> waitTaskUnit
        conn.BindAsync(config.username, config.password, CancellationToken.None) |> waitTaskUnit
        conn

    let internal doLDAPSearch (conn: LdapConnection) config =
        let scope = scopeToInt config.scope
        let searchConstraints = new LdapSearchConstraints()
        searchConstraints.ReferralFollowing <- true
        let results = conn.SearchAsync(config.ldapDN, scope, config.filter, config.properties, false, searchConstraints, CancellationToken.None) |> waitTask
        gatherEntries results


    let private runByteHandlers =
        handleNtSecurityDescriptor >> handleObjectSid >> handleDNSRecord >> handleSecurityIdentifier >> handleObjectGuid
        >> handlemsdfsrReplicationGroupGuid >> handleUserCertificate >> handleLogonHours >> handleDSASignature

    let private runStringHandlers =
        handleGenericStrings >> handleThingsWithTicks >> handleThingsWithTimespans >> handleThingsWithZulus
        >> handleGroupType >> handleSystemFlags >> handleUserAccountControl >> handleSamAccountType
        >> handlemsdsSupportedEncryptionType >> handleWellKnownThings >> handleInstanceType >> handleRepSto
        >> handleTrustType >> handleTrustAttibutes >> handleTrustDirection


    let internal createLDAPSearchResults (searchType: LDAPSearchType) config (results: Result<LdapEntry list, string>) =
        match results with
        | Ok entries ->
            let ldapData =
                entries
                |> List.map (fun entry ->
                    let attrSet = entry.GetAttributeSet()
                    let names = attrSet.Keys :> seq<string>
                    names
                    |> Seq.map (fun name ->
                        let attr = attrSet.[name]
                        let values =
                            attr.ByteValueArray
                            |> Array.filter (fun b -> b <> null)
                            |> Array.map ADBytes
                            |> List.ofArray
                        (name, values)
                    )
                    |> Seq.toList
                    |> List.fold (fun acc (name, values) ->
                        match values with
                        | [] -> acc
                        | _ -> acc |> Map.add name values
                    ) Map.empty<string, ADDataTypes list>
                )
                |> List.map runByteHandlers
                |> List.map runStringHandlers

            { searchType = searchType
              searchConfig = config
              ldapSearcherError = None
              ldapData = ldapData }

        | Error e ->
            { searchType = searchType
              searchConfig = config
              ldapSearcherError = e |> Some
              ldapData = [Map.empty<string,string list>] }
