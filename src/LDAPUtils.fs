namespace Fiewport

module LDAPUtils =     

    open System.DirectoryServices.Protocols
    open System.Net

    open Types
    open LDAPDataHandlers


    let internal readyLDAPSearch config =
        let ldapIdentifier = LdapDirectoryIdentifier(config.ldapHost) // does this work with ldap://?
        let credential = NetworkCredential(config.username, config.password)
        let connection = new LdapConnection(ldapIdentifier, credential)    
        let searchRequest =
            SearchRequest(config.ldapDN, config.filter, config.scope, config.properties)
            |> fun sr ->
                sr.Controls.Add(SecurityDescriptorFlagControl(SecurityMasks.Dacl ||| SecurityMasks.Group ||| SecurityMasks.Owner)) |> ignore
                sr
        (connection, searchRequest)

    
    let private runByteHandlers =
        handleNtSecurityDescriptor >> handleObjectSid >> handleDNSRecord >> handleSecurityIdentifier >> handleObjectGuid
        >> handlemsdfsrReplicationGroupGuid >> handleUserCertificate >> handleLogonHours >> handleDSASignature
        
    let private runStringHandlers =
        handleGenericStrings >> handleThingsWithTicks >> handleThingsWithTimespans >> handleThingsWithZulus
        >> handleGroupType >> handleSystemFlags >> handleUserAccountControl >> handleSamAccountType
        >> handlemsdsSupportedEncryptionType >> handleWellKnownThings >> handleInstanceType >> handleRepSto
        >> handleTrustType >> handleTrustAttibutes >> handleTrustDirection

    
    let internal createLDAPSearchResults (searchType: LDAPSearchType) config (results: Result<SearchResponse, string>) =
        match results with
        | Ok res ->
            let ldapData = // need to handle objectsid, ntsecdes, objectguid, usercert
                [for item in res.Entries do yield item] // Extract entries
                |> List.map (fun p ->
                    [for name in p.Attributes.AttributeNames do yield name.ToString()]// extract the names of the attributes returned
                    |> List.map (fun name -> (name, [for item in p.Attributes[name] do yield (item :?> byte array) |> ADBytes])) // for each attribute, retrieve all values and create a tuple
                    |> List.fold (fun acc (name, values) -> acc |> Map.add name values) Map.empty<string, ADDataTypes list>)  // create a Map to easily access values
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