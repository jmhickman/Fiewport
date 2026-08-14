namespace Fiewport

module LDAPUtils =

    open Types
    open LDAPDataHandlers
    open FauliAuth
    open LdapSearch


    /// Convert a list of RawLdapEntry into the internal ADDataTypes map format.
    let internal rawEntriesToMaps (entries: RawLdapEntry list) : Map<string, ADDataTypes list> list =
        entries
        |> List.map (fun entry ->
            entry.Attributes
            |> Map.map (fun _ byteVals ->
                byteVals |> List.map ADBytes)
            |> Map.filter (fun _ vals -> not (List.isEmpty vals)))


    let private runByteHandlers =
        handleNtSecurityDescriptor 
        >> handleObjectSid 
        >> handleDNSRecord 
        >> handleSecurityIdentifier 
        >> handleObjectGuid
        >> handlemsdfsrReplicationGroupGuid 
        >> handlemsdsOptionalFeatureGuid 
        >> handleInvocationId 
        >> handleUserCertificate 
        >> handleLogonHours 
        >> handleDSASignature
        >> handleBigEndianIntegers


    let private runStringHandlers =
        handleGenericStrings 
        >> handleThingsWithTicks 
        >> handleThingsWithTimespans 
        >> handleThingsWithZulus
        >> handleGroupType 
        >> handleSystemFlags 
        >> handleUserAccountControl 
        >> handleSamAccountType
        >> handlemsdsSupportedEncryptionType 
        >> handleWellKnownThings 
        >> handleInstanceType 
        >> handleRepSto
        >> handleTrustType 
        >> handleTrustAttibutes 
        >> handleTrustDirection
        >> handleGroupPolicyCseGuids


    /// Authenticate via Fauli, then perform a wire-layer search with
    /// SD Flags and paged results controls. This is the primary search entry point.
    let internal doSearch (creds: LdapCredentials) (config: LdapSearchConfig) : Result<RawLdapEntry list, LdapWireError> =
        match authenticate creds config with
        | Error e -> Error e
        | Ok session -> LdapSearch.doSearch session config


    /// Build an LDAPSearchResult from the wire-layer search outcome.
    /// On success, decodes raw bytes into the fully processed LDAPEntryData format.
    /// On error, wraps the LdapWireError in the result's error field.
    let internal createLDAPSearchResults searchType config (results: Result<RawLdapEntry list, LdapWireError>) : LDAPSearchResult =
        match results with
        | Ok entries ->
            let ldapData =
                entries
                |> rawEntriesToMaps
                |> List.map runByteHandlers
                |> List.map runStringHandlers

            { searchType = searchType
              searchConfig = config
              ldapSearcherError = None
              ldapData = ldapData }

        | Error err ->
            { searchType = searchType
              searchConfig = config
              ldapSearcherError = Some { message = err.ToString(); context = "search" }
              ldapData = [Map.empty] }
