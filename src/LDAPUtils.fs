namespace Fiewport

module LDAPUtils =

    open Types
    open LDAPDataHandlers
    open FauliAuth
    open LdapSearch
    open Fauli.Domain


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


    ///
    /// Bind via Fauli and run a single-server paged search (no chase).
    let private searchOneServer (creds: LdapCredentials) (config: LdapSearchConfig) : Result<ServerSearchOutcome, LdapWireError> =
        match authenticate creds config with
        | Error e -> Error e
        | Ok session -> searchSession session config


    ///
    /// Apply transparent referral chase to a primary server outcome.
    let private withReferralChase (creds: LdapCredentials) (config: LdapSearchConfig) (primary: ServerSearchOutcome) : Result<RawLdapEntry list, LdapWireError> =
        match primaryReferralTarget config with
        | Error e -> Error e
        | Ok primaryTarget ->
            chaseReferrals (searchOneServer creds) config primaryTarget primary.entries primary.referralUris


    ///
    /// Authenticate, perform a wire-layer search with SD Flags and paged
    /// results controls, then transparently chase any LDAP referrals with the same
    /// credentials, filter, scope, and attributes.
    /// 
    let internal doSearch (creds: LdapCredentials) (config: LdapSearchConfig) : Result<RawLdapEntry list * AuthenticationMethod, LdapWireError> =
        match authenticate creds config with
        | Error e -> Error e
        | Ok session ->
            match searchSession session config with
            | Error e -> Error e
            | Ok primaryOutcome ->
                match withReferralChase creds config primaryOutcome with
                | Error e -> Error e
                | Ok entries -> Ok (entries, session.authenticationMethod)


    ///
    /// Build an LDAPSearchResult from the wire-layer search outcome.
    /// On success, decodes raw bytes into the fully processed LDAPEntryData format.
    /// Referral chasing is transparent.
    /// On error, wraps the LdapWireError in the result's error field.
    /// 
    let internal createLDAPSearchResults searchType config (results: Result<RawLdapEntry list * AuthenticationMethod, LdapWireError>) : LDAPSearchResult =
        match results with
        | Ok (entries, authMethod) ->
            let ldapData =
                entries
                |> rawEntriesToMaps
                |> List.map runByteHandlers
                |> List.map runStringHandlers

            { searchType = searchType
              searchConfig = config
              ldapSearcherError = None
              ldapData = ldapData
              authenticationMethod = Some authMethod }

        | Error err ->
            { searchType = searchType
              searchConfig = config
              ldapSearcherError = Some { message = err.ToString(); context = "search" }
              ldapData = [Map.empty]
              authenticationMethod = None }
