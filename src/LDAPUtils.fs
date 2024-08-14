namespace Fiewport

module LDAPUtils =     
    open System
    open System.DirectoryServices.Protocols
    open System.Net

    open Types
    ///
    /// Creates a connection to the specified LDAP endpoint at the specified path.
    /// Generally, this should be the FDQN:
    /// LDAP://somedomain.tld</code>
    /// or
    /// LDAP://somdomain.tld/CN=Some,CN=Container,DC=somedomain,DC=tld</code>
    /// 
    // let internal getDomainConnection lDAPEndpoint username password = 
    //     new DirectoryEntry(lDAPEndpoint, username, password)

    
    /// 
    /// Creates a DirectorySearcher using an existing connection to an LDAP endpoint.
    // let internal getDomainSearcher config domain =
    //     new DirectorySearcher(domain, config.filter, config.properties, config.scope)
    //     |> fun ds ->            
    //         ds.SecurityMasks <- SecurityMasks.Dacl ||| SecurityMasks.Group ||| SecurityMasks.Owner
    //         ds        


    let internal configureLDAPConnection ldapEndpoint username (password: string) =
        let ldapIdentifier = LdapDirectoryIdentifier(ldapEndpoint)
        let credential = NetworkCredential(username, password)
        new LdapConnection(ldapIdentifier, credential)
        
        
    let internal getLDAPSearcher config =
        let searchRequest = SearchRequest(config.ldapDomain, config.filter, config.scope, config.properties)
        let flags = SecurityDescriptorFlagControl(SecurityMasks.Dacl ||| SecurityMasks.Group ||| SecurityMasks.Owner)
        searchRequest.Controls.Add(flags) |> ignore
        searchRequest
    
    ///
    /// Helper to convert a TLD in the connection style into the LDAP style 
    let internal deriveDistinguishedString (domainTld: string) =
        domainTld[7..].Split('.')
        |> Array.map (fun s -> $"""DC={s},""")
        |> fun xs -> String.Join("", xs).Trim(',')


 
    /// Removes the four record attrs from the Map that appear in the 'root' of the record.
    let private setRecordAttrs searchType searchConfig (map: Map<string, ADDataTypes>) =       
        { searchType = searchType
          searchConfig = searchConfig 
          lDAPSearcherError = None
          lDAPData = map }
    
    
    ///
    /// Processes SearchResults into LDAPSearchResults, placing in a Map only the attributes that appeared
    /// in the given SearchResult.
    /// 
    let internal LDAPCoercer searchType searchConfig (searchResult: SearchResult) =
        [for name in searchResult.Properties.PropertyNames do yield name.ToString ()]
        |> List.fold(fun mapData attr -> mapData |> Map.add attr (unboxLDAPValue attr searchResult))
               Map.empty<string, ADDataTypes>
        |> setRecordAttrs searchType searchConfig
    
    
    ///
    /// Error message injection
    let internal decodeLDAPSearcherError error =
        match error with
        | ServerConnectionError s -> "ServerConnectionError: " + s + " Check your connection string and user/pass"
        | UnknownError80005000 s -> "UnknownError80005000: " + s
        | NoSuchObject s -> "NoSuchObject: " + s
        | InvalidDNSyntax s -> "InvalidDNSyntax: " + s
        | OtherError s -> "OtherError: " + s
