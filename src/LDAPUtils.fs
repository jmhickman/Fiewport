namespace Fiewport

open System
open System.DirectoryServices

open Types

module LDAPUtils =     

    ///
    /// Creates a connection to the specified LDAP endpoint at the specified path.
    /// Generally, this should be the FDQN:
    /// LDAP://somedomain.tld</code>
    /// or
    /// LDAP://somdomain.tld/CN=Some,CN=Container,DC=somedomain,DC=tld</code>
    /// 
    let internal getDomainConnection lDAPEndpoint username password = 
        new DirectoryEntry(lDAPEndpoint, username, password)

    
    /// 
    /// Creates a DirectorySearcher using an existing connection to an LDAP endpoint.
    let internal getDomainSearcher config domain =
        new DirectorySearcher(domain, config.filter, config.properties, config.scope)
        |> fun ds ->            
            ds.SecurityMasks <- SecurityMasks.Dacl ||| SecurityMasks.Group ||| SecurityMasks.Owner
            ds        


    ///
    /// Helper to convert a TLD in the connection style into the LDAP style 
    let internal deriveDistinguishedString (domainTld: string) =
        domainTld[7..].Split('.')
        |> Array.map (fun s -> $"""DC={s},""")
        |> fun xs -> String.Join("", xs).Trim(',')


    ///
    /// This function unboxes values from a SearchResult and sticks them in an ADDataType. 
    let private unboxLDAPValue attrName (searchResult: SearchResult) =
        let items = searchResult.Properties.Item(attrName)
        let count = items.Count
        let item = items.Item(0)
        let detectedType = item.GetType()
        
        match count with
        | 1 ->
            match detectedType with
            | x when x = typeof<Int64> -> unbox<Int64> item |> ADInt64
            | x when x = typeof<int> -> unbox<int> item |> ADInt
            | x when x = typeof<string> -> unbox<string> item |> ADString
            | x when x = typeof<DateTime> -> unbox<DateTime> item |> ADDateTime
            | x when x = typeof<byte array> -> unbox<byte array> item |> ADBytes
            | x when x = typeof<bool> -> unbox<bool> item |> ADBool
            | _ -> "***HIT COLLECTION TYPE THAT DIDN'T MATCH: " + detectedType.ToString() |> ADString
        | _ ->
            match detectedType with
            | x when x = typeof<DateTime> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<DateTime>
                |> Seq.map unbox<DateTime>
                |> List.ofSeq
                |> ADDateTimeList
            | x when x = typeof<string> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<string>
                |> Seq.map unbox<string>
                |> List.ofSeq
                |> ADStringList
            | x when x = typeof<byte array> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<byte array>
                |> Seq.map unbox<byte array>
                |> List.ofSeq
                |> ADBytesList
            | _ -> ["***HIT COLLECTION TYPE THAT DIDN'T MATCH: " + detectedType.ToString()]|> ADStringList

    
    ///
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
