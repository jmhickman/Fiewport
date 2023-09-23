namespace Fiewport

open System
open System.DirectoryServices

open Types
open ADData
open LDAPRecords

[<AutoOpen>]
module DomainSearcher = 
    
    ///<summary>
    ///<para>
    /// Creates a connection to the specified LDAP endpoint at the specified path.
    /// Generally, this should be the FDQN:
    /// <code>LDAP://somedomain.tld</code>
    /// or
    /// <code>LDAP://somdomain.tld/CN=Some,CN=Container,DC=somedomain,DC=tld</code>
    /// </para>
    /// <para>
    /// The latter form simultaneously allows non-domain-joined computers to query while allowing the connection
    /// to live further down the object hierarchy. If the machine you're using isn't domain-joined, a connection
    /// string like
    /// <code>LDAP://CN=Some,CN=Container,DC=somedomain,DC=tld</code>
    /// will not work.
    /// </para>
    /// <remarks>This object should be disposed when you're done with it in a long running script.</remarks>
    /// </summary>
    let internal getDomainConnection lDAPEndpoint username password =
        new DirectoryEntry(lDAPEndpoint, username, password)


    /// 
    /// <summary>Creates a DirectorySearcher using an existing connection to an LDAP endpoint.</summary>
    /// <remarks>This object should be disposed when you're done with it in a long running script.</remarks>
    let internal getDomainSearcher config domain =
        new DirectorySearcher(domain, config.filter, config.properties, config.scope)
    

    ///
    /// <summary>
    /// Helper to convert a TLD in the connection style into the LDAP style
    /// </summary>
    let internal deriveDistinguishedString (domainTld: string) =
        domainTld[7..].Split('.')
        |> Array.map (fun ss -> $"""DC={ss},""")
        |> fun s -> (String.Join("", s)).Trim(',')
    ///
    /// <summary>
    /// This function unboxes values from a SearchResult and sticks them in an ADDataType.
    /// </summary>
    /// <remarks> We don't test for `count &lt;= 0` because we only enter this function if SearchResult.Properties.Contains()
    /// comes back with true.
    /// </remarks>
    /// 
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
            | _ -> "hit singleton type that didn't match: " + detectedType.ToString() |> ADString
        | _ ->
            match detectedType with
            | x when x = typeof<DateTime> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<DateTime>
                |> Seq.map unbox<DateTime>
                |> List.ofSeq
                |> ADDateTimes
            | x when x = typeof<string> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<string>
                |> Seq.map unbox<string>
                |> List.ofSeq
                |> ADStrings
            | x when x = typeof<bool> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<bool>
                |> Seq.map unbox<bool>
                |> List.ofSeq
                |> ADBoolList
            | _ -> "hit collection type that didn't match: " + detectedType.ToString() |> ADString               

    
    ///
    /// I might toss this, not sure it's worth the loc. Removes the three record attrs from the Map.
    let private stripObjsAndEmit (map: Map<string, ADDataTypes>) =
        let objcls = map.Item "objectClass" |> ADData.unwrapADStrings
        let objcat = map.Item "objectCategory" |> ADData.unwrapADString
        let objguid = map.Item "objectGUID" |> ADData.unwrapADBytes |> fun a -> Guid(a)
        ["objectClass"; "objectCategory"; "objectGUID"]
        |> List.fold (fun (lessMap: Map<string, ADDataTypes>) prop -> lessMap.Remove prop ) map
        |> fun map -> {objectClass = objcls; objectCategory = objcat ; objectGUID = objguid; LDAPSearcherError = None; LDAPData = map }
        
    ///
    /// <summary>
    /// Processes SearchResults into LDAPSearchResults, placing in a Map only the attributes that appeared
    /// in the given SearchResult.
    /// </summary>
    /// 
    let private LDAPCoercer (searchResult: SearchResult) =
        ADSIAttributes
        |> List.filter searchResult.Properties.Contains 
        |> List.fold(fun mapData attr ->
            // create an empty Map to use as accumulator for the fold, stuffing it with unboxed values 
            mapData |> Map.add attr (unboxLDAPValue attr searchResult)) Map.empty<string, ADDataTypes>
        |> stripObjsAndEmit
    
    
    let decodeLDAPSearcherError error =
        match error with
        | ServerConnectionError s -> "ServerConnectionError: " + s
        | UnknownError80005000 s -> "UnknownError80005000: " + s
        | NoSuchObject s -> "NoSuchObject: " + s
        | InvalidDNSyntax s -> "InvalidDNSyntax: " + s
        | OtherError s -> "OtherError: " + s
    
    
    ///
    /// This function takes in a SearchResultCollection and returns a LDAPSearchResult
    let internal createLDAPSearchResults (results: Result<SearchResultCollection, LDAPSearcherError>) = 
        match results with
            | Ok results' ->
                try
                    [for item in results' do yield item] |> List.map LDAPCoercer
                with exn ->
                    [{objectClass = [""]; objectCategory = "" ; objectGUID = Guid.Empty; LDAPSearcherError = exn.Message |> Some; LDAPData = Map.empty<string,ADDataTypes> }]
            | Error e ->
                [{objectClass = [""]; objectCategory = "" ; objectGUID = Guid.Empty; LDAPSearcherError = decodeLDAPSearcherError e |> Some; LDAPData = Map.empty<string,ADDataTypes> }]
             
