﻿namespace Fiewport

open System
open System.DirectoryServices

open Types
open ADData
open LDAPConstants

module DomainSearcher = 
    
    ///
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
    /// </summary>
    /// 
    let internal getDomainConnection lDAPEndpoint username password = 
        new DirectoryEntry(lDAPEndpoint, username, password)


    /// 
    /// <summary>Creates a DirectorySearcher using an existing connection to an LDAP endpoint.</summary>
    let internal getDomainSearcher config domain =
        new DirectorySearcher(domain, config.filter, config.properties, config.scope)
        |> fun ds ->
            ds.SecurityMasks <-
                SecurityMasks.Dacl ||| SecurityMasks.Sacl ||| SecurityMasks.Group ||| SecurityMasks.Owner
            ds        


    ///
    /// <summary>
    /// Helper to convert a TLD in the connection style into the LDAP style
    /// </summary>
    /// 
    let internal deriveDistinguishedString (domainTld: string) =
        domainTld[7..].Split('.')
        |> Array.map (fun ss -> $"""DC={ss},""")
        |> fun s -> String.Join("", s).Trim(',')


    ///
    /// <summary>
    /// This function unboxes values from a SearchResult and sticks them in an ADDataType.
    /// </summary>
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
            | x when x = typeof<byte array> ->
                searchResult.Properties.Item(attrName)
                |> Seq.cast<byte array>
                |> Seq.map unbox<byte array>
                |> List.ofSeq
                |> ADBytesList
            | _ -> "***HIT COLLECTION TYPE THAT DIDN'T MATCH: " + detectedType.ToString() |> ADString               

    
    ///
    /// Removes the four record attrs from the Map that appear in the 'root' of the record.
    let private stripObjsAndEmit searchType searchConfig (map: Map<string, ADDataTypes>) =
        let objcls = map.Item "objectClass" |> ADData.unwrapADStrings
        let objcat = map.Item "objectCategory" |> ADData.unwrapADString
        let objguid = map.Item "objectGUID" |> ADData.unwrapADBytes |> fun a -> Guid(a)
        let mutable ntsd = ""
        if map.ContainsKey "nTSecurityDescriptor" then
            ntsd <- map.Item "nTSecurityDescriptor" |> ADData.unwrapADBytes |> ADData.readSecurityDescriptor
        ["objectClass"; "objectCategory"; "objectGUID"; "nTSecurityDescriptor"]
        |> List.fold (fun (lessMap: Map<string, ADDataTypes>) prop -> lessMap.Remove prop ) map
        |> fun map ->
                { searchType = searchType
                  searchConfig = searchConfig 
                  objectClass = objcls
                  objectCategory = objcat
                  objectGUID = objguid
                  nTSecurityDescriptor = ntsd
                  lDAPSearcherError = None
                  lDAPData = map }
    
    
    ///
    /// <summary>
    /// Processes SearchResults into LDAPSearchResults, placing in a Map only the attributes that appeared
    /// in the given SearchResult.
    /// </summary>
    /// 
    let private LDAPCoercer searchType searchConfig (searchResult: SearchResult) =
        ADSIAttributes
        |> List.filter searchResult.Properties.Contains 
        |> List.fold(fun mapData attr ->
            // create an empty Map to use as accumulator for the fold, stuffing it with unboxed values 
            mapData |> Map.add attr (unboxLDAPValue attr searchResult)) Map.empty<string, ADDataTypes>
        |> stripObjsAndEmit searchType searchConfig
    
    
    ///
    /// Error message injection
    let private decodeLDAPSearcherError error =
        match error with
        | ServerConnectionError s -> "ServerConnectionError: " + s
        | UnknownError80005000 s -> "UnknownError80005000: " + s
        | NoSuchObject s -> "NoSuchObject: " + s
        | InvalidDNSyntax s -> "InvalidDNSyntax: " + s
        | OtherError s -> "OtherError: " + s
    
    
    ///
    /// This function takes in a SearchResultCollection and returns a LDAPSearchResult
    let internal createLDAPSearchResults searchType (results: IntermediateSearchResultsCollection) = 
        
        match results with
            | Ok (results', searchConfig) ->
                // This try/with is necessary because (for whatever reason) invalid filters blow up here, instead of
                // during the search. I don't know if this is some hidden lazy eval or what, but that's what happens.
                try
                    [for item in results' do yield item] |> List.map (LDAPCoercer searchType searchConfig)
                with exn ->
                    [{ searchType = searchType
                       searchConfig = searchConfig 
                       objectClass = [""]
                       objectCategory = "Failed Search"
                       objectGUID = Guid.Empty
                       nTSecurityDescriptor =  ""
                       lDAPSearcherError = exn.Message |> Some
                       lDAPData = Map.empty<string,ADDataTypes> }]
            | Error (e, searchConfig) ->                
                [{ searchType = searchType
                   searchConfig = searchConfig
                   objectClass = [""]
                   objectCategory = "Failed Search"
                   objectGUID = Guid.Empty
                   nTSecurityDescriptor =  ""
                   lDAPSearcherError = decodeLDAPSearcherError e |> Some
                   lDAPData = Map.empty<string,ADDataTypes> }]
