namespace Fiewport

open System
open System.DirectoryServices

open Types
open ADData
open LDAPRecords

[<AutoOpen>]
module DomainSearcher =    
    
    /// <summary>
    /// <para>
    /// Convenience function to create an empty DirectorySearcherConfig, ready to be manipulated into
    /// other specific search setups using `with`:
    /// </para>
    /// <code>
    /// let dSearch = defaultDirectorySearcher ()
    /// </code>
    /// <code>
    /// let personSearch = {dSearch with filter = "(&amp;(objectCategory=person\))" }
    /// </code>
    /// </summary>    
    let defaultDirectorySearcher () = {properties = [||]; filter = ""; scope = SearchScope.Subtree }
    
    ///<summary>
    ///<para>
    /// Creates a connection to the specified LDAP endpoint at the specified path.
    /// Generally, this should be the FDQN: "LDAP://somedomain.tld".
    /// </para>
    /// <remarks>
    /// Unless there is a specific reason to, it's  best to connect at the 'rootmost' endpoint rather
    /// than deeper into the LDAP hierarchy, in order to avoid missing search results.
    /// </remarks>
    /// </summary>
    let getDomainConnection lDAPEndpoint username password =
        new DirectoryEntry(lDAPEndpoint, username, password)

    
    /// 
    /// Creates a DirectorySearcher using an existing connection to an LDAP endpoint.
    let getDomainSearcher config domain =
        new DirectorySearcher(domain, config.filter, config.properties, config.scope)
    

    ///
    /// <summary>
    /// This function unboxes values from a SearchResult where they are a single value, and sticks them in
    /// an ADDataType.
    /// </summary>
    /// <remarks> We don't test for &lt;= 0 because we only enter this function if Contains() comes back with true.</remarks>
    /// 
    let unboxLDAPValue attrName (searchResult: SearchResult) =
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
            | _ -> "hit singleton type that didn't match: " + attrName |> ADString
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
            | _ -> "hit collection type that didn't match: " + attrName |> ADString               

    
    ///
    /// I might toss this, not sure it's worth the loc.
    let stripObjsAndEmit (map: Map<string, ADDataTypes>) =
        let objcls = map.Item "objectClass" |> ADData.unwrapADStrings
        let objcat = map.Item "objectCategory" |> ADData.unwrapADString
        let objguid = map.Item "objectGUID" |> ADData.unwrapADBytes
        ["objectClass"; "objectCategory"; "objectGUID"]
        |> List.fold (fun (lessMap: Map<string, ADDataTypes>) prop -> lessMap.Remove prop ) map
        |> fun map -> {objectClass = objcls; objectCategory = objcat ; objectGUID = objguid; LDAPData = map }
        
    ///
    /// <summary>
    /// Processes SearchResults into LDAPSearchResults, placing in a Map only the attributes that appeared
    /// in the given SearchResult.
    /// </summary>
    /// 
    let LDAPCoercer (searchResult: SearchResult) =
        ADSIAttributes
        |> List.filter searchResult.Properties.Contains 
        |> List.fold(fun mapData attr ->
            // create an empty Map to use as accumulator for the fold, stuffing it with unboxed values 
            mapData |> Map.add attr (unboxLDAPValue attr searchResult)) Map.empty<string, ADDataTypes>
        |> stripObjsAndEmit
    
    
    ///
    /// This function takes in a SearchResultCollection and returns a LDAPSearchResult
    let createLDAPSearchResults (results: SearchResultCollection) = 
        [for item in results do yield item] |> List.map LDAPCoercer
