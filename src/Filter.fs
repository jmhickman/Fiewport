namespace Fiewport

module Filter =
    
    ///
    ///<summary>
    /// Filters LDAPSearchResults based upon the presence of the supplied <c>filterAttribute</c> key in the
    /// LDAPData map.
    /// </summary>
    let attributePresent attr (results: LDAPSearchResult list) =
        results
        |> List.map(fun result ->
            let maps = result.ldapData
            let filteredMaps = maps |> List.filter(fun oneMap -> oneMap.ContainsKey attr)
            {result with ldapData = filteredMaps})


    ///
    ///<summary>
    ///Filters LDAPSearchResults based upon <c>value</c> being present in any key in the ldapData Map. Will return
    ///only Maps where the <c>value</c> matched.
    ///</summary>
    /// 
    let valueIs (value: string) (results: LDAPSearchResult list) =
        results
        |> List.map(fun result ->
            let maps = result.ldapData
            let filteredMaps = maps |> List.filter(fun oneMap -> [for key in oneMap.Keys do yield oneMap[key] = [value]] |> List.contains true)
            {result with ldapData = filteredMaps})    
    

    ///
    /// <summary>
    /// Filter LDAPSearchResults based upon the presence of a matching attribute and value.
    /// </summary>
    ///  
    let attributeIsValue (attr: string) (value: string) (results: LDAPSearchResult list) =
        results |> attributePresent attr |> valueIs value


    ///
    /// <summary>
    /// Filter LDAPSearchResults by the specific WHOLE config used. This is useful with <c>Tee</c>s, allowing the
    /// results of different searches to be split off for processing within that <c>Tee</c> based on the config.
    /// </summary>
    /// 
    let byConfig config (results: LDAPSearchResult list) =
        List.filter (fun p ->
            match p.ldapSearcherError with
            | Some _ -> true
            | None -> p.searchConfig = config) results
