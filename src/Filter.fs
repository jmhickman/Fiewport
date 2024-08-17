namespace Fiewport

[<AutoOpen>]
module Filter =
    
    let private attributePresent attr (results: LDAPSearchResult list) =
        results
        |> List.map(fun result ->
            let maps = result.ldapData
            let filteredMaps = maps |> List.filter(fun oneMap -> oneMap.ContainsKey attr)
            {result with ldapData = filteredMaps})


    let private valueIs (value: string) (results: LDAPSearchResult list) =
            results
            |> List.map(fun result ->
                let maps = result.ldapData
                let filteredMaps = maps |> List.filter(fun oneMap -> [for key in oneMap.Keys do yield oneMap[key] = [value]] |> List.contains true)
                {result with ldapData = filteredMaps})    


    type Filter = class end
    
        with        
        // TODO: Generally need to check that the logic of how these are used blocks processing empty lists. Otherwise add guards
        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied <c>filterAttribute</c> key in the
        /// LDAPData map.
        /// </summary>
        static member public attributePresent attr (results: LDAPSearchResult list) = attributePresent attr results
            
        ///
        ///<summary>
        ///Filters LDAPSearchResults based upon <c>value</c> being present in any key in the ldapData Map. Will return
        ///only Maps where the <c>value</c> matched.
        ///</summary>
        /// 
        static member public valueIs (value: string) (results: LDAPSearchResult list) = valueIs value results
        
        ///
        /// <summary>
        /// Filter LDAPSearchResults based upon the presence of a matching attribute and value.
        /// </summary>
        ///  
        static member public attributeIsValue (attr: string) (value: string) (results: LDAPSearchResult list) =
            results |> (attributePresent attr ) |> (valueIs value)


        ///
        /// <summary>
        /// Filter LDAPSearchResults by the specific WHOLE config used. This is useful with <c>Tee</c>s, allowing the
        /// results of different searches to be split off for processing within that <c>Tee</c> based on the config.
        /// </summary>
        /// 
        static member public byConfig config (results: LDAPSearchResult list) =
            List.filter (fun p ->
                match p.ldapSearcherError with
                | Some _ -> true
                | None -> p.searchConfig = config) results
