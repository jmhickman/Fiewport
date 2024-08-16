namespace Fiewport

[<AutoOpen>]
module Filter =
    
    type Filter = class end
    
        with        
        // TODO: Generally need to check that the logic of how these are used blocks processing empty lists. Otherwise add guards
        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied <c>filterAttribute</c> key in the
        /// LDAPData map.
        /// </summary>
        static member public attributePresent filterAttribute (results: LDAPSearchResult list) =
            results
            |> List.map(fun result ->
                let maps = result.ldapData
                let filteredMaps = maps |> List.filter(fun oneMap -> oneMap.ContainsKey filterAttribute)
                {result with ldapData = filteredMaps})
            
        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied value <c>value</c> for any key in the
        /// LDAPData Map. Answers the question "does any key match this value?" Note that <c>value</c> is of type
        /// ADDataTypes. Cast your term into the appropriate type, i.e. <code>"term" |> ADString</code> or <code>1 |> ADInt</code>
        /// </summary>
        /// 
        static member public valuePresent (value: string) (results: LDAPSearchResult list) =
            results
            |> List.map(fun result ->
                let maps = result.ldapData
                let filteredMaps = maps |> List.filter(fun oneMap -> [for key in oneMap.Keys do yield oneMap[key] = [value]] |> List.contains true)
                {result with ldapData = filteredMaps})            
        
        // ///
        // /// <summary>
        // /// Filter LDAPSearchResults based upon the presence of a matching attribute and value. Note that
        // /// <c>value</c> is of type ADDataTypes. Cast your term into the appropriate type, i.e.
        // /// <code>"term" |> ADString</code> or <code>1 |> ADInt</code>
        // /// </summary>
        // /// <remarks>
        // /// The <c>value</c>
        // /// comparison is strict, as these comparisons operate on the <c>ADDataType</c>s so there's no regex or <c>
        // /// Contains</c> testing.
        // /// </remarks>
        // ///  
        // static member public attributeIsValue attr value (results: LDAPSearchResult list) =
        //     List.filter (fun p ->
        //         match p.lDAPSearcherError with
        //         | Some _ -> true
        //         | None -> (p.lDAPData.ContainsKey attr && p.lDAPData[attr] = value)) res
        //
        //
        // ///
        // /// <summary>
        // /// Filter LDAPSearchResults to return a single result. The result is a singleton List, to maintain
        // /// composability with the PrettyPrinter.
        // /// </summary>
        // /// <remarks>
        // /// I confess I don't understand the usefulness of this. I'm including it anyway because I anticipate
        // /// someone will ask for it and it's in PowerView.
        // /// </remarks>
        // /// 
        // static member public justOne (results: LDAPSearchResult list) = [List.head res]
        //
        //
        // ///
        // /// <summary>
        // /// Filter LDAPSearchResults by the specific WHOLE config used. This is useful with <c>Tee</c>s, allowing the
        // /// results of different searches to be split off for processing within that <c>Tee</c> based on the config.
        // /// </summary>
        // /// 
        // static member public byConfig config (results: LDAPSearchResult list) =
        //     List.filter (fun p ->
        //         match p.lDAPSearcherError with
        //         | Some _ -> true
        //         | None -> p.searchConfig = config) res
