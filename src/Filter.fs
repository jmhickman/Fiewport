namespace Fiewport

module Filter =

    open System


    ///
    /// Keep only attributes whose names appear in <c>attrs</c> (case-insensitive).
    /// Useful after a broad search to reduce noise, or with <c>AttributeBatteries</c>.
    ///
    let private retainListedAttributes (wanted: Set<string>) (oneMap: LDAPEntryData) : LDAPEntryData =
        oneMap
        |> Map.filter (fun key _ -> wanted.Contains (key.ToLowerInvariant()))


    ///
    /// True when any value under any attribute contains <c>needle</c> (case-insensitive substring).
    ///
    let private mapValueContains (needle: string) (oneMap: LDAPEntryData) : bool =
        oneMap
        |> Map.exists (fun _ values ->
            values
            |> List.exists (fun value -> value.Contains(needle, StringComparison.OrdinalIgnoreCase)))


    ///
    /// <summary>
    /// Filters LDAPSearchResults based upon the presence of the supplied <c>filterAttribute</c> key in the
    /// LDAPData map.
    /// </summary>
    let attributePresent attr (results: LDAPSearchResult list) =
        results
        |> List.map (fun result ->
            let filteredMaps =
                result.ldapData
                |> List.filter (fun oneMap -> oneMap.ContainsKey attr)
            { result with ldapData = filteredMaps })


    ///
    /// <summary>
    /// Filters LDAPSearchResults based upon <c>value</c> being present in any key in the ldapData Map. Will return
    /// only Maps where the <c>value</c> matched.
    /// </summary>
    ///
    let valueIs (value: string) (results: LDAPSearchResult list) =
        results
        |> List.map (fun result ->
            let filteredMaps =
                result.ldapData
                |> List.filter (fun oneMap ->
                    oneMap
                    |> Map.exists (fun _ values -> values = [value]))
            { result with ldapData = filteredMaps })


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
    let byConfig (config: LdapSearchConfig) (results: LDAPSearchResult list) =
        results
        |> List.filter (fun p ->
            match p.ldapSearcherError with
            | Some _ -> true
            | None -> p.searchConfig = config)


    ///
    /// <summary>
    /// Client-side attribute projection: keep only the named attributes on each entry.
    /// Names are matched case-insensitively against decoded map keys.
    /// Pass any <c>string array</c> — including <c>AttributeBatteries.terse</c>,
    /// <c>standard</c>, <c>verbose</c>, or a custom list.
    /// </summary>
    ///
    let showMany (attrs: string array) (results: LDAPSearchResult list) =
        let wanted =
            attrs
            |> Array.map (fun a -> a.ToLowerInvariant())
            |> Set.ofArray
        results
        |> List.map (fun result ->
            let filteredMaps =
                result.ldapData
                |> List.map (retainListedAttributes wanted)
            { result with ldapData = filteredMaps })


    ///
    /// <summary>
    /// Keep only entries where <c>needle</c> appears as a substring of <b>any</b> attribute value
    /// (case-insensitive). Whole matching entries are retained with all of their attributes.
    /// Chain multiple calls with <c>Tee</c> when hunting several keywords.
    /// </summary>
    ///
    let attributeValueContains (needle: string) (results: LDAPSearchResult list) =
        results
        |> List.map (fun result ->
            let filteredMaps =
                result.ldapData
                |> List.filter (mapValueContains needle)
            { result with ldapData = filteredMaps })
