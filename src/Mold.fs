namespace Fiewport

module Mold =

    ///
    /// <summary>
    /// <para><c>Mold.getKeys</c> allows the user to directly access the keys that were
    /// returned in a given search. This is a deeply nested string list with the same
    /// shape as the original results, just with the values omitted.</para>
    /// <para>Example:</para>
    /// <code>[config]
    /// |> Searcher.getUsers
    /// |> Mold.getKeys
    /// |> someCustomFunction
    /// |> ignore</code>
    /// </summary>
    ///
    let getKeys results =
        results
        |> List.map(fun result ->
            result.ldapData
            |> fun maps ->
                maps
                |> List.map(fun map -> [for key in map.Keys do yield key]))


    ///
    /// <summary>
    /// <para><c>Mold.getValues</c> allows the user to directly access the values that were
    /// returned in a given search. This is a deeply nested string list with the same
    /// shape as the original results, just with the keys omitted.</para>
    /// <para>Example:</para>
    /// <code>[config]
    /// |> Searcher.getUsers
    /// |> Mold.getValues
    /// |> someCustomFunction
    /// |> ignore</code>
    /// </summary>
    ///
    let getValues results =
        results
        |> List.map(fun result ->
            result.ldapData
            |> fun maps ->
                maps
                |> List.collect(fun map ->
                    [for key in map.Keys do yield map[key]]))



    ///
    /// <summary>
    /// <para><c>Mold.composeResults</c> allows the user to directly access the keys and values
    /// that were returned in a given search. This is a list-ified version of data with the
    /// same shape as the original results.</para>
    /// <para>Example:</para>
    /// <code>[config]
    /// |> Searcher.getUsers
    /// |> Mold.composeResults
    /// |> someCustomFunction
    /// |> ignore</code>
    /// </summary>
    ///
    let composeResults results =
       results
        |> List.collect(fun result ->
            result.ldapData
            |> fun maps ->
                maps
                |> List.collect(fun map ->
                    [for key in map.Keys do yield key,map[key]]))


    ///
    /// <summary>
    /// <para><c>Mold.extractOccurances</c> allows the user to directly extract a specific key and
    ///  value pair, for all occurances of that key in the dataset.</para>
    /// <para>Example:</para>
    /// <code>[config]
    /// |> Searcher.getUsers
    /// |> Mold.extractOccurances "ou"
    /// |> someCustomFunction
    /// |> ignore</code>
    /// </summary>
    ///
    let extractOccurances key results =
        results
        |> List.collect (fun result ->
            result.ldapData
            |> List.collect (fun map ->
                Map.tryFind key map
                |> Option.defaultValue []))