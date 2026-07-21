namespace Fiewport

module Mold =


    let getKeys results =
        results
        |> List.map(fun result ->
            result.ldapData
            |> fun maps ->
                maps
                |> List.map(fun map -> [for key in map.Keys do yield key]))


    let getValues results =
        results
        |> List.map(fun result ->
            result.ldapData
            |> fun maps ->
                maps
                |> List.collect(fun map ->
                    [for key in map.Keys do yield map[key]]))


    let composeResults results =
       results
        |> List.collect(fun result ->
            result.ldapData
            |> fun maps ->
                maps
                |> List.collect(fun map ->
                    [for key in map.Keys do yield key,map[key]]))
