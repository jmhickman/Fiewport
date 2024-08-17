namespace Fiewport

[<AutoOpen>]
module Mold =
    

    type Mold = class end
    
        with        
        
        static member public getKeys results =
            results
            |> List.map(fun result ->
                result.ldapData
                |> fun maps ->
                    maps
                    |> List.map(fun map -> [for key in map.Keys do yield key]))


        static member public getValues results =
            results
            |> List.map(fun result ->
                result.ldapData
                |> fun maps ->
                    maps
                    |> List.collect(fun map ->
                        [for key in map.Keys do yield map[key]]))
            
            
        static member public composeResults results =
           results
            |> List.collect(fun result ->
                result.ldapData
                |> fun maps ->
                    maps
                    |> List.collect(fun map ->
                        [for key in map.Keys do yield key,map[key]]))