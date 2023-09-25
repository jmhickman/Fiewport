namespace Fiewport

open Types
open LDAPRecords

module Filter =
    
    
    type Filter = class end
    
        with        
        
        static member attributePresent filterAttribute (res: LDAPSearchResult list) =
            List.filter (fun p -> p.LDAPData.ContainsKey filterAttribute) res

        static member valuePresent value (res: LDAPSearchResult list) =
            res
            |> List.filter(fun res' ->
                ADSIAttributes
                |> List.map (fun attr ->
                    match res'.LDAPData.ContainsKey attr with
                    | true -> res'.LDAPData[attr] = value
                    | false -> false)
                |> List.filter (fun p -> p = true)
                |> fun m -> m.Length > 0)
            
        static member attributeIsValue attr value (res: LDAPSearchResult list) =
            List.filter (fun p -> (p.LDAPData.ContainsKey attr && p.LDAPData[attr] = value)) res