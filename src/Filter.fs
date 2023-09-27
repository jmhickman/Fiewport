namespace Fiewport

open Types
open LDAPConstants

module Filter =    
    
    type Filter = class end
    
        with        

        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied `filterAttribute` key in the
        /// LDAPData map.
        /// </summary>
        static member public attributePresent filterAttribute (res: LDAPSearchResult list) =
            List.filter (fun p -> p.LDAPData.ContainsKey filterAttribute) res

        
        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied value 'value' for any key in the
        /// LDAPData Map.
        /// </summary>
        static member public valuePresent value (res: LDAPSearchResult list) =
            res
            |> List.filter(fun res' ->
                [for key in res'.LDAPData.Keys do yield key]
                |> List.map (fun attr -> res'.LDAPData[attr] = value)
                |> List.filter (fun p -> p = true)
                |> fun m -> m.Length > 0)
            
        
        ///
        /// <summary>
        /// Filter LDAPSearchResults based upon the presence of a matching attribute and value.
        /// </summary>
        static member public attributeIsValue attr value (res: LDAPSearchResult list) =
            List.filter (fun p -> (p.LDAPData.ContainsKey attr && p.LDAPData[attr] = value)) res