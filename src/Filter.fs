namespace Fiewport

[<AutoOpen>]
module Filter =
    
    type Filter = class end
    
        with        

        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied <c>filterAttribute</c> key in the
        /// LDAPData map.
        /// </summary>
        static member public attributePresent filterAttribute (res: LDAPSearchResult list) =
            List.filter (fun p -> p.lDAPData.ContainsKey filterAttribute) res

        
        ///
        ///<summary>
        /// Filters LDAPSearchResults based upon the presence of the supplied value <c>value</c> for any key in the
        /// LDAPData Map. Answers the question "does any key match this value?" Note that <c>value</c> is of type
        /// ADDataTypes. Cast your term into the appropriate type, i.e. <code>"term" |> ADString</code> or <code>1 |> ADInt</code>
        /// </summary>
        /// 
        static member public valuePresent value (res: LDAPSearchResult list) =
            res
            |> List.filter(fun res' ->
                [for key in res'.lDAPData.Keys do yield key]
                |> List.map (fun attr -> res'.lDAPData[attr] = value)
                |> List.filter (fun p -> p = true)
                |> fun m -> m.Length > 0)
            
        
        ///
        /// <summary>
        /// Filter LDAPSearchResults based upon the presence of a matching attribute and value. Note that
        /// <c>value</c> is of type ADDataTypes. Cast your term into the appropriate type, i.e.
        /// <code>"term" |> ADString</code> or <code>1 |> ADInt</code>
        /// </summary>
        /// <remarks>
        /// The <c>value</c>
        /// comparison is strict, as these comparisons operate on the <c>ADDataType</c>s so there's no regex or <c>
        /// Contains</c> testing.
        /// </remarks>
        ///  
        static member public attributeIsValue attr value (res: LDAPSearchResult list) =
            List.filter (fun p -> (p.lDAPData.ContainsKey attr && p.lDAPData[attr] = value)) res
