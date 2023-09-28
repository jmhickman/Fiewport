namespace Fiewport

module Mold =
    
    type Mold = class end
    
        with        
        
        ///
        /// <summary>
        /// <para>Operates on lists of LDAPSearchResults to yield the corresponding values to the provided <c>key</c>. Returns
        /// a list of ADDataTypes.</para>
        /// <para>This function does not test for key presence, as it is intended for use after using a `Filter`.
        /// Be sure that your <c>key</c> is present if using it without <c>Filter</c>s.</para>
        /// </summary>
        static member getValues key (res: LDAPSearchResult list) =
            List.map (fun r -> r.LDAPData[key]) res


        ///
        /// <summary>
        /// Operates on a single <c>LDAPSearchResult</c> to yield the corresponding value to the provided <c>key</c>. Returns a
        /// string representing the value. Byte arrays aren't interpreted; if you know what the array represents, use
        /// the corresponding <c>ADData</c> method to unwrap it properly. This returns a string of hex bytes.
        /// </summary>
        static member getValue key (res: LDAPSearchResult) =
            match res.LDAPData[key] with
            | ADBool b -> $"{b}"
            | ADBytes b -> b |> Array.fold (fun acc b' -> acc + $"{b':x2}") ""
            | ADInt i -> $"{i}"
            | ADInt64 i -> $"{i}"
            | ADString s -> s
            | ADDateTime d -> d.ToShortDateString ()
            | ADStrings sList -> sList |> String.concat "; "
            | ADDateTimes dList -> dList |> List.map (fun d -> d.ToShortDateString ()) |> String.concat "; "
