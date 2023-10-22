namespace Fiewport

[<AutoOpen>]
module Mold =
    
    let private valueToString key res =
        match res.lDAPData[key] with
        | ADBool b -> $"{b}"
        | ADBytes b -> b |> Array.fold (fun acc b' -> acc + $"{b':x2}") ""
        | ADInt i -> $"{i}"
        | ADInt64 i -> $"{i}"
        | ADString s -> s
        | ADDateTime d -> d.ToShortDateString ()
        | ADStringList sList -> sList |> String.concat "; "
        | ADDateTimeList dList -> dList |> List.map (fun d -> d.ToShortDateString ()) |> String.concat "; "
        | ADBytesList bList -> bList |> List.map (fun b -> b |> Array.fold (fun acc b' -> acc + $"{b':x2}") "") |> String.concat ", "
    
    type Mold = class end
    
        with        
        
        ///
        /// <summary>
        /// <para>Operates on lists of LDAPSearchResults to yield the corresponding values to the provided <c>key</c>.
        /// Returns a list of ADDataTypes.</para>
        /// <para>This function does not test for key presence, as it is intended for use after using a `Filter`.
        /// Be sure that your <c>key</c> is present if using it without <c>Filter</c>s.</para>
        /// </summary>
        /// 
        static member public getValues key res =
            List.map (fun r -> r.lDAPData[key]) res


        static member internal getKeys res =
            [for key in res.lDAPData.Keys do yield key]
            
            
        ///
        /// <summary>
        /// Add keys that support custom logic for your use-case to the <c>lDAPData</c> map in a list of
        /// <c>LDAPSearchResult</c>s.
        /// </summary>
        ///         
        static member public addKeys keys res =
            // Too smoothbrained to get this expressed as a fold. This is probably clearer anyway.
            let rec addKeys keys acc =
                match keys with
                | [] -> acc
                | head::tail -> addKeys tail {acc with lDAPData = acc.lDAPData.Add head}
                
            res |> List.map (addKeys keys)
        
        
        ///
        /// <summary>
        /// Remove keys that aren't important to your use-case from the <c>lDAPData</c> map in a list of
        /// <c>LDAPSearchResult</c>s.
        /// </summary>
        /// 
        static member public removeKeys keys res =
            // Too smoothbrained to get this expressed as a fold. This is probably clearer anyway.
            let rec removeKeys keys acc =
                match keys with
                | [] -> acc
                | head::tail -> removeKeys tail {acc with lDAPData = acc.lDAPData.Remove head}
                
            res |> List.map (removeKeys keys)
        
        
        ///
        /// <summary>
        /// Operates on a single <c>LDAPSearchResult</c> to yield the corresponding value to the provided <c>key</c>.
        /// Returns a string representing the value. Byte arrays aren't interpreted; if you know what the array
        /// represents, use the corresponding <c>ADData</c> method to unwrap it properly. This returns a string of hex
        /// bytes. Leaving this internal for now.
        /// </summary>
        /// 
        static member internal getValue key (res: LDAPSearchResult) =
            res |> valueToString key


        /// Temporary testing function, will be subsumed by the prettyprinter
        static member internal dumpKeysAndValues (res: LDAPSearchResult) =
            [for key in res.lDAPData.Keys do yield $"{key}::{valueToString key res}"]