namespace Fiewport

module Tee =    
    
    type Tee = class end

        with

            ///
            /// <summary>
            /// <para>Tee.filter allows a specific filter (or sequence of filters) to be run against an incoming set of
            /// LDAPSearchResults, applying a unit function to the output, and then returning the original results for
            /// other uses. This function is side-effectful through the Action function.</para>
            /// <para>Example:</para>
            /// <code>[config]
            /// |> Searcher.getUsers
            /// |> Tee.filter (Filter.attributePresent "sAMAccountName") (prettyPrint "sam-path")
            /// |> Tee.filter (Filter.attributePresent "adminCount") (fileWriteAction "admin-path")
            /// |> ignore</code>
            /// </summary>
            static member filter (filter: Filter) (action: Action) (results: LDAPSearchResult list) =
                results |> filter |> List.iter action
                results
