namespace Fiewport

open Types

module Tee =


    /// TODO: Expand docstring to cover filter composition
    /// <summary>
    /// <para><c>Tee.filter</c> allows a specific filter (or sequence of filters) to be run against an incoming
    /// set of <c>LDAPSearchResults</c>, applying a unit function to the output, and then returning the original
    /// results for other uses. This function is side-effectful through the <c>Action</c> function.</para>
    /// <para>Example:</para>
    /// <code>[config]
    /// |> Searcher.getUsers
    /// |> Tee.filter (Filter.attributePresent "sAMAccountName") prettyPrint
    /// |> Tee.filter (Filter.attributePresent "adminCount") (fileWriteAction "admin-path")
    /// |> ignore</code>
    /// </summary>
    ///
    let filter (filter: Filter) (action: FilterAction) results =
        results |> filter |> action
        results


    ///
    /// <summary>
    /// <para><c>Tee.mold</c> allows a Mold (or sequence of filters ending in a Mold) to be run against an
    /// incoming set of <c>LDAPSearchResults</c>, applying a unit function to the output, and then returning
    /// the original results for other uses. This function is side-effectful through the <c>Action</c>
    /// function.</para>
    /// </summary>
    ///
    let mold (mold: Mold<'T>) (action: MoldAction<'T>) results =
        results |> mold |> action
        results

    // TODO: Is it worth it to add filterAndPrint?