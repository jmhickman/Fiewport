namespace Fiewport

module Types =
    open System

    ///
    /// Representation of unboxed data from an LDAP query.
    type ADDataTypes =
        | ADInt64 of Int64 // confirmed
        | ADInt of int // confirmed
        | ADBytes of byte array // confirmed
        | ADString of string // confirmed
        | ADDateTime of DateTime // confirmed
        | ADStrings of string list // confirmed
        | ADInt64List of Int64 list // have you seen this datatype?
        | ADIntList of int list // have you seen this datatype?
        | ADDateTimes of DateTime list // confirmed
        | ADBytesList of byte array list // have you seen this datatype?
        //| ADComObject of ??
    
    ///
    /// Defines the non-DirectoryEntry parts of a DirectorySearcher
    type DirectorySearcherConfig =
        { properties: string array
          filter: string
          scope: System.DirectoryServices.SearchScope }
    
    
    /// <summary>
    /// <para>
    /// Represents the result of an LDAP search. AD has 1507 unique attributes, and that's
    /// a few(!) hundred too many to individually add to a record. So aside from these three
    /// always-present attrs, the rest are in a Map where they can be inspected manually.
    /// </para>
    /// <remarks>
    /// Storing the bulk of data as a Map adds overhead for scoped functions ("I only care about persons" or
    /// "I only care about GPOs") checking the input LDAPSearchResults for relevance. Total friction is reduced
    ///  though, and it doesn't prevent creating ad-hoc "verifiedThing" types if required.
    /// </remarks> 
    /// </summary>
    ///  
    type LDAPSearchResult =
        { objectClass: string list
          objectCategory: string
          objectGUID: byte array
          LDAPData: Map<string, ADDataTypes> }