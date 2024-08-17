namespace Fiewport

[<AutoOpen>]
module Types =
    open System.DirectoryServices.Protocols
    
    open MessagePack

    ///
    /// <summary>Representation of unboxed data from an LDAP query.</summary>
    /// <remarks>Some of these datatypes are speculation and aren't confirmed in real results.
    /// I have access to a limited AD that is very simplistic, so verifying all of these is likely
    /// impossible for me alone.
    /// </remarks>
    /// 
    type ADDataTypes =       
        | ADBytes of byte array 
        | ADString of string 
        
    
    ///
    /// <summary>Defines a DirectorySearcher</summary>
    /// <param name="properties">an array indicating the attributes to retain from a search.
    /// All other attributes will be omitted, even if they are present.</param>
    /// <param name="filter">The LDAP filter string. Not case sensitive</param>
    /// <param name="scope">One of the three values of the enum SearchScope</param>
    /// <param name="ldapDomain">The AD to attach to, in the form "LDAP://domain.tld" or
    /// "LDAP://domain.tld/CN=Some,CN=Container,DC=domain,DC=tld"</param>
    /// <param name="username">Username used to connect to the AD</param>
    /// <param name="password">Password used to connect to the AD</param>
    /// 
    [<MessagePackObject>]
    type SearcherConfig =
        { [<Key(0)>]properties: string array
          [<Key(1)>]filter: string
          [<Key(2)>]ldapDN: string
          [<Key(3)>]scope: SearchScope
          [<Key(4)>]ldapHost: string
          [<Key(5)>]username: string
          [<Key(6)>]password: string }
        
    ///
    /// <summary>Defines the batteries-included searches</summary> 
    [<MessagePackObject>]
    type LDAPSearchType =
        | [<Key(0)>] GetUsers
        | [<Key(1)>] GetComputers
        | [<Key(2)>] GetSites
        | [<Key(3)>] GetOUs
        | [<Key(4)>] GetGroups
        | [<Key(5)>] GetDomainDNSZones
        | [<Key(6)>] GetDNSRecords
        | [<Key(7)>] GetDomainSubnets
        | [<Key(8)>] GetDFSShares
        | [<Key(9)>] GetGroupPolicyObjects
        | [<Key(10)>] GetDomainTrusts
        | [<Key(11)>] GetDomainObjects
        | [<Key(12)>] GetDomainControllers
        | [<Key(13)>] GetHostsTrustedForDelegation
        | [<Key(14)>] GetReportedServersNotDC
        | [<Key(15)>] GetContainers
        | [<Key(16)>] GetUsersWithSPNs
        | [<Key(17)>] GetConstrainedDelegates
        | [<Key(18)>] GetASREPTargets
        | [<Key(19)>] GetKerberoastTargets
        | [<Key(20)>] GetProtectedUsers
        | [<Key(21)>] GetGroupsWithLocalAdminRights
        | [<Key(22)>] DumpAD
    
    
    ///
    /// <summary>
    /// Represents the result of an LDAP search. An AD has an arbitrary number of attributes, and all
    /// results are stored in the <c>Map</c>.
    /// </summary>
    ///
    [<MessagePackObject>]
    type LDAPSearchResult =
        { [<Key(0)>]searchType: LDAPSearchType 
          [<Key(1)>]searchConfig: SearcherConfig
          [<Key(2)>]ldapSearcherError: string option
          [<Key(3)>]ldapData: Map<string, string list> list }

    
    ///
    /// <summary>Defines a Filter for the <c>Tee</c></summary>    
    type Filter = LDAPSearchResult list -> LDAPSearchResult list
    
    
    ///
    /// <summary>Defines a Mold for the <c>Tee</c></summary>    
    type Mold<'T> = LDAPSearchResult list -> 'T
    
    
    ///
    /// <summary>Defines a FilterAction for the <c>Tee</c></summary>    
    type FilterAction = LDAPSearchResult -> unit
    
    
    ///
    /// <summary>Defines a MoldAction for the <c>Tee</c></summary>    
    type MoldAction<'T> = 'T -> unit
