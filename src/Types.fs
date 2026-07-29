namespace Fiewport

[<AutoOpen>]
module Types =
    // Allow test cases to function
    [<assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Fiewport.Tests")>]
    do ()
    
    open MessagePack

    /// <summary>Search scope for LDAP queries.</summary>
    type SearchScope =
        | Base
        | OneLevel
        | Subtree

    ///
    /// <summary>Representation of unboxed data from an LDAP query.</summary>
    /// <remarks>Some of these datatypes are speculation and aren't confirmed in real results.
    /// I have access to a limited AD that is very simplistic, so verifying all of these is likely
    /// impossible for me alone.
    /// </remarks>
    /// 
    type internal ADDataTypes =       
        | ADBytes of byte array 
        | ADString of string 
        
    
    ///
    /// <summary>
    /// Authentication credentials for LDAP connection.
    /// Lives only in the connection layer — never serialized, never persisted.
    /// </summary>
    ///
    type LdapCredentials =
        { username: string
          password: string }

    ///
    /// <summary>
    /// Serializable LDAP search configuration — no credentials, safe to persist.
    /// Embedded in <c>LDAPSearchResult</c> for downstream analysis of search parameters.
    /// </summary>
    ///
    [<MessagePackObject>]
    type LdapSearchConfig =
        { [<Key(0)>] properties: string array
          [<Key(1)>] filter: string
          [<Key(2)>] ldapDN: string
          [<Key(3)>] scope: SearchScope
          [<Key(4)>] ldapHost: string
          [<Key(5)>] ldapPort: int
          [<Key(6)>] useSsl: bool }

    ///
    /// <summary>
    /// Public-facing config: wraps the LDAP details with credentials.
    /// Consumed at the connection boundary; credentials are stripped before
    /// the config enters the serializable pipeline.
    /// </summary>
    ///
    type SearcherConfig =
        { ldapDetails: LdapSearchConfig
          credentials: LdapCredentials }
        
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
        | [<Key(23)>] GetGroupMembers
        | [<Key(24)>] GetGMSAs
        | [<Key(25)>] GetUsersWithSidHistory
        | [<Key(26)>] GetUsersWithAdminCount
        | [<Key(27)>] GetMachineAccountQuota
        | [<Key(28)>] GetForestDomains
        | [<Key(29)>] GetForestGlobalCatalogs
        | [<Key(30)>] GetForestTrusts
        | [<Key(31)>] GetDomainSID
    
    
    ///
    /// <summary>Represents a single LDAP entry as a map of attribute names to decoded string values.</summary>
    ///
    type internal LDAPEntryData = Map<string, string list>


    ///
    /// <summary>Represents an error from the LDAP infrastructure layer.</summary>
    /// <param name="context">Where the error occurred: "bind", "search", or "iterate".</param>
    ///
    [<MessagePackObject>]
    type LdapError =
        { [<Key(0)>]message: string
          [<Key(1)>]context: string }


    ///
    /// <summary>
    /// Represents the result of an LDAP search. An AD has an arbitrary number of attributes, and all
    /// results are stored in the <c>Map</c>.
    /// </summary>
    ///
    [<MessagePackObject>]
    type LDAPSearchResult =
        { [<Key(0)>]searchType: LDAPSearchType 
          [<Key(1)>]searchConfig: LdapSearchConfig
          [<Key(2)>]ldapSearcherError: LdapError option
          [<Key(3)>]ldapData: LDAPEntryData list }

    
    ///
    /// <summary>Defines a Filter for the <c>Tee</c></summary>    
    type Filter = LDAPSearchResult list -> LDAPSearchResult list
    
    
    ///
    /// <summary>Defines a Mold for the <c>Tee</c></summary>    
    type Mold<'T> = LDAPSearchResult list -> 'T
    
    
    ///
    /// <summary>Defines a FilterAction for the <c>Tee</c></summary>    
    type FilterAction = LDAPSearchResult list -> unit
    
    
    ///
    /// <summary>Defines a MoldAction for the <c>Tee</c></summary>    
    type MoldAction<'T> = 'T -> unit


