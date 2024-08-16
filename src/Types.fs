namespace Fiewport

open System.DirectoryServices.ActiveDirectory
open System.DirectoryServices.Protocols

[<AutoOpen>]
module Types =
    open System

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
    type SearcherConfig =
        { properties: string array
          filter: string
          ldapDN: string
          scope: SearchScope
          ldapHost: string
          username: string
          password: string }
        
    ///
    /// <summary>Defines the batteries-included searches</summary> 
    type LDAPSearchType =
        | GetUsers
        | GetComputers
        | GetSites
        | GetOUs
        | GetGroups
        | GetDomainDNSZones
        | GetDNSRecords
        | GetDomainSubnets
        | GetDFSShares
        | GetGroupPolicyObjects
        | GetDomainTrusts
        | GetDomainObjects
        | GetDomainControllers
        | GetHostsTrustedForDelegation
        | GetReportedServersNotDC
        | GetContainers
        | GetUsersWithSPNs
        | GetConstrainedDelegates
        | GetASREPTargets
        | GetKerberoastTargets
        | GetProtectedUsers
        | GetGroupsWithLocalAdminRights
    
    
    ///
    /// <summary>
    /// Represents the result of an LDAP search. An AD has an arbitrary number of attributes, and all
    /// results are stored in the <c>Map</c>.
    /// </summary>
    ///
    type LDAPSearchResult =
        { searchType: LDAPSearchType 
          searchConfig: SearcherConfig
          ldapSearcherError: string option
          ldapData: Map<string, string list> list }

    
    ///
    /// <summary>Defines a Filter for the <c>Tee</c></summary>    
    type Filter = LDAPSearchResult list -> LDAPSearchResult list
    
    
    ///
    /// <summary>Defines a Mold for the <c>Tee</c></summary>    
    type Mold<'T> = LDAPSearchResult list -> 'T list
    
    
    ///
    /// <summary>Defines a FilterAction for the <c>Tee</c></summary>    
    type FilterAction = LDAPSearchResult -> unit
    
    
    ///
    /// <summary>Defines a MoldAction for the <c>Tee</c></summary>    
    type MoldAction<'T> = 'T -> unit
