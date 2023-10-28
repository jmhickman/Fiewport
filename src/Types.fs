namespace Fiewport

open System.DirectoryServices.ActiveDirectory
open System.DirectoryServices

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
        | ADInt64 of Int64 
        | ADInt of int 
        | ADBool of bool 
        | ADBytes of byte array 
        | ADString of string 
        | ADDateTime of DateTime 
        | ADStringList of string list 
        | ADDateTimeList of DateTime list 
        | ADBytesList of byte array list
    
    ///
    /// <summary>Defines a DirectorySearcher aside from the DirectoryEntry</summary>
    /// <param name="properties">an array indicating the attributes to retain from a search.
    /// All other attributes will be omitted, even if they are present.</param>
    /// <param name="filter">The LDAP filter string. Not case sensitive</param>
    /// <param name="scope">One of the three values of the enum SearchScope</param>
    /// <param name="ldapDomain">The AD to attach to, in the form "LDAP://domain.tld" or
    /// "LDAP://domain.tld/CN=Some,CN=Container,DC=domain,DC=tld"</param>
    /// <param name="username">Username used to connect to the AD</param>
    /// <param name="password">Password used to connect to the AD</param>
    /// 
    type DirectorySearcherConfig =
        { properties: string array
          filter: string
          scope: SearchScope
          ldapDomain: string
          username: string
          password: string }
        
        
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
    
    
    type HumanSDDL =
        { owner: string
          group: string
          dacl: string list }
    
    
    ///
    /// <summary>
    /// Represents the result of an LDAP search. AD has 1507 unique attributes, and that's
    /// a few too many to individually add to a record. Most are stored in the <c>Map</c> but a few are
    /// available from the top of the record.
    /// </summary>
    ///
    type LDAPSearchResult =
        { searchType: LDAPSearchType 
          searchConfig: DirectorySearcherConfig
          lDAPSearcherError: string option
          lDAPData: Map<string, ADDataTypes> }
        
        
    ///
    /// <summary>
    /// A mild attempt to encode the various types of errors observed for LDAP searches
    /// during development. I'm sure there are more.
    /// </summary>
    /// 
    type LDAPSearcherError =
        | ServerConnectionError of string
        | UnknownError80005000 of string
        | InvalidDNSyntax of string
        | NoSuchObject of string
        | OtherError of string


    ///
    /// A 'lightweight' (lazy) way to capture some Domain details without devolving into
    /// mutually recursive record definitions. Because no one has time for that.
    /// 
    type ActiveDirectoryDomain =
        { children: string list
          domainControllers: string list
          domainMode: DomainMode
          domainModeLevel: int
          forest: string
          infrastructureRoleOwner: string
          name: string
          parent: string option
          pdcRoleOwner: string
          ridRoleOwner: string }
            
    
    ///
    /// Setting up the Tee module    
    type Filter = LDAPSearchResult list -> LDAPSearchResult list
    
    
    ///
    /// Setting up the Tee module
    type Mold<'T> = LDAPSearchResult list -> 'T list
    
    
    ///
    /// Setting up the Tee module
    type FilterAction = LDAPSearchResult -> unit
    
    
    ///
    /// Setting up the Tee module
    type MoldAction<'T> = 'T -> unit
