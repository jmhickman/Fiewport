﻿namespace Fiewport

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
    type ADDataTypes =
        | ADInt64 of Int64 // confirmed
        | ADInt of int // confirmed
        | ADBool of bool // confirmed
        | ADBytes of byte array // confirmed
        | ADString of string // confirmed
        | ADDateTime of DateTime // confirmed
        | ADStrings of string list // confirmed
        | ADInt64List of Int64 list // unconfirmed datatype
        | ADIntList of int list // unconfirmed datatype
        | ADBoolList of bool list // unconfirmed datatype
        | ADDateTimes of DateTime list // confirmed
        | ADBytesList of byte array list // unconfirmed datatype
        //| ADComObject of ??  saw this referenced in some docs, haven't seen it yet
    
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
    type DirectorySearcherConfig =
        { properties: string array
          filter: string
          scope: System.DirectoryServices.SearchScope
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
    
    
    /// <summary>
    /// <para>
    /// Represents the result of an LDAP search. AD has 1507 unique attributes, and that's
    /// a few too many to individually add to a record. So aside from three
    /// always-present attrs, the rest are in a Map where they can be inspected manually.
    /// </para>
    /// <remarks>
    /// Storing the bulk of data as a Map adds overhead for scoped functions ("I only care about persons" or
    /// "I only care about GPOs") by checking any input LDAPSearchResult[s] for relevance. Total pipeline
    /// frictions are reduced though, and it doesn't prevent creating ad-hoc "verifiedThing" types if required.
    /// </remarks> 
    /// </summary>
    ///
    // consider adding a property that includes the search values in the record?
    // That seems like a good idea, to help easily group which queries came from what data
    type LDAPSearchResult =
        { searchType: LDAPSearchType 
          searchConfig: DirectorySearcherConfig
          objectClass: string list
          objectCategory: string
          objectGUID: Guid
          nTSecurityDescriptor: string
          LDAPSearcherError: string option
          LDAPData: Map<string, ADDataTypes> }
        
        
    ///
    /// <summary>
    /// A mild attempt to encode the various types of errors observed for LDAP searches
    /// during development. I'm sure there are more.
    /// </summary>
    type LDAPSearcherError =
        | ServerConnectionError of string
        | UnknownError80005000 of string
        | InvalidDNSyntax of string
        | NoSuchObject of string
        | OtherError of string


    ///
    /// A 'lightweight' (lazy) way to capture some Domain details without devolving into
    /// mutually recursive record definitions. Because no one has time for that.
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
        

    type IntermediateSearchResultsCollection = Result<SearchResultCollection * DirectorySearcherConfig, LDAPSearcherError * DirectorySearcherConfig>
            
    ///
    /// Setting up the Tee module    
    type Filter = LDAPSearchResult list -> LDAPSearchResult list
    
    ///
    /// Setting up the Tee module
    type Action = LDAPSearchResult -> unit