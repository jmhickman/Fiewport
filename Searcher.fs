namespace Fiewport

open System.DirectoryServices
open Types
open DomainSearcher

module Searcher =
    
    ///
    /// Linkage to DomainSearcher module
    let private configureDomainConnection (config: DirectorySearcherConfig) =
        (getDomainConnection config.ldapDomain config.username config.password), config
        
    
    ///
    /// Linkage to DomainSearcher module    
    let private configureSearcher (domainAndConfig: DirectoryEntry * DirectorySearcherConfig) =
        let domain, config = domainAndConfig
        getDomainSearcher config domain
        
    
    ///
    /// Calls FindAll() on the DirectorySearcher, encodes some of the ways it can blow up
    let private findAll (searcher: DirectorySearcher) =
        try
            searcher.FindAll() |> Ok
        with
            exn ->
                match exn with
                | x when x.Message = "The server is not operational." -> x.Message |> ServerConnectionError |> Error
                | x when x.Message = "Unknown error (0x80005000)" -> x.Message |> UnknownError80005000 |> Error
                | x when x.Message = "An invalid dn syntax has been specified." -> x.Message |> InvalidDNSyntax |> Error
                | x when x.Message = "There is no such object on the server." -> x.Message |> NoSuchObject |> Error
                | x -> x.Message |> OtherError |> Error
    
    
    ///
    /// Composed pipeline of 'doing the search.'
    let doSearch = configureDomainConnection >> configureSearcher >> findAll
    
    ///
    /// <summary>
    /// <para>
    /// A Searcher is an abstraction around a group of pre-defined 'most-common' LDAP searches. All methods take a
    /// DirectorySearcherConfig list. This allows some flexibility around the number of domains or so-called
    /// 'SearchBase' locations in the LDAP hierarchy the user can query at once.
    /// </para>
    /// <para>
    /// The tradeoff is that this is a 'noisy' way of doing multiple AD searches, because it isn't using a cached query
    /// across multiple searches. This repetitive querying is easy to detect for defenders. So a Searcher is for when
    /// stealthiness isn't a concern. 
    /// </para>
    /// <para>
    /// All of the filters predefined in these methods are logical OR, allowing for the widest net to be cast for
    /// results. Fiewport supplies a battery of filters that allow you to dig into the data and extract the results
    /// you want, rather than crafting very narrow queries. However, passing a filter value in the
    /// DirectorySearcherConfig causes it to be appended to the end of the pre-built filter. The LDAP connection string
    /// passed via the `ldapDomain` value is respected as well, if you want the search restricted to certain containers.
    /// </para>
    /// 
    /// </summary>
    type Searcher = class end
        with
        
        
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all users using the filter
        /// <code>(|(objectCategory=person)(objectCategory=user)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        /// 
        static member getUsers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=person)(objectCategory=user){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all computers using the filter
        /// <code>(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member getComputers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all sites using the basic filter
        /// <code>(|(objectClass=site)</code>
        /// and LDAP connection
        /// <code>CN=Sites,CN=Configuration,[DC=domain...]</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///        
        static member getSites (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectClass=site){c.filter})"""
                        ldapDomain = $"""{c.ldapDomain}/CN=Sites,CN=Configuration,{deriveDistinguishedString c.ldapDomain}""" })
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all organization units using the filter
        /// <code>(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///            
        static member getOUs (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults


        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain groups using the filter
        /// <code>(|(objectCategory=group)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member getGroups (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=group){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
        
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain DNS zones using the filter
        /// <code>(|(objectClass=dnsZone)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member getDomainDNSZones (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=dnsZone){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
        
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain DNS records using the filter
        /// <code>(|(objectClass=dnsnode)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member getDNSRecords (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=dnsnode){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults


        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain subnets using the filter
        /// <code>(|(siteObject=*)</code>
        /// and LDAP connection
        /// <code>CN=Subnets,CN=Sites,CN=Configuration,[DC=domain...]</code> 
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member getDomainSubnets (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(siteObject=*){c.filter})"""
                        ldapDomain = $"""{c.ldapDomain}/CN=Subnets,CN=Sites,CN=Configuration,{deriveDistinguishedString c.ldapDomain}""" })
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all published DFS shares via two different searches using filters
        /// <code>(|(objectClass=fTDfs)</code>
        /// and
        /// <code>(|(objectClass=msDFS-Linkv2)</code>
        /// which are combined into one list.
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member getDFSShares (config: DirectorySearcherConfig list) =
            let part1 =
                config
                |> List.map (fun c -> {c with filter = $"""(|(objectClass=fTDfs){c.filter})"""})
                |> List.map doSearch
                |> List.collect createLDAPSearchResults
            let part2 =
                config
                |> List.map (fun c -> {c with filter = $"""(|(objectClass=msDFS-Linkv2){c.filter})"""})
                |> List.map doSearch
                |> List.collect createLDAPSearchResults
            part1 @ part2
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain group policy objects using the filter
        /// <code>(|(objectCategory=groupPolicyContainer)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///        
        static member getGroupPolicyObjects (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectCategory=groupPolicyContainer){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain trusts using the filter
        /// <code>(|(objectClass=trustedDomain)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///        
        static member getDomainTrusts (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectClass=trustedDomain){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain objects matching the user-supplied filter from
        /// the DirectorySearcherConfig. This is the method to use if you want full control over the search logic.
        /// </summary>
        ///
        static member getDomainObjects (config: DirectorySearcherConfig list) =
            config
            |> List.map doSearch
            |> List.collect createLDAPSearchResults