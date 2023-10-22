namespace Fiewport

open System.DirectoryServices
open Types
open DomainSearcher

[<AutoOpen>]
module Searcher =
    
    ///
    /// Linkage to DomainSearcher module
    let private configureDomainConnection (config: DirectorySearcherConfig) =
        (getDomainConnection config.ldapDomain config.username config.password), config
        
    
    ///
    /// Linkage to DomainSearcher module    
    let private configureSearcher (domainAndConfig: DirectoryEntry * DirectorySearcherConfig) =
        let domain, config = domainAndConfig
        (getDomainSearcher config domain, config )
        
    
    ///
    /// Calls FindAll() on the DirectorySearcher, encodes some of the ways it can blow up
    let private findAll (searcherAndConfig: DirectorySearcher * DirectorySearcherConfig) =
        let searcher, config = searcherAndConfig
        try
            (searcher.FindAll(), {config with password = ""} ) |> Ok
        with
            exn ->
                match exn with
                | x when x.Message = "The server is not operational." -> x.Message |> ServerConnectionError|> (fun e -> e, {config with password = ""}) |> Error
                | x when x.Message = "Unknown error (0x80005000)" -> x.Message |> UnknownError80005000 |> (fun e -> e, {config with password = ""})|> Error
                | x when x.Message = "An invalid dn syntax has been specified." -> x.Message |> InvalidDNSyntax|> (fun e -> e, {config with password = ""}) |> Error
                | x when x.Message = "There is no such object on the server." -> x.Message |> NoSuchObject |> (fun e -> e, {config with password = ""})|> Error
                | x -> x.Message |> OtherError |> (fun e -> e, {config with password = ""}) |> Error
    
    
    ///
    /// Composed pipeline of 'doing the search.'
    let private doSearch = configureDomainConnection >> configureSearcher >> findAll
    
    ///
    /// <summary>
    /// <para>
    /// A Searcher is an abstraction around a group of pre-defined 'most-common' LDAP searches. All methods take a
    /// DirectorySearcherConfig list. This allows some flexibility around the number of domains or so-called
    /// 'SearchBase' locations in the LDAP hierarchy the user can query at once.
    /// </para>
    /// <para>
    /// To get stealthier behavior, use <c>getDomainObjects</c> with a filter like <c>objectClass=*</c> and save the results
    /// to a value, and then use the value in multiple operations. Alternatively, use the <c>Tee</c> module to perform multiple
    /// filtering/molding operations per search.
    /// </para>
    /// <para>
    /// Most of the filters predefined in these methods use logical <c>OR</c>, allowing for the widest net to be cast for
    /// results. Fiewport supplies a battery of filters that allow you to dig into the data and extract the results
    /// you want, rather than crafting very narrow queries. However, passing a filter value in the
    /// DirectorySearcherConfig causes it to be appended to the end of the pre-built filter. The LDAP connection string
    /// passed via the `ldapDomain` value is respected as well, if you want the search restricted to a certain path.
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
        static member public getUsers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=person)(objectCategory=user){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetUsers)

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all computers using the filter
        /// <code>(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member public getComputers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetComputers)
            

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all sites using the basic filter
        /// <code>(|(objectClass=site)</code>
        /// and LDAP connection
        /// <code>CN=Sites,CN=Configuration,[DC=domain...]</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///        
        static member public getSites (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectClass=site){c.filter})"""
                        ldapDomain = $"""{c.ldapDomain}/CN=Sites,CN=Configuration,{deriveDistinguishedString c.ldapDomain}""" })
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetSites)
            

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all organization units using the filter
        /// <code>(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///            
        static member public getOUs (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetOUs)


        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain groups using the filter
        /// <code>(|(objectCategory=group)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member public getGroups (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=group){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetGroups)
            
        
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain DNS zones using the filter
        /// <code>(|(objectClass=dnsZone)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member public getDomainDNSZones (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=dnsZone){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetDomainDNSZones)
            
        
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain DNS records using the filter
        /// <code>(|(objectClass=dnsnode)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member public getDNSRecords (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=dnsnode){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetDNSRecords)


        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain subnets using the filter
        /// <code>(|(siteObject=*)</code>
        /// and LDAP connection
        /// <code>CN=Subnets,CN=Sites,CN=Configuration,[DC=domain...]</code> 
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member public getDomainSubnets (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(siteObject=*){c.filter})"""
                        ldapDomain = $"""{c.ldapDomain}/CN=Subnets,CN=Sites,CN=Configuration,{deriveDistinguishedString c.ldapDomain}""" })
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetDomainSubnets)
            
            
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
        static member public getDFSShares (config: DirectorySearcherConfig list) =
            let part1 =
                config
                |> List.map (fun c -> {c with filter = $"""(|(objectClass=fTDfs){c.filter})"""})
                |> List.map doSearch
                |> List.collect (createLDAPSearchResults LDAPSearchType.GetDFSShares)
            let part2 =
                config
                |> List.map (fun c -> {c with filter = $"""(|(objectClass=msDFS-Linkv2){c.filter})"""})
                |> List.map doSearch
                |> List.collect (createLDAPSearchResults LDAPSearchType.GetDFSShares)
            part1 @ part2
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain group policy objects using the filter
        /// <code>(|(objectCategory=groupPolicyContainer)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///        
        static member public getGroupPolicyObjects (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectCategory=groupPolicyContainer){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetGroupPolicyObjects)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain trusts using the filter
        /// <code>(|(objectClass=trustedDomain)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///        
        static member public getDomainTrusts (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectClass=trustedDomain){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetDomainTrusts)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain objects matching the user-supplied filter from
        /// the DirectorySearcherConfig. This is the method to use if you want full control over the search logic.
        /// </summary>
        ///
        static member public getDomainObjects (config: DirectorySearcherConfig list) =
            config
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetDomainObjects)

                    
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all domain controllers using the filter
        /// <code>(useraccountcontrol:1.2.840.113556.1.4.803:=8192)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///            
        static member public getDomainControllers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(useraccountcontrol:1.2.840.113556.1.4.803:=8192){c.filter}"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetDomainControllers)
           
 
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all hosts with the TRUSTED_FOR_DELEGATION userAccountControl
        /// flag set using the filter
        /// <code>(useraccountcontrol:1.2.840.113556.1.4.803:=524288)</code>
        /// User-supplied filter is ignored for this search. 
        /// </summary>
        ///            
        static member public getHostsTrustedForDelegation (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(useraccountcontrol:1.2.840.113556.1.4.803:=524288)"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetHostsTrustedForDelegation)
            

        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all self-reported server objects that lack the userAccountControl
        /// SERVER_TRUST_ACCOUNT flag set using the filter
        /// <code>(&amp;(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))</code>
        /// User-supplied filter is appended to the end of the logical and. 
        /// </summary>
        ///
        static member public getReportedServersNotDC (config: DirectorySearcherConfig list) =
            config
            |> List.map(fun c ->
                {c with filter = $"""(&(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetReportedServersNotDC)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all containers using the filter
        /// <code>(objectCategory=container)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        ///
        static member public getContainers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectCategory=container){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetContainers)


        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all users with a non-null serviceprincipalname using the filter
        /// <code>(&amp;(objectClass=user)(!objectClass=computer)(serviceprincipalname=*)</code>
        /// User-supplied filter is appended to the end of the logical and. 
        /// </summary>
        ///
        static member public getUsersWithSPNs (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(&(objectClass=user)(!objectClass=computer)(serviceprincipalname=*){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetUsersWithSPNs)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all users with constrained delegation rights using the filter
        /// <code>(&amp;(objectClass=user)(msds-allowedtodelegateto=*)</code>
        /// User-supplied filter is appended to the end of the logical and. 
        /// </summary>
        ///
        static member public getConstrainedDelegates (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(&(objectClass=user)(msds-allowedtodelegateto=*){c.filter})"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetConstrainedDelegates)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all AS-REP roasting targets using the filter
        /// <code>(&amp;(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))</code>
        /// User-supplied filter is ignored for this search. 
        /// </summary>
        ///
        static member public getASREPTargets (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetASREPTargets)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all kerberoasting targets using the filter
        /// <code>(&amp;(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))</code>
        /// User-supplied filter is ignored for this search. 
        /// </summary>
        ///
        static member public getKerberoastTargets (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetKerberoastTargets)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve the Protected Users group if it contains any members
        /// using the filter
        /// <code>(&amp;(samaccountname=Protect*)(member=*))</code>
        /// User-supplied filter is ignored for this search. 
        /// </summary>
        ///
        static member public getProtectedUsers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(&(samaccountname=Protect*)(member=*))"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetProtectedUsers)
            
            
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve groups whose members are in the Builtin Administrators group
        /// using the filter
        /// <code>(&amp;(objectCategory=group)(memberOf=CN=Administrators,CN=Builtin,&lt;DC&gt;</code>
        /// User-supplied filter is ignored for this search. 
        /// </summary>
        ///
        static member public getGroupsWithLocalAdminRights (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(&(objectCategory=group)(memberOf=CN=Administrators,CN=Builtin,{c.ldapDomain |> deriveDistinguishedString}))"""})
            |> List.map doSearch
            |> List.collect (createLDAPSearchResults LDAPSearchType.GetGroupsWithLocalAdminRights)