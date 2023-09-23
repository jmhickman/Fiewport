namespace Fiewport

open System.DirectoryServices
open Types
open DomainSearcher

module Searcher =
    
    let private configureDomainConnection (config: DirectorySearcherConfig) =
        (getDomainConnection config.ldapDomain config.username config.password), config
        
    let private configureSearcher (domainAndConfig: DirectoryEntry * DirectorySearcherConfig) =
        let domain, config = domainAndConfig
        getDomainSearcher config domain
        
    let findAll (searcher: DirectorySearcher) = searcher.FindAll()
    
    let doSearch = configureDomainConnection >> configureSearcher >> findAll
    
    type Searcher = class end
        with        
        
        
        ///
        /// <summary>
        /// Connects to an AD and attempts to retrieve all users using the basic filter
        /// <code>(|(objectCategory=person)(objectCategory=user)</code>
        /// User-supplied filter is appended to the end of the logical or. 
        /// </summary>
        /// 
        static member getUsers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=person)(objectCategory=user){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults


        static member getComputers (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
        
        static member getSites (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectClass=site){c.filter})"""
                        ldapDomain = $"""{c.ldapDomain}/CN=Sites,CN=Configuration,{deriveDistinguishedString c.ldapDomain}""" })
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
        static member getOUs (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults


        static member getGroups (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectCategory=group){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
        
        static member getDomainDNSZones (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=dnsZone){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
        
        static member getDNSRecords (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c -> {c with filter = $"""(|(objectClass=dnsnode){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults


        static member getDomainSubnets (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(siteObject=*){c.filter})"""
                        ldapDomain = $"""{c.ldapDomain}/CN=Subnets,CN=Sites,CN=Configuration,{deriveDistinguishedString c.ldapDomain}""" })
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
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
            
            
        static member getGroupPolicyObjects (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectCategory=groupPolicyContainer){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
        static member getDomainTrusts (config: DirectorySearcherConfig list) =
            config
            |> List.map (fun c ->
                {c with filter = $"""(|(objectClass=trustedDomain){c.filter})"""})
            |> List.map doSearch
            |> List.collect createLDAPSearchResults
            
            
        static member getDomainObjects (config: DirectorySearcherConfig list) =
            config
            |> List.map doSearch
            |> List.collect createLDAPSearchResults