namespace Fiewport

module Searcher =
    open Types
    open LDAPUtils


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


    /// <summary>
    /// Helper: extract credentials and ldapDetails from SearcherConfig.
    /// Returns (credentials, ldapDetails) pairs for parallel processing.
    /// </summary>
    let private splitConfig (sc: SearcherConfig) =
        (sc.credentials, sc.ldapDetails)

    /// <summary>
    /// Execute LDAP search against each (credentials, details) pair.
    /// </summary>
    let private searchAll (creds: LdapCredentials list) (details: LdapSearchConfig list) =
        List.map2 (fun c d -> doSearch c d) creds details

    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users using the filter
    /// <code>(|(objectCategory=person)(objectCategory=user)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getUsers (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d -> {d with filter = $"""(|(objectCategory=person)(objectCategory=user){d.filter})"""})
        
        (credsList, modifiedDetails)
        ||> searchAll 
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetUsers) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all computers using the filter
    /// <code>(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getComputers (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d -> {d with filter = $"""(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetComputers) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all sites using the basic filter
    /// <code>(|(objectClass=site)</code>
    /// and LDAP connection
    /// <code>CN=Sites,CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getSites (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(|(objectClass=site){d.filter})"""
                        ldapDN = $"""CN=Sites,CN=Configuration,{d.ldapDN}""" })
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetSites) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all organization units using the filter
    /// <code>(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getOUs (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d -> {d with filter = $"""(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetOUs) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain groups using the filter
    /// <code>(|(objectCategory=group)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getGroups (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d -> {d with filter = $"""(|(objectCategory=group){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetGroups) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain DNS zones using the filter
    /// <code>(|(objectClass=dnsZone)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getDomainDNSZones (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d -> {d with filter = $"""(|(objectClass=dnsZone){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDomainDNSZones) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain DNS records using the filter
    /// <code>(|(objectClass=dnsnode)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getDNSRecords (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d -> {d with filter = $"""(|(objectClass=dnsnode){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDNSRecords) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain subnets using the filter
    /// <code>(|(siteObject=*)</code>
    /// and LDAP connection
    /// <code>CN=Subnets,CN=Sites,CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getDomainSubnets (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(|(siteObject=*){d.filter})"""
                        ldapDN = $"""CN=Subnets,CN=Sites,CN=Configuration,{d.ldapDN}""" })
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDomainSubnets) detailsList


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
    let getDFSShares (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip

        let part1 =
            let modifiedDetails =
                detailsList
                |> List.map (fun d -> {d with filter = $"""(|(objectClass=fTDfs){d.filter})"""})
            (credsList, modifiedDetails)
            ||> searchAll
            |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDFSShares) detailsList

        let part2 =
            let modifiedDetails =
                detailsList
                |> List.map (fun d -> {d with filter = $"""(|(objectClass=msDFS-Linkv2){d.filter})"""})
            (credsList, modifiedDetails)
            ||> searchAll
            |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDFSShares) detailsList

        part1 @ part2


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain group policy objects using the filter
    /// <code>(|(objectCategory=groupPolicyContainer)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getGroupPolicyObjects (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(|(objectCategory=groupPolicyContainer){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetGroupPolicyObjects) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain trusts using the filter
    /// <code>(|(objectClass=trustedDomain)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getDomainTrusts (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(|(objectClass=trustedDomain){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDomainTrusts) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain objects matching the user-supplied filter from
    /// the SearcherConfig. This is the method to use if you want full control over the search logic. It is
    /// important to note that if you don't configure a filter at all, you will get no results, rather than all
    /// results as was previously the case in Fiewport.
    /// </summary>
    ///
    let getDomainObjects (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""({d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDomainObjects) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain controllers using the filter
    /// <code>(useraccountcontrol:1.2.840.113556.1.4.803:=8192)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getDomainControllers (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(useraccountcontrol:1.2.840.113556.1.4.803:=8192){d.filter}"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetDomainControllers) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all hosts with the TRUSTED_FOR_DELEGATION UserAccountControl
    /// flag set using the filter
    /// <code>(useraccountcontrol:1.2.840.113556.1.4.803:=524288)</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    ///
    let getHostsTrustedForDelegation (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(useraccountcontrol:1.2.840.113556.1.4.803:=524288)"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetHostsTrustedForDelegation) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all self-reported server objects that lack the userAccountControl
    /// SERVER_TRUST_ACCOUNT flag set using the filter
    /// <code>(&amp;(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))</code>
    /// User-supplied filter is appended to the end of the logical and.
    /// </summary>
    ///
    let getReportedServersNotDC (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map(fun d ->
                {d with filter = $"""(&(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetReportedServersNotDC) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all containers using the filter
    /// <code>(objectCategory=container)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    ///
    let getContainers (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(|(objectCategory=container){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetContainers) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users with a non-null serviceprincipalname using the filter
    /// <code>(&amp;(objectClass=user)(!objectClass=computer)(serviceprincipalname=*)</code>
    /// User-supplied filter is appended to the end of the logical and.
    /// </summary>
    ///
    let getUsersWithSPNs (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(&(objectClass=user)(!objectClass=computer)(serviceprincipalname=*){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetUsersWithSPNs) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users with constrained delegation rights using the filter
    /// <code>(&amp;(objectClass=user)(msds-allowedtodelegateto=*)</code>
    /// User-supplied filter is appended to the end of the logical and.
    /// </summary>
    ///
    let getConstrainedDelegates (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(&(objectClass=user)(msds-allowedtodelegateto=*){d.filter})"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetConstrainedDelegates) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all AS-REP roasting targets using the filter
    /// <code>(&amp;(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    ///
    let getASREPTargets (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetASREPTargets) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all kerberoasting targets using the filter
    /// <code>(&amp;(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    ///
    let getKerberoastTargets (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetKerberoastTargets) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve the Protected Users group if it contains any members
    /// using the filter
    /// <code>(&amp;(samaccountname=Protect*)(member=*))</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    ///
    let getProtectedUsers (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(&(samaccountname=Protect*)(member=*))"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetProtectedUsers) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve groups whose members are in the Builtin Administrators group
    /// using the filter
    /// <code>(&amp;(objectCategory=group)(memberOf=CN=Administrators,CN=Builtin,&lt;DC&gt;</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    ///
    let getGroupsWithLocalAdminRights (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"""(&(objectCategory=group)(memberOf=CN=Administrators,CN=Builtin,{d.ldapDN}))"""})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.GetGroupsWithLocalAdminRights) detailsList


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve everything the server knows about.
    /// User-supplied filter is ignored for this search.
    /// </summary>
    ///
    let dumpDomainObjects (config: SearcherConfig list) =
        let credsList, detailsList = config |> List.map splitConfig |> List.unzip
        let modifiedDetails =
            detailsList
            |> List.map (fun d ->
                {d with filter = $"(objectclass=*)"})
        (credsList, modifiedDetails)
        ||> searchAll
        |> List.map2 (createLDAPSearchResults LDAPSearchType.DumpAD) detailsList
