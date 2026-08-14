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

    let private splitConfig (sc: SearcherConfig) =
        sc.credentials, sc.ldapDetails

    let private searchAll (creds: LdapCredentials list) (details: LdapSearchConfig list) =
        List.map2 (fun c d -> doSearch c d) creds details


    ///
    /// Shared search pipeline: split configs, apply a transform to the search details,
    /// execute, and wrap results. Each public function provides its own transform lambda.
    /// 
    let private searchWith searchType modifyDetails configs : LDAPSearchResult list =
        let creds, details = configs |> List.map splitConfig |> List.unzip
        let modified = details |> List.map modifyDetails
        (creds, modified) ||> searchAll
        |> List.map2 (createLDAPSearchResults searchType) details


    /// 
    /// Internal helper: apply a searcher's transform to a config and return the modified details.
    /// Exposed for unit-testing filter construction without hitting LDAP.
    /// 
    let internal applySearchTransform modifyDetails (config: SearcherConfig) : LdapSearchConfig =
        config.ldapDetails |> modifyDetails


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users using the filter
    /// <code>(|(objectCategory=person)(objectCategory=user)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getUsers (configs: SearcherConfig list) =
        searchWith GetUsers
                   (fun d -> {d with filter = $"""(|(objectCategory=person)(objectCategory=user){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all computers using the filter
    /// <code>(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getComputers (configs: SearcherConfig list) =
        searchWith GetComputers
                   (fun d -> {d with filter = $"""(|(objectCategory=computer)(objectCategory=server)(objectClass=computer)(objectClass=server){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all sites using the basic filter
    /// <code>(|(objectClass=site)</code>
    /// and LDAP connection
    /// <code>CN=Sites,CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getSites (configs: SearcherConfig list) =
        searchWith GetSites
                   (fun d -> {d with filter = $"""(|(objectClass=site){d.filter})"""; ldapDN = $"""CN=Sites,CN=Configuration,{d.ldapDN}"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all organization units using the filter
    /// <code>(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getOUs (configs: SearcherConfig list) =
        searchWith GetOUs
                   (fun d -> {d with filter = $"""(|(objectClass=organizationalUnit)(objectCategory=organizationalUnit)(ou=*){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain groups using the filter
    /// <code>(|(objectCategory=group)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getGroups (configs: SearcherConfig list) =
        searchWith GetGroups
                   (fun d -> {d with filter = $"""(|(objectCategory=group){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain DNS zones using the filter
    /// <code>(|(objectClass=dnsZone)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getDomainDNSZones (configs: SearcherConfig list) =
        searchWith GetDomainDNSZones
                   (fun d -> {d with filter = $"""(|(objectClass=dnsZone){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain DNS records using the filter
    /// <code>(|(objectClass=dnsnode)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getDNSRecords (configs: SearcherConfig list) =
        searchWith GetDNSRecords
                   (fun d -> {d with filter = $"""(|(objectClass=dnsnode){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain subnets using the filter
    /// <code>(|(siteObject=*)</code>
    /// and LDAP connection
    /// <code>CN=Subnets,CN=Sites,CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getDomainSubnets (configs: SearcherConfig list) =
        searchWith GetDomainSubnets
                   (fun d -> {d with filter = $"""(|(siteObject=*){d.filter})"""; ldapDN = $"""CN=Subnets,CN=Sites,CN=Configuration,{d.ldapDN}"""})
                   configs

    
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
    let getDFSShares (configs: SearcherConfig list) =
        let part1 = searchWith GetDFSShares
                               (fun d -> {d with filter = $"""(|(objectClass=fTDfs){d.filter})"""})
                               configs
        let part2 = searchWith GetDFSShares
                               (fun d -> {d with filter = $"""(|(objectClass=msDFS-Linkv2){d.filter})"""})
                               configs
        part1 @ part2

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain group policy objects using the filter
    /// <code>(|(objectCategory=groupPolicyContainer)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getGroupPolicyObjects (configs: SearcherConfig list) =
        searchWith GetGroupPolicyObjects
                   (fun d -> {d with filter = $"""(|(objectCategory=groupPolicyContainer){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain trusts using the filter
    /// <code>(|(objectClass=trustedDomain)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getDomainTrusts (configs: SearcherConfig list) =
        searchWith GetDomainTrusts
                   (fun d -> {d with filter = $"""(|(objectClass=trustedDomain){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain objects matching the user-supplied filter from
    /// the SearcherConfig. This is the method to use if you want full control over the search logic. It is
    /// important to note that if you don't configure a filter at all, you will get no results, rather than all
    /// results as was previously the case in Fiewport.
    /// </summary>
    /// 
    let getDomainObjects (configs: SearcherConfig list) =
        searchWith GetDomainObjects
                   (fun d -> {d with filter = $"""({d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all domain controllers using the filter
    /// <code>(useraccountcontrol:1.2.840.113556.1.4.803:=8192)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getDomainControllers (configs: SearcherConfig list) =
        searchWith GetDomainControllers
                   (fun d -> {d with filter = $"""(useraccountcontrol:1.2.840.113556.1.4.803:=8192){d.filter}"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all hosts with the TRUSTED_FOR_DELEGATION UserAccountControl
    /// flag set using the filter
    /// <code>(useraccountcontrol:1.2.840.113556.1.4.803:=524288)</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getHostsTrustedForDelegation (configs: SearcherConfig list) =
        searchWith GetHostsTrustedForDelegation
                   (fun d -> {d with filter = $"""(useraccountcontrol:1.2.840.113556.1.4.803:=524288)"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all self-reported server objects that lack the userAccountControl
    /// SERVER_TRUST_ACCOUNT flag set using the filter
    /// <code>(&amp;(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))</code>
    /// User-supplied filter is appended to the end of the logical and.
    /// </summary>
    /// 
    let getReportedServersNotDC (configs: SearcherConfig list) =
        searchWith GetReportedServersNotDC
                   (fun d -> {d with filter = $"""(&(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all containers using the filter
    /// <code>(objectCategory=container)</code>
    /// User-supplied filter is appended to the end of the logical or.
    /// </summary>
    /// 
    let getContainers (configs: SearcherConfig list) =
        searchWith GetContainers
                   (fun d -> {d with filter = $"""(|(objectCategory=container){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users with a non-null serviceprincipalname using the filter
    /// <code>(&amp;(objectClass=user)(!objectClass=computer)(serviceprincipalname=*)</code>
    /// User-supplied filter is appended to the end of the logical and.
    /// </summary>
    /// 
    let getUsersWithSPNs (configs: SearcherConfig list) =
        searchWith GetUsersWithSPNs
                   (fun d -> {d with filter = $"""(&(objectClass=user)(!objectClass=computer)(serviceprincipalname=*){d.filter})"""})
                   configs

    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users with constrained delegation rights using the filter
    /// <code>(&amp;(objectClass=user)(msds-allowedtodelegateto=*)</code>
    /// User-supplied filter is appended to the end of the logical and.
    /// </summary>
    /// 
    let getConstrainedDelegates (configs: SearcherConfig list) =
        searchWith GetConstrainedDelegates
                   (fun d -> {d with filter = $"""(&(objectClass=user)(msds-allowedtodelegateto=*){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all AS-REP roasting targets using the filter
    /// <code>(&amp;(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getASREPTargets (configs: SearcherConfig list) =
        searchWith GetASREPTargets
                   (fun d -> {d with filter = $"""(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all kerberoasting targets using the filter
    /// <code>(&amp;(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getKerberoastTargets (configs: SearcherConfig list) =
        searchWith GetKerberoastTargets
                   (fun d -> {d with filter = $"""(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve the Protected Users group if it contains any members
    /// using the filter
    /// <code>(&amp;(samaccountname=Protect*)(member=*))</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getProtectedUsers (configs: SearcherConfig list) =
        searchWith GetProtectedUsers
                   (fun d -> {d with filter = $"""(&(samaccountname=Protect*)(member=*))"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve groups whose members are in the Builtin Administrators group
    /// using the filter
    /// <code>(&amp;(objectCategory=group)(memberOf=CN=Administrators,CN=Builtin,&lt;DC&gt;</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getGroupsWithLocalAdminRights (configs: SearcherConfig list) =
        searchWith GetGroupsWithLocalAdminRights
                   (fun d -> {d with filter = $"""(&(objectCategory=group)(memberOf=CN=Administrators,CN=Builtin,{d.ldapDN}))"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve everything the server knows about.
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let dumpDomainObjects (configs: SearcherConfig list) =
        searchWith DumpAD
                   (fun d -> {d with filter = $"(objectclass=*)"})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and retrieves group membership data, requesting only the
    /// <c>member</c> and <c>samaccountname</c> attributes.
    /// Uses the filter
    /// <code>(&amp;(objectCategory=group)(samaccountname=&lt;GroupName&gt;)</code>
    /// Pass the group name via the <c>filter</c> field in <c>SearcherConfig</c> as the group's
    /// <c>samAccountName</c>, e.g. <c>filter = "Domain Admins"</c>. If no filter is provided,
    /// falls back to retrieving all groups that have at least one member.
    /// </summary>
    /// 
    let getGroupMembers (configs: SearcherConfig list) =
        searchWith GetGroupMembers
                   (fun d ->
                       match d.filter with
                       | "" | null ->
                           {d with filter = $"""(&(objectCategory=group)(member=*))"""; properties = [| "member"; "samaccountname" |]}
                       | name ->
                           {d with filter = $"""(&(objectCategory=group)(samaccountname={name}))"""; properties = [| "member"; "samaccountname" |]})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all Group Managed Service Accounts using the filter
    /// <code>(objectClass=msDS-GroupManagedServiceAccount)</code>
    /// User-supplied filter is appended inside an AND.
    /// </summary>
    /// 
    let getGMSAs (configs: SearcherConfig list) =
        searchWith GetGMSAs
                   (fun d -> {d with filter = $"""(&(objectClass=msDS-GroupManagedServiceAccount){d.filter})"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users with the <c>sidHistory</c> attribute set
    /// using the filter
    /// <code>(&amp;(objectCategory=person)(objectClass=user)(sidHistory=*))</code>
    /// User-supplied filter is appended inside an AND.
    /// </summary>
    /// 
    let getUsersWithSidHistory (configs: SearcherConfig list) =
        searchWith GetUsersWithSidHistory
                   (fun d -> {d with filter = $"""(&(objectCategory=person)(objectClass=user)(sidHistory=*){d.filter})"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and attempts to retrieve all users and groups where <c>adminCount</c> is 1,
    /// indicating current or former membership in a privileged group, using the filter
    /// <code>(&amp;(admincount=1)(|(objectcategory=person)(objectcategory=group)))</code>
    /// User-supplied filter is appended inside an AND.
    /// </summary>
    /// 
    let getUsersWithAdminCount (configs: SearcherConfig list) =
        searchWith GetUsersWithAdminCount
                   (fun d -> {d with filter = $"""(&(admincount=1)(|(objectcategory=person)(objectcategory=group)){d.filter})"""})
                   configs

    
    ///
    /// <summary>
    /// Connects to an AD and retrieves the <c>ms-DS-MachineAccountQuota</c> property from the domain object
    /// using a base-level search with the filter
    /// <code>(objectClass=domain)</code>
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getMachineAccountQuota (configs: SearcherConfig list) =
        searchWith GetMachineAccountQuota
                   (fun d -> {d with filter = $"(objectClass=domain)"; scope = SearchScope.Base; properties = [| "ms-DS-MachineAccountQuota" |]})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and retrieves all domains in the forest by querying the configuration partition
    /// using the filter
    /// <code>(objectClass=domainDNS)</code>
    /// with search base <code>CN=Partitions,CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended inside an OR.
    /// </summary>
    /// 
    let getForestDomains (configs: SearcherConfig list) =
        searchWith GetForestDomains
                   (fun d -> {d with filter = $"""(|(objectClass=domainDNS){d.filter})"""; ldapDN = $"""CN=Partitions,CN=Configuration,{d.ldapDN}"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and retrieves all global catalog servers by querying the configuration partition
    /// using the filter
    /// <code>(objectClass=nTDSDSA)</code>
    /// with search base <code>CN=Sites,CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended inside an OR.
    /// </summary>
    /// 
    let getForestGlobalCatalogs (configs: SearcherConfig list) =
        searchWith GetForestGlobalCatalogs
                   (fun d -> {d with filter = $"""(|(objectClass=nTDSDSA){d.filter})"""; ldapDN = $"""CN=Sites,CN=Configuration,{d.ldapDN}"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and retrieves all forest-level trusts by querying the configuration partition
    /// using the filter
    /// <code>(objectClass=trustedDomain)</code>
    /// with search base <code>CN=Configuration,[DC=domain...]</code>
    /// User-supplied filter is appended inside an OR.
    /// </summary>
    /// 
    let getForestTrusts (configs: SearcherConfig list) =
        searchWith GetForestTrusts
                   (fun d -> {d with filter = $"""(|(objectClass=trustedDomain){d.filter})"""; ldapDN = $"""CN=Configuration,{d.ldapDN}"""})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and retrieves the domain's base SID by querying the domain object
    /// using a base-level search with the filter
    /// <code>(objectClass=domain)</code>
    /// requesting the <c>objectSid</c> property.
    /// User-supplied filter is ignored for this search.
    /// </summary>
    /// 
    let getDomainSID (configs: SearcherConfig list) =
        searchWith GetDomainSID
                   (fun d -> {d with filter = $"(objectClass=domain)"; scope = SearchScope.Base; properties = [| "objectSid" |]})
                   configs


    ///
    /// <summary>
    /// Connects to an AD and retrieves the default domain password policy by querying the domain object
    /// using a base-level search with the filter
    /// <code>(objectClass=domain)</code>
    /// requesting the password policy properties: <c>minpwdage</c>, <c>maxpwdage</c>,
    /// <c>minpwdlength</c>, <c>pwdhistorylength</c>, <c>lockoutthreshold</c>,
    /// <c>lockoutduration</c>, and <c>lockoutobservationwindow</c>.
    /// User-supplied filter is ignored for this search.
    /// Timespan attributes (<c>minpwdage</c>, <c>maxpwdage</c>, <c>lockoutduration</c>,
    /// <c>lockoutobservationwindow</c>) are automatically converted to hours by the data handlers.
    /// </summary>
    /// 
    let getPasswordPolicy (configs: SearcherConfig list) =
        let passwordPolicyProperties =
            [| "minpwdage"
               "maxpwdage"
               "minpwdlength"
               "pwdhistorylength"
               "lockoutthreshold"
               "lockoutduration"
               "lockoutobservationwindow" |]
        searchWith GetDefaultPasswordPolicy
                   (fun d -> {d with filter = $"(objectClass=domain)"; scope = SearchScope.Base; properties = passwordPolicyProperties})
                   configs
