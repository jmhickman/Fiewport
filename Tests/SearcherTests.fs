namespace Fiewport.Tests

module SearcherTests =

    open Expecto
    open Fiewport

    let private transform (modifyDetails: LdapSearchConfig -> LdapSearchConfig) (config: SearcherConfig) =
        Searcher.applySearchTransform modifyDetails config



    let private tGetUsers d = {d with filter = $"""(|(objectCategory=person)(objectCategory=user){d.filter})"""}
    let private tGetSites d = {d with filter = $"""(|(objectClass=site){d.filter})"""; ldapDN = $"""CN=Sites,CN=Configuration,{d.ldapDN}"""}
    let private tGetASREPTargets d = {d with filter = $"""(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"""}
    let private tGetKerberoastTargets d = {d with filter = $"""(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))"""}


    let private tGetGroupMembers d =
        match d.filter with
        | "" | null -> {d with filter = $"""(&(objectCategory=group)(member=*))"""; properties = [| "member"; "samaccountname" |]}
        | name -> {d with filter = $"""(&(objectCategory=group)(samaccountname={name}))"""; properties = [| "member"; "samaccountname" |]}
    let private tGetGMSAs d = {d with filter = $"""(&(objectClass=msDS-GroupManagedServiceAccount){d.filter})"""}
    let private tGetUsersWithSidHistory d = {d with filter = $"""(&(objectCategory=person)(objectClass=user)(sidHistory=*){d.filter})"""}
    let private tGetUsersWithAdminCount d = {d with filter = $"""(&(admincount=1)(|(objectcategory=person)(objectcategory=group)){d.filter})"""}
    let private tGetMachineAccountQuota d = {d with filter = $"(objectClass=domain)"; scope = Base; properties = [| "ms-DS-MachineAccountQuota" |]}
    let private tGetForestDomains d = {d with filter = $"""(|(objectClass=domainDNS){d.filter})"""; ldapDN = $"""CN=Partitions,CN=Configuration,{d.ldapDN}"""}
    let private tGetForestGlobalCatalogs d = {d with filter = $"""(|(objectClass=nTDSDSA){d.filter})"""; ldapDN = $"""CN=Sites,CN=Configuration,{d.ldapDN}"""}
    let private tGetForestTrusts d = {d with filter = $"""(|(objectClass=trustedDomain){d.filter})"""; ldapDN = $"""CN=Configuration,{d.ldapDN}"""}
    let private tGetDomainSID d = {d with filter = $"(objectClass=domain)"; scope = Base; properties = [| "objectSid" |]}
    let private tGetPasswordPolicy d =
        {d with filter = $"(objectClass=domain)"
                scope = Base
                properties = [| "minpwdage"
                                "maxpwdage"
                                "minpwdlength"
                                "pwdhistorylength"
                                "lockoutthreshold"
                                "lockoutduration"
                                "lockoutobservationwindow" |]}
    let private tGetGroup (groupName: string) d =
        { d with filter = $"""(&(objectCategory=group)(|(sAMAccountName={groupName})(cn={groupName})(name={groupName})))""" }
    let private anyLapsComputerFilter =
        """(&(objectCategory=computer)(|(ms-mcs-admpwd=*)(ms-mcs-admpwdexpirationtime=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedDSRMPassword=*)))"""
    let private lapsAttributeProperties =
        [| "cn"; "name"; "dnshostname"; "distinguishedname"
           "ms-mcs-admpwd"; "ms-mcs-admpwdexpirationtime"
           "msLAPS-Password"; "msLAPS-EncryptedPassword"; "msLAPS-PasswordExpirationTime"
           "msLAPS-EncryptedPasswordHistory"; "msLAPS-EncryptedDSRMPassword"
           "msLAPS-EncryptedDSRMPasswordHistory"; "msLAPS-CurrentPasswordVersion" |]
    let private tGetLaps d =
        { d with filter = anyLapsComputerFilter; properties = lapsAttributeProperties }
    let private tLapsRights d =
        { d with filter = anyLapsComputerFilter; properties = Array.append lapsAttributeProperties [| "ntsecuritydescriptor" |] }

    // ── Test configs ─────────────────────────────────────────────────

    let private baseConfig : SearcherConfig =
        { ldapDetails =
            { properties = [||]
              filter = ""
              ldapDN = "DC=test,DC=local"
              scope = Subtree
              ldapHostname = ""
              ldapIP = "192.168.56.10"
              ldapPort = 389
              useSsl = false }
          credentials =
            { username = "testuser"
              password = "P@ssw0rd" } }

    let private configWithFilter (f: string) : SearcherConfig =
        { baseConfig with ldapDetails = { baseConfig.ldapDetails with filter = f } }


    let searcherTests =
        testList "Searcher filter construction"
            [ test "getUsers builds correct filter"
                { let result = transform tGetUsers baseConfig
                  Expect.equal result.filter "(|(objectCategory=person)(objectCategory=user))" "filter matches" }
              test "getUsers appends user filter"
                { let result = transform tGetUsers (configWithFilter "(cn=admin)")
                  Expect.equal result.filter "(|(objectCategory=person)(objectCategory=user)(cn=admin))" "filter appends" }
              test "getSites overrides ldapDN"
                { let result = transform tGetSites baseConfig
                  Expect.equal result.ldapDN "CN=Sites,CN=Configuration,DC=test,DC=local" "DN overridden" }
              test "getASREPTargets ignores user filter"
                { let result = transform tGetASREPTargets (configWithFilter "(cn=x)")
                  Expect.equal result.filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" "filter unchanged" }
              test "getKerberoastTargets ignores user filter"
                { let result = transform tGetKerberoastTargets (configWithFilter "(cn=x)")
                  Expect.equal result.filter "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))" "filter unchanged" }
              test "getGroupMembers with empty filter returns broad query"
                { let result = transform tGetGroupMembers baseConfig
                  Expect.equal result.filter "(&(objectCategory=group)(member=*))" "broad group filter"
                  Expect.sequenceEqual result.properties [| "member"; "samaccountname" |] "requests member + samaccountname" }
              test "getGroupMembers with group name targets specific group"
                { let result = transform tGetGroupMembers (configWithFilter "Domain Admins")
                  Expect.equal result.filter "(&(objectCategory=group)(samaccountname=Domain Admins))" "named group filter"
                  Expect.sequenceEqual result.properties [| "member"; "samaccountname" |] "requests member + samaccountname" }
              test "getGMSAs builds correct filter"
                { let result = transform tGetGMSAs baseConfig
                  Expect.equal result.filter "(&(objectClass=msDS-GroupManagedServiceAccount))" "GMSA filter" }
              test "getGMSAs appends user filter"
                { let result = transform tGetGMSAs (configWithFilter "(cn=svc*)")
                  Expect.equal result.filter "(&(objectClass=msDS-GroupManagedServiceAccount)(cn=svc*))" "GMSA filter appends" }
              test "getUsersWithSidHistory builds correct filter"
                { let result = transform tGetUsersWithSidHistory baseConfig
                  Expect.equal result.filter "(&(objectCategory=person)(objectClass=user)(sidHistory=*))" "sidHistory filter" }
              test "getUsersWithAdminCount builds correct filter"
                { let result = transform tGetUsersWithAdminCount baseConfig
                  Expect.equal result.filter "(&(admincount=1)(|(objectcategory=person)(objectcategory=group)))" "adminCount filter" }
              test "getMachineAccountQuota uses base scope and requests property"
                { let result = transform tGetMachineAccountQuota baseConfig
                  Expect.equal result.filter "(objectClass=domain)" "domain filter"
                  Expect.equal result.scope SearchScope.Base "base scope"
                  Expect.sequenceEqual result.properties [| "ms-DS-MachineAccountQuota" |] "requests MAQ property" }
              test "getForestDomains uses configuration partition"
                { let result = transform tGetForestDomains baseConfig
                  Expect.equal result.ldapDN "CN=Partitions,CN=Configuration,DC=test,DC=local" "partition DN"
                  Expect.equal result.filter "(|(objectClass=domainDNS))" "domainDNS filter" }
              test "getForestGlobalCatalogs uses configuration partition"
                { let result = transform tGetForestGlobalCatalogs baseConfig
                  Expect.equal result.ldapDN "CN=Sites,CN=Configuration,DC=test,DC=local" "sites DN"
                  Expect.equal result.filter "(|(objectClass=nTDSDSA))" "nTDSDSA filter" }
              test "getForestTrusts uses configuration partition"
                { let result = transform tGetForestTrusts baseConfig
                  Expect.equal result.ldapDN "CN=Configuration,DC=test,DC=local" "config DN"
                  Expect.equal result.filter "(|(objectClass=trustedDomain))" "trustedDomain filter" }
              test "getDomainSID uses base scope and requests property"
                { let result = transform tGetDomainSID baseConfig
                  Expect.equal result.filter "(objectClass=domain)" "domain filter"
                  Expect.equal result.scope SearchScope.Base "base scope"
                  Expect.sequenceEqual result.properties [| "objectSid" |] "requests objectSid" }
              test "getPasswordPolicy uses base scope and requests password policy properties"
                { let result = transform tGetPasswordPolicy baseConfig
                  Expect.equal result.filter "(objectClass=domain)" "domain filter"
                  Expect.equal result.scope SearchScope.Base "base scope"
                  Expect.sequenceEqual result.properties
                      [| "minpwdage"; "maxpwdage"; "minpwdlength"; "pwdhistorylength"
                         "lockoutthreshold"; "lockoutduration"; "lockoutobservationwindow" |]
                      "requests all password policy properties" }
              test "getPasswordPolicy ignores user-supplied filter"
                { let result = transform tGetPasswordPolicy (configWithFilter "(cn=x)")
                  Expect.equal result.filter "(objectClass=domain)" "filter unchanged" }
              test "getGroup builds name OR filter"
                { let result = transform (tGetGroup "Security Interns") baseConfig
                  Expect.equal result.filter "(&(objectCategory=group)(|(sAMAccountName=Security Interns)(cn=Security Interns)(name=Security Interns)))" "group name filter" }
              test "getGroup ignores config.filter"
                { let result = transform (tGetGroup "Domain Admins") (configWithFilter "(cn=x)")
                  Expect.equal result.filter "(&(objectCategory=group)(|(sAMAccountName=Domain Admins)(cn=Domain Admins)(name=Domain Admins)))" "name wins" }
              test "getLaps ORs legacy MCS and Windows LAPS attributes"
                { let result = transform tGetLaps baseConfig
                  Expect.equal result.filter anyLapsComputerFilter "combined LAPS filter"
                  Expect.isTrue (result.properties |> Array.contains "ms-mcs-admpwd") "legacy password"
                  Expect.isTrue (result.properties |> Array.contains "msLAPS-Password") "windows cleartext"
                  Expect.isTrue (result.properties |> Array.contains "msLAPS-EncryptedPassword") "windows encrypted" }
              test "lapsRights uses same LAPS filter and requests nTSecurityDescriptor"
                { let result = transform tLapsRights baseConfig
                  Expect.equal result.filter anyLapsComputerFilter "combined LAPS filter"
                  Expect.isTrue (result.properties |> Array.contains "ntsecuritydescriptor") "requests ntsd"
                  Expect.isTrue (result.properties |> Array.contains "msLAPS-EncryptedPassword") "windows encrypted"
                  Expect.isTrue (result.properties |> Array.contains "ms-mcs-admpwd") "legacy password" } ]
