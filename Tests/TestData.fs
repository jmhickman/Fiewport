namespace Fiewport.Tests

module TestData =

    open Fiewport.Types

    // ── Configs ──────────────────────────────────────────────────────

    let defaultLdapDetails : LdapSearchConfig =
        { properties = [||]
          filter = ""
          ldapDN = "DC=test,DC=local"
          scope = SearchScope.Subtree
          ldapHost = "192.168.56.10"
          ldapPort = 389
          useSsl = false }

    let defaultCredentials : LdapCredentials =
        { username = "testuser"
          password = "P@ssw0rd" }

    let defaultConfig : SearcherConfig =
        { ldapDetails = defaultLdapDetails
          credentials = defaultCredentials }

    let altConfig : SearcherConfig =
        { defaultConfig with ldapDetails = { defaultLdapDetails with ldapHost = "10.0.0.1" } }

    // ── Map builders ─────────────────────────────────────────────────

    let mkMap (pairs : (string * string list) list) : Map<string, string list> =
        Map.ofList pairs

    let mkResult (searchType : LDAPSearchType) (config : LdapSearchConfig) (data : Map<string, string list>) =
        { searchType = searchType
          searchConfig = config
          ldapSearcherError = None
          ldapData = [data] }

    let mkMultiResult (searchType : LDAPSearchType) (config : LdapSearchConfig) (maps : Map<string, string list> list) =
        { searchType = searchType
          searchConfig = config
          ldapSearcherError = None
          ldapData = maps }

    let mkErrorResult (config : LdapSearchConfig) (message : string) =
        { searchType = LDAPSearchType.GetUsers
          searchConfig = config
          ldapSearcherError = Some { message = message; context = "search" }
          ldapData = [Map.empty] }

    // ── User fixtures ────────────────────────────────────────────────

    let adminUser =
        mkResult LDAPSearchType.GetUsers defaultLdapDetails (mkMap 
        [ "cn", ["Administrator"]
          "sAMAccountName", ["Administrator"]
          "adminCount", ["1"]
          "useraccountcontrol", ["66048"]
          "objectsid", ["S-1-5-21-1166717504-1521404966-3895803826-500"]
          "samaccounttype", ["SAM_USER_OBJECT_OR_NORMAL_ACCOUNT"]
          "whencreated", ["04/05/2025 06:31"] ])

    let regularUser =
        mkResult LDAPSearchType.GetUsers defaultLdapDetails (mkMap 
        [ "cn", ["Ebony Kelly"]
          "sAMAccountName", ["Ebony.Kelly"]
          "useraccountcontrol", ["512"]
          "objectsid", ["S-1-5-21-1166717504-1521404966-3895803826-1123"]
          "samaccounttype", ["SAM_USER_OBJECT_OR_NORMAL_ACCOUNT"]
          "department", ["Marketing"]
          "mail", ["Ebony.Kelly@ad-lab.com"] ])

    let disabledUser =
        mkResult LDAPSearchType.GetUsers defaultLdapDetails (mkMap 
        [ "cn", ["Guest"]
          "sAMAccountName", ["Guest"]
          "useraccountcontrol", ["256"]
          "objectsid", ["S-1-5-21-1166717504-1521404966-3895803826-501"] ])

    let krbtgtUser =
        mkResult LDAPSearchType.GetUsers defaultLdapDetails (mkMap 
        [ "cn", ["krbtgt"]
          "sAMAccountName", ["krbtgt"]
          "useraccountcontrol", ["514"]
          "msds-supportedencryptiontypes", ["RC4_HMAC_MD5"]
          "serviceprincipalname", ["kadmin/changepw"] ])

    let kerberoastTarget =
        mkResult LDAPSearchType.GetKerberoastTargets defaultLdapDetails (mkMap 
        [ "cn", ["svc_backup"]
          "sAMAccountName", ["svc_backup"]
          "serviceprincipalname", ["cifs/fileserver01"; "cifs/fileserver01.test.local"]
          "useraccountcontrol", ["66048"]
          "pwdlastset", ["132345678901234567"] ])

    let asrepTarget =
        mkResult LDAPSearchType.GetASREPTargets defaultLdapDetails (mkMap 
        [ "cn", ["svc_asrep"]
          "sAMAccountName", ["svc_asrep"]
          "useraccountcontrol", ["4249536"] ])

    // ── Computer fixtures ────────────────────────────────────────────

    let dcComputer =
        mkResult LDAPSearchType.GetComputers defaultLdapDetails (mkMap 
        [ "cn", ["AD-SERVER-01"]
          "sAMAccountName", ["AD-SERVER-01$"]
          "dnshostname", ["AD-Server-01.ad-lab.local"]
          "useraccountcontrol", ["32768"]
          "operatingsystem", ["Windows Server 2019 Essentials"]
          "msds-supportedencryptiontypes", ["RC4, AES128, AES256"]
          "objectsid", ["S-1-5-21-1166717504-1521404966-3895803826-1000"]
          "samaccounttype", ["SAM_MACHINE_ACCOUNT"] ])

    let workstationComputer =
        mkResult LDAPSearchType.GetComputers defaultLdapDetails (mkMap 
        [ "cn", ["WORKSTATION01"]
          "sAMAccountName", ["WORKSTATION01$"]
          "dnshostname", ["workstation01.test.local"]
          "useraccountcontrol", ["4096"]
          "samaccounttype", ["SAM_MACHINE_ACCOUNT"] ])

    // ── Group fixtures ───────────────────────────────────────────────

    let builtinAdminsGroup =
        mkResult LDAPSearchType.GetGroups defaultLdapDetails (mkMap 
        [ "cn", ["Administrators"]
          "sAMAccountName", ["Administrators"]
          "grouptype", ["-2147483645"]
          "systemflags", ["-2147483616"]
          "member", 
            [ "CN=Domain Admins,CN=Users,DC=ad-lab,DC=local"
              "CN=Administrator,CN=Users,DC=ad-lab,DC=local" ]
          "objectsid", ["S-1-5-32-544"]
          "samaccounttype", ["SAM_ALIAS_OBJECT"] ])

    let securityGroup =
        mkResult LDAPSearchType.GetGroups defaultLdapDetails (mkMap 
        [ "cn", ["IT_Folders"]
          "sAMAccountName", ["IT_Folders"]
          "grouptype", ["-2147483644"]
          "member", ["CN=Ebony Kelly,OU=Marketing,DC=ad-lab,DC=local"]
          "objectsid", ["S-1-5-21-1166717504-1521404966-3895803826-1111"]
          "samaccounttype", ["SAM_ALIAS_OBJECT"]
          "whencreated", ["04/05/2025 15:02"] ])

    let distributionGroup =
        mkResult LDAPSearchType.GetGroups defaultLdapDetails (mkMap 
        [ "cn", ["All Staff"]
          "sAMAccountName", ["All_Staff"]
          "grouptype", ["8"]
          "samaccounttype", ["SAM_ALIAS_OBJECT"] ])

    // ── Trust fixture ────────────────────────────────────────────────

    let domainTrust =
        mkResult LDAPSearchType.GetDomainTrusts defaultLdapDetails (mkMap 
        [ "cn", ["partner.com"]
          "flatname", ["partner.com"]
          "trustdirection", ["3"]
          "trusttype", ["2"]
          "trustattributes", ["32"] ])

    // ── Multi-map result ─────────────────────────────────────────────

    let multipleUsers =
        mkMultiResult LDAPSearchType.GetUsers defaultLdapDetails 
        [ mkMap ["cn", ["User1"]; "sAMAccountName", ["user1"]; "useraccountcontrol", ["512"]]
          mkMap ["cn", ["User2"]; "sAMAccountName", ["user2"]; "useraccountcontrol", ["512"]]
          mkMap ["cn", ["User3"]; "sAMAccountName", ["user3"]; "useraccountcontrol", ["514"]] ]

    let multipleGroups =
        mkMultiResult LDAPSearchType.GetGroups defaultLdapDetails 
            [ mkMap ["cn", ["GroupA"]; "grouptype", ["-2147483646"]]
              mkMap ["cn", ["GroupB"]; "grouptype", ["8"]] ]

    // ── Empty result ─────────────────────────────────────────────────

    let emptyResult =
        { searchType = LDAPSearchType.GetDomainTrusts
          searchConfig = defaultLdapDetails
          ldapSearcherError = None
          ldapData = [] }

    // ── GPO fixtures ─────────────────────────────────────────────────

    let gpoWithSecurityExtension =
        mkResult LDAPSearchType.GetGroupPolicyObjects defaultLdapDetails (mkMap 
        [ "cn", ["{31B2F340-016D-11D2-945F-00C04FB984F9}"]
          "displayname", ["Default Domain Policy"]
          "gpcmachineextensionnames", ["[CSE-GUID{827D319E-6EAC-11D2-A4EA-00C04F79F83A};Security]"]
          "gpcuserextensionnames", ["[CSE-GUID{827D319E-6EAC-11D2-A4EA-00C04F79F83A};Security]"] ])

    let gpoWithMultipleExtensions =
        mkResult LDAPSearchType.GetGroupPolicyObjects defaultLdapDetails (mkMap 
        [ "cn", ["{ABC12345-6789-ABCD-EF01-234567890ABC}"]
          "displayname", ["IT Security Policy"]
          "gpcmachineextensionnames", 
            [ "[CSE-GUID{827D319E-6EAC-11D2-A4EA-00C04F79F83A};Security]"
              "[CSE-GUID{40B6664F-4972-11D1-A7CA-0000F87571E3};ProcessScripts]"
              "[CSE-GUID{25537BA6-77A8-11D2-9B6C-0000F8080861};FolderRedirection]"
              "[CSE-GUID{D76B9641-3288-4F75-942D-087DE603E3EA};AdmPwd]" ]
          "gpcuserextensionnames", [
              "[CSE-GUID{827D319E-6EAC-11D2-A4EA-00C04F79F83A};Security]"
              "[CSE-GUID{40B66650-4972-11D1-A7CA-0000F87571E3};ProcessScripts]"] ])

    let gpoWithUnknownExtension =
        mkResult LDAPSearchType.GetGroupPolicyObjects defaultLdapDetails (mkMap 
        [ "cn", ["{DEADBEEF-CAFE-BABE-1234-567890ABCDEF}"]
          "displayname", ["Custom Vendor GPO"]
          "gpcmachineextensionnames", 
          [ "[CSE-GUID{827D319E-6EAC-11D2-A4EA-00C04F79F83A};Security]"
            "[CSE-GUID{12345678-1234-1234-1234-123456789012};UnknownExtension]"] ])
