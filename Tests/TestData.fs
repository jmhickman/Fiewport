namespace Fiewport.Tests

module TestData =

    open Fiewport.Types

    let defaultConfig : SearcherConfig =
        { properties = [||]
          filter = ""
          ldapDN = "DC=test,DC=local"
          scope = SearchScope.Subtree
          ldapHost = "192.168.56.10"
          ldapPort = 389
          useSsl = false
          username = "testuser"
          password = "P@ssw0rd" }

    let mkMap (pairs : (string * string list) list) : Map<string, string list> =
        Map.ofList pairs

    let mkResult (searchType : LDAPSearchType) (config : SearcherConfig) (data : Map<string, string list>) =
        { searchType = searchType
          searchConfig = config
          ldapSearcherError = None
          ldapData = [data] }

    let mkErrorResult (config : SearcherConfig) (message : string) =
        { searchType = LDAPSearchType.GetUsers
          searchConfig = config
          ldapSearcherError = Some message
          ldapData = [Map.empty] }

    let adminUser =
        mkResult LDAPSearchType.GetUsers defaultConfig (mkMap [
            "cn", ["Administrator"]
            "sAMAccountName", ["admin"]
            "adminCount", ["1"]
            "useraccountcontrol", ["66048"] ])

    let regularUser =
        mkResult LDAPSearchType.GetUsers defaultConfig (mkMap [
            "cn", ["jsmith"]
            "sAMAccountName", ["jsmith"]
            "useraccountcontrol", ["512"] ])

    let computerObject =
        mkResult LDAPSearchType.GetComputers defaultConfig (mkMap [
            "cn", ["WORKSTATION01"]
            "dnshostname", ["workstation01.test.local"] ])
