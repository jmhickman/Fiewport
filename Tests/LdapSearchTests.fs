namespace Fiewport.Tests

module LdapSearchTests =

    open System
    open Expecto
    open Fiewport

    let private sampleConfig =
        { properties = [| "cn" |]
          filter = "(objectClass=user)"
          ldapDN = "DC=example,DC=com"
          scope = Subtree
          ldapHostname = "dc.example.com"
          ldapIP = ""
          ldapPort = 389
          useSsl = false }

    let private entry dn attrs : RawLdapEntry =
        { DN = dn
          Attributes = Map.ofList attrs }

    let private allTestsBody =
        testList "LDAPUtils result pipeline"
            [ test "rawEntriesToMaps preserves multi-valued attributes as ADBytes" {
                  let entries =
                      [ entry "CN=test,DC=example,DC=com"
                            [ "cn", [ [| 116uy; 101uy; 115uy; 116uy |] ]
                              "objectclass",
                              [ [| 116uy; 111uy; 112uy |]
                                [| 112uy; 101uy; 114uy; 115uy; 111uy; 110uy |] ] ] ]

                  let maps = LDAPUtils.rawEntriesToMaps entries
                  Expect.equal maps.Length 1 "one map per entry"
                  let m = maps.[0]
                  match m.["cn"] with
                  | [ ADBytes b ] -> Expect.equal b (Text.Encoding.UTF8.GetBytes "test") "cn bytes"
                  | other -> failtest $"expected single ADBytes cn, got {other}"
                  match m.["objectclass"] with
                  | [ ADBytes a; ADBytes b ] ->
                      Expect.equal (Text.Encoding.UTF8.GetString a) "top" "oc0"
                      Expect.equal (Text.Encoding.UTF8.GetString b) "person" "oc1"
                  | other -> failtest $"expected two ADBytes objectClass values, got {other}"
              }

              test "rawEntriesToMaps drops attributes whose value list is empty" {
                  let entries =
                      [ entry "CN=empty,DC=example,DC=com"
                            [ "cn", []
                              "description", [ [| 120uy |] ] ] ]
                  let m = (LDAPUtils.rawEntriesToMaps entries)[0]
                  Expect.isFalse (m.ContainsKey "cn") "empty value list removed"
                  Expect.isTrue (m.ContainsKey "description") "non-empty kept"
              }

              test "createLDAPSearchResults Ok runs handlers and preserves search metadata" {
                  // objectGuid (16 bytes) exercises a byte handler; cn exercises string handler
                  let guidBytes = Array.init 16 (fun i -> uint8 (i + 1))
                  let entries =
                      [ entry "CN=alice,DC=example,DC=com"
                            [ "cn", [ Text.Encoding.UTF8.GetBytes "alice" ]
                              "objectguid", [ guidBytes ] ] ]

                  let result =
                      LDAPUtils.createLDAPSearchResults LDAPSearchType.GetUsers sampleConfig (Ok entries)

                  Expect.equal result.searchType LDAPSearchType.GetUsers "search type"
                  Expect.equal result.searchConfig sampleConfig "config preserved"
                  Expect.isNone result.ldapSearcherError "no error"
                  Expect.equal result.ldapData.Length 1 "one entry"
                  let data = result.ldapData.[0]
                  Expect.equal data.["cn"] [ "alice" ] "cn decoded to string"
                  match data.TryFind "objectguid" with
                  | Some [ guidStr ] ->
                      Expect.isTrue (guidStr.Contains "-") $"GUID-shaped string, got {guidStr}"
                  | other -> failtest $"expected objectguid string list, got {other}"
              }

              test "createLDAPSearchResults Error surfaces wire error and empty data" {
                  let err: LdapWireError = ConnectionFailed "network unreachable"
                  let result =
                      LDAPUtils.createLDAPSearchResults LDAPSearchType.GetDomainSID sampleConfig (Error err)

                  Expect.equal result.searchType LDAPSearchType.GetDomainSID "search type"
                  Expect.equal result.searchConfig sampleConfig "config preserved"
                  match result.ldapSearcherError with
                  | Some e ->
                      Expect.stringContains e.message "network unreachable" "error message"
                      Expect.equal e.context "search" "context"
                  | None -> failtest "expected ldapSearcherError"
                  Expect.equal result.ldapData [ Map.empty ] "empty data placeholder on error"
              }]

    let allTests = allTestsBody
