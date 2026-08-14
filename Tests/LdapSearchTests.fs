namespace Fiewport.Tests

module LdapSearchTests =

    open System
    open Expecto
    open Fiewport
    open Fiewport.Types
    open Fiewport.LdapSearch
    open Fiewport.LdapWire

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

    let private sslPrimary =
        { sampleConfig with
            useSsl = true
            ldapPort = 636 }

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
                      LDAPUtils.createLDAPSearchResults LDAPSearchType.GetUsers sampleConfig (Ok (entries, Fauli.Domain.AuthenticationMethod.Kerberos))

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
              } ]

    let private chaseTests =
        testList "referral chase"
            [ test "buildChaseConfig preserves filter scope properties; takes host port dn ssl" {
                  match parseLdapUrl "ldap://child.example.com:389/DC=child,DC=example,DC=com??sub?" with
                  | Error e -> failtest $"parse failed: {e}"
                  | Ok parsed ->
                      match buildReferralTarget sampleConfig parsed with
                      | Error e -> failtest $"target failed: {e}"
                      | Ok target ->
                          let chase = buildChaseConfig sampleConfig target
                          Expect.equal chase.filter sampleConfig.filter "filter"
                          Expect.equal chase.scope sampleConfig.scope "scope"
                          Expect.equal chase.properties sampleConfig.properties "properties"
                          Expect.equal chase.ldapHostname "child.example.com" "host"
                          Expect.equal chase.ldapIP "" "ip empty for hostname"
                          Expect.equal chase.ldapPort 389 "port"
                          Expect.equal chase.ldapDN "DC=child,DC=example,DC=com" "base DN from URL"
                          Expect.equal chase.useSsl false "plain"
              }

              test "ldap:// default port inherits primary LDAPS transport" {
                  match parseLdapUrl "ldap://child.example.com/DC=child,DC=example,DC=com" with
                  | Error e -> failtest $"parse: {e}"
                  | Ok parsed ->
                      match buildReferralTarget sslPrimary parsed with
                      | Error e -> failtest $"target: {e}"
                      | Ok target ->
                          Expect.equal target.useSsl true "inherit ssl"
                          Expect.equal target.port 636 "ssl default port"
              }

              test "ldaps:// forces TLS even when primary is plain" {
                  match parseLdapUrl "ldaps://secure.example.com/DC=example,DC=com" with
                  | Error e -> failtest $"parse: {e}"
                  | Ok parsed ->
                      match buildReferralTarget sampleConfig parsed with
                      | Error e -> failtest $"target: {e}"
                      | Ok target ->
                          Expect.equal target.useSsl true "ldaps"
                          Expect.equal target.port 636 "default ldaps port"
              }

              test "empty-host URL reuses primary host" {
                  match parseLdapUrl "ldap:///DC=ForestDnsZones,DC=example,DC=com" with
                  | Error e -> failtest $"parse: {e}"
                  | Ok parsed ->
                      match buildReferralTarget sampleConfig parsed with
                      | Error e -> failtest $"target: {e}"
                      | Ok target ->
                          Expect.equal target.host "dc.example.com" "primary host"
                          Expect.equal target.baseDn "DC=ForestDnsZones,DC=example,DC=com" "dn from url"
              }

              test "chaseReferrals merges successful branch entries" {
                  let childEntry =
                      entry "CN=bob,DC=child,DC=example,DC=com"
                          [ "cn", [ Text.Encoding.UTF8.GetBytes "bob" ] ]
                  let seed =
                      [ entry "CN=alice,DC=example,DC=com"
                            [ "cn", [ Text.Encoding.UTF8.GetBytes "alice" ] ] ]
                  let searchOne : SearchOneServer =
                      fun cfg ->
                          Expect.equal cfg.filter sampleConfig.filter "chase filter"
                          Expect.equal cfg.scope sampleConfig.scope "chase scope"
                          Expect.equal cfg.ldapHostname "child.example.com" "chase host"
                          Ok
                              { entries = [ childEntry ]
                                referralUris = [] }
                  match primaryReferralTarget sampleConfig with
                  | Error e -> failtest $"primary target: {e}"
                  | Ok primaryTarget ->
                      match chaseReferrals searchOne sampleConfig primaryTarget seed [ "ldap://child.example.com/DC=child,DC=example,DC=com" ] with
                      | Error e -> failtest $"chase failed: {e}"
                      | Ok entries ->
                          Expect.equal entries.Length 2 "seed + chased"
                          Expect.equal entries.[0].DN "CN=alice,DC=example,DC=com" "seed first"
                          Expect.equal entries.[1].DN "CN=bob,DC=child,DC=example,DC=com" "chased second"
              }

              test "chaseReferrals skips already-visited targets (loop)" {
                  let mutable calls = 0
                  let searchOne : SearchOneServer =
                      fun _ ->
                          calls <- calls + 1
                          Ok
                              { entries = []
                                // refers back to primary host/dn
                                referralUris = [ "ldap://dc.example.com:389/DC=example,DC=com" ] }
                  match primaryReferralTarget sampleConfig with
                  | Error e -> failtest $"primary: {e}"
                  | Ok primaryTarget ->
                      // Seed URI points at a *different* host so first chase runs once and returns loop URI
                      match chaseReferrals searchOne sampleConfig primaryTarget [] [ "ldap://other.example.com/DC=other,DC=com" ] with
                      | Error e -> failtest $"chase: {e}"
                      | Ok _ ->
                          Expect.equal calls 1 "only one chase call; primary re-visit skipped"
              }

              test "chaseReferrals soft-fails branch and keeps seed entries" {
                  let seed =
                      [ entry "CN=alice,DC=example,DC=com"
                            [ "cn", [ Text.Encoding.UTF8.GetBytes "alice" ] ] ]
                  let searchOne : SearchOneServer =
                      fun _ -> Error (BindFailed "bad password on child")
                  match primaryReferralTarget sampleConfig with
                  | Error e -> failtest $"primary: {e}"
                  | Ok primaryTarget ->
                      match chaseReferrals searchOne sampleConfig primaryTarget seed [ "ldap://child.example.com/DC=child,DC=com" ] with
                      | Error e -> failtest $"should keep seed, got {e}"
                      | Ok entries ->
                          Expect.equal entries.Length 1 "seed retained"
                          Expect.equal entries.[0].DN "CN=alice,DC=example,DC=com" "alice"
              }

              test "chaseReferrals empty seed and all branches fail → BindFailed" {
                  let searchOne : SearchOneServer =
                      fun _ -> Error (ConnectionFailed "down")
                  match primaryReferralTarget sampleConfig with
                  | Error e -> failtest $"primary: {e}"
                  | Ok primaryTarget ->
                      match chaseReferrals searchOne sampleConfig primaryTarget [] [ "ldap://child.example.com/DC=child,DC=com" ] with
                      | Error (BindFailed msg) ->
                          Expect.stringContains msg "Referral chase failed" "bind-style finalize"
                      | other -> failtest $"expected BindFailed, got {other}"
              } ]

    let allTests =
        testList "LdapSearch"
            [ allTestsBody
              chaseTests ]
