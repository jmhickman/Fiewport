namespace Fiewport.Tests

module FilterTests =

    open Expecto
    
    open Fiewport

    let filterTests =
        testList "Filter"
            [ test "attributePresent filters correctly" 
                { let input = [ TestData.adminUser; TestData.regularUser ]
                  let actual = Filter.attributePresent "adminCount" input
                  Expect.equal actual.Length 2 "Outer list preserved"
                  Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser has adminCount"
                  Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser no adminCount" }
              test "attributePresent empty input" 
                { Expect.equal (Filter.attributePresent "x" []) [] "Empty input returns empty" }
              test "attributeIsValue filters by key and value" 
                  { let input = [ TestData.adminUser; TestData.regularUser ]
                    let actual = Filter.attributeIsValue "cn" "Administrator" input
                    Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser matches"
                    Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser no match" }
              test "attributeIsValue no match" 
                  { let input = [ TestData.adminUser; TestData.regularUser ]
                    let actual = Filter.attributeIsValue "cn" "nonexistent" input
                    Expect.equal ((List.head actual).ldapData |> List.length) 0 "no match in adminUser"
                    Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "no match in regularUser" }
              test "valueIs finds value across any key" 
                  { let input = [ TestData.adminUser; TestData.regularUser ]
                    let actual = Filter.valueIs "Administrator" input
                    Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser has Administrator"
                    Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser no Administrator" }
              test "byConfig isolates by config" 
                  { let altLdapDetails = { TestData.defaultLdapDetails with ldapHostname = ""; ldapIP = "10.0.0.1"}
                    let altResult = TestData.mkResult LDAPSearchType.GetUsers altLdapDetails (TestData.mkMap [ "cn", ["other"] ])
                    let input = [ TestData.adminUser; altResult ]
                    Expect.equal (Filter.byConfig TestData.defaultLdapDetails input).Length 1 "only defaultConfig result" }
              test "byConfig includes error results" 
                  { let altLdapDetails = { TestData.defaultLdapDetails with ldapHostname = ""; ldapIP = "9.9.9.9"}
                    let err = TestData.mkErrorResult altLdapDetails "refused"
                    Expect.equal (Filter.byConfig TestData.defaultLdapDetails [ TestData.adminUser; err ]).Length 2 "error results always pass" }
              test "chained filters compound" 
                  { let input = [ TestData.adminUser; TestData.regularUser ]
                    let actual = Filter.attributePresent "adminCount" input |> Filter.attributeIsValue "cn" "Administrator"
                    Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser passes both"
                    Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser filtered out" }
              test "showMany keeps only listed attributes"
                  { let input = [ TestData.adminUser ]
                    let actual = Filter.showMany [| "cn"; "adminCount" |] input
                    let map = (List.head actual).ldapData |> List.head
                    Expect.isTrue (map.ContainsKey "cn") "cn kept"
                    Expect.isTrue (map.ContainsKey "adminCount") "adminCount kept"
                    Expect.isFalse (map.ContainsKey "sAMAccountName") "sAMAccountName dropped"
                    Expect.equal map.Count 2 "only two keys" }
              test "showMany is case-insensitive on attribute names"
                  { let input = [ TestData.adminUser ]
                    let actual = Filter.showMany [| "CN"; "ADMINCOUNT" |] input
                    let map = (List.head actual).ldapData |> List.head
                    Expect.isTrue (map.ContainsKey "cn") "cn kept via case-insensitive match"
                    Expect.isTrue (map.ContainsKey "adminCount") "adminCount kept" }
              test "showMany accepts AttributePresets.terse"
                  { let rich =
                        TestData.mkResult GetUsers TestData.defaultLdapDetails
                            (TestData.mkMap
                                [ "cn", ["x"]
                                  "name", ["x"]
                                  "samaccountname", ["x"]
                                  "distinguishedname", ["CN=x"]
                                  "objectclass", ["user"]
                                  "objectcategory", ["person"]
                                  "mail", ["x@y.z"]
                                  "description", ["noise"] ])
                    let actual = Filter.showMany AttributePresets.terse [ rich ]
                    let map = (List.head actual).ldapData |> List.head
                    Expect.isFalse (map.ContainsKey "mail") "mail not in terse"
                    Expect.isFalse (map.ContainsKey "description") "description not in terse"
                    Expect.isTrue (map.ContainsKey "cn") "cn in terse" }
              test "attributeValueContains matches any value substring"
                  { let input = [ TestData.adminUser; TestData.regularUser ]
                    let actual = Filter.attributeValueContains "Market" input
                    Expect.equal ((List.head actual).ldapData |> List.length) 0 "admin has no Marketing"
                    Expect.equal ((List.item 1 actual).ldapData |> List.length) 1 "regularUser department Marketing" }
              test "attributeValueContains is case-insensitive"
                  { let input = [ TestData.regularUser ]
                    let actual = Filter.attributeValueContains "ebony.kelly@ad-lab.com" input
                    Expect.equal ((List.head actual).ldapData |> List.length) 1 "mail matched ignore case" }
              test "attributeValueContains no match yields empty ldapData"
                  { let input = [ TestData.adminUser ]
                    let actual = Filter.attributeValueContains "zzznomatch" input
                    Expect.equal ((List.head actual).ldapData |> List.length) 0 "no hit" } ]
