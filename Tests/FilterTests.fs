namespace Fiewport.Tests

module FilterTests =

    open Expecto
    open Fiewport

    let filterTests =
        testList "Filter" [
            test "attributePresent filters correctly" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                let actual = Filter.attributePresent "adminCount" input
                Expect.equal actual.Length 2 "Outer list preserved"
                Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser has adminCount"
                Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser no adminCount" }
            test "attributePresent empty input" {
                Expect.equal (Filter.attributePresent "x" []) [] "Empty input returns empty" }
            test "attributeIsValue filters by key and value" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                let actual = Filter.attributeIsValue "cn" "Administrator" input
                Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser matches"
                Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser no match" }
            test "attributeIsValue no match" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                let actual = Filter.attributeIsValue "cn" "nonexistent" input
                Expect.equal ((List.head actual).ldapData |> List.length) 0 "no match in adminUser"
                Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "no match in regularUser" }
            test "valueIs finds value across any key" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                let actual = Filter.valueIs "Administrator" input
                Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser has Administrator"
                Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser no Administrator" }
            test "byConfig isolates by config" {
                let altLdapDetails = { TestData.defaultLdapDetails with ldapHost = "10.0.0.1" }
                let altResult = TestData.mkResult LDAPSearchType.GetUsers altLdapDetails (TestData.mkMap [ "cn", ["other"] ])
                let input = [ TestData.adminUser; altResult ]
                Expect.equal (Filter.byConfig TestData.defaultLdapDetails input).Length 1 "only defaultConfig result" }
            test "byConfig includes error results" {
                let altLdapDetails = { TestData.defaultLdapDetails with ldapHost = "9.9.9.9" }
                let err = TestData.mkErrorResult altLdapDetails "refused"
                Expect.equal (Filter.byConfig TestData.defaultLdapDetails [ TestData.adminUser; err ]).Length 2 "error results always pass" }
            test "chained filters compound" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                let actual = Filter.attributePresent "adminCount" input |> Filter.attributeIsValue "cn" "Administrator"
                Expect.equal ((List.head actual).ldapData |> List.length) 1 "adminUser passes both"
                Expect.equal ((List.item 1 actual).ldapData |> List.length) 0 "regularUser filtered out" } ]
