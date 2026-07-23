namespace Fiewport.Tests

module MoldTests =

    open Expecto
    open Fiewport

    let moldTests =
        testList "Mold" [
            test "getKeys returns attribute names per map" {
                let actual = Mold.getKeys [ TestData.adminUser ]
                Expect.equal actual.Length 1 "one result"
                let keys = List.head actual |> List.head
                Expect.isTrue (List.contains "cn" keys) "has cn"
                Expect.isTrue (List.contains "adminCount" keys) "has adminCount"
            }

            test "composeResults returns tuples" {
                let actual = Mold.composeResults [ TestData.adminUser ]
                Expect.isTrue (List.exists (fun (k, _) -> k = "cn") actual) "has cn tuple"
                Expect.isTrue (List.exists (fun (k, _) -> k = "adminCount") actual) "has adminCount tuple"
            }

            test "extractOccurances returns flat string list for existing key" {
                let actual = Mold.extractOccurances "cn" [ TestData.adminUser; TestData.regularUser ]
                Expect.equal actual ["Administrator"; "jsmith"] "two values in order"
            }

            test "extractOccurances returns empty list for missing key" {
                let actual = Mold.extractOccurances "nonexistent" [ TestData.adminUser ]
                Expect.equal actual [] "no entries found"
            }

            test "extractOccurances skips entries that lack the key" {
                let actual = Mold.extractOccurances "adminCount" [ TestData.adminUser; TestData.computerObject ]
                Expect.equal actual ["1"] "only one value present"
            }
        ]
