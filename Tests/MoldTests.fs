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
        ]
