namespace Fiewport.Tests

module TeeTests =

    open Expecto
    open Fiewport

    let teeTests =
        testList "Tee" [
            test "filter preserves content" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                Expect.equal (Tee.filter (Filter.attributePresent "adminCount") ignore input) input "content preserved"
            }
            test "filter invokes action" {
                let input = [ TestData.adminUser; TestData.regularUser ]
                let mutable captured = [] : LDAPSearchResult list
                let action (results: LDAPSearchResult list) = captured <- results
                Tee.filter (Filter.attributePresent "adminCount") action input |> ignore
                Expect.equal captured.Length 2 "action received results"
            }
            test "mold preserves results" {
                Expect.equal (Tee.mold Mold.getKeys ignore [ TestData.adminUser; TestData.regularUser ]).Length 2 "results preserved"
            }
            test "mold invokes action" {
                let mutable captured = false
                let action (_keys: string list list list) = captured <- true
                Tee.mold Mold.getKeys action [ TestData.adminUser ] |> ignore
                Expect.isTrue captured "action was called"
            }
        ]
