namespace Fiewport.Tests

module LDAPDataHandlerTests =

    open Expecto
    open Fiewport

    let dataHandlerTests =
        testList "LDAPDataHandlers" [
            testCase "handleThingsWithTicks converts FILETIME" <| fun () ->
                let input = TestData.mkMap [ "pwdlastset", ["132345678901234567"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTicks input
                Expect.stringContains "2012" (List.head actual["pwdlastset"])

            testCase "handleThingsWithTicks MaxValue is no expiry" <| fun () ->
                let input = TestData.mkMap [ "accountexpires", ["9223372036854775807"] ]
                Expect.equal (List.head (Fiewport.LDAPDataHandlers.handleThingsWithTicks input)["accountexpires"]) "no expiry"

            testCase "handleThingsWithTicks zero is never" <| fun () ->
                let input = TestData.mkMap [ "lastlogon", ["0"] ]
                Expect.equal (List.head (Fiewport.LDAPDataHandlers.handleThingsWithTicks input)["lastlogon"]) "never logged in/out"

            testCase "handleThingsWithTicks skips unknown keys" <| fun () ->
                let input = TestData.mkMap [ "cn", ["test"] ]
                Expect.equal (Fiewport.LDAPDataHandlers.handleThingsWithTicks input)["cn"] ["test"]

            testCase "handleUserAccountControl 512" <| fun () ->
                let input = TestData.mkMap [ "useraccountcontrol", ["512"] ]
                Expect.isTrue (List.contains "NORMAL_ACCOUNT" (Fiewport.LDAPDataHandlers.handleUserAccountControl input)["useraccountcontrol"])

            testCase "handleUserAccountControl 66048 multi-flag" <| fun () ->
                let input = TestData.mkMap [ "useraccountcontrol", ["66048"] ]
                let actual = Fiewport.LDAPDataHandlers.handleUserAccountControl input
                Expect.isTrue (List.contains "NORMAL_ACCOUNT" actual["useraccountcontrol"])
                Expect.isTrue (List.contains "DONT_EXPIRE_PASSWORD" actual["useraccountcontrol"])

            testCase "handleUserAccountControl missing key" <| fun () ->
                let input = TestData.mkMap [ "cn", ["test"] ]
                Expect.isFalse (Map.containsKey "useraccountcontrol" (Fiewport.LDAPDataHandlers.handleUserAccountControl input))

            testCase "handleThingsWithTimespans ticks to hours" <| fun () ->
                let input = TestData.mkMap [ "maxpwdage", ["-864000000000"] ]
                Expect.stringContains "240" (List.head (Fiewport.LDAPDataHandlers.handleThingsWithTimespans input)["maxpwdage"])

            testCase "handleThingsWithTimespans MinValue" <| fun () ->
                let input = TestData.mkMap [ "forcelogoff", ["-9223372036854775808"] ]
                Expect.equal (List.head (Fiewport.LDAPDataHandlers.handleThingsWithTimespans input)["forcelogoff"]) "no expiry"

            testCase "handleThingsWithZulus" <| fun () ->
                let input = TestData.mkMap [ "whencreated", ["20240115123045.0Z"] ]
                Expect.stringContains "2024" (List.head (Fiewport.LDAPDataHandlers.handleThingsWithZulus input)["whencreated"])

            testCase "handleGroupType SECURITY" <| fun () ->
                let input = TestData.mkMap [ "grouptype", ["-2147483646"] ]
                Expect.isTrue (List.contains "SECURITY" (Fiewport.LDAPDataHandlers.handleGroupType input)["grouptype"])

            testCase "handleGenericStrings ADString" <| fun () ->
                let input = Map.ofList [ "cn", [Fiewport.Types.ADString "test"] ]
                Expect.equal (Fiewport.LDAPDataHandlers.handleGenericStrings input)["cn"] ["test"]

            testCase "handleGenericStrings ADBytes to UTF-8" <| fun () ->
                let bytes = System.Text.Encoding.UTF8.GetBytes "hello"
                let input = Map.ofList [ "description", [Fiewport.Types.ADBytes bytes] ]
                Expect.equal (Fiewport.LDAPDataHandlers.handleGenericStrings input)["description"] ["hello"]

            testCase "handleTrustDirection OUTBOUND" <| fun () ->
                let input = TestData.mkMap [ "trustdirection", ["2"] ]
                Expect.isTrue (List.contains "TRUST_DIRECTION_OUTBOUND" (Fiewport.LDAPDataHandlers.handleTrustDirection input)["trustdirection"])

            testCase "handleRepSto removes repsto" <| fun () ->
                let input = TestData.mkMap [ "repsto", ["CN=DC,DC=test"] ]
                Expect.isFalse (Map.containsKey "repsto" (Fiewport.LDAPDataHandlers.handleRepSto input))

            testCase "handleInstanceType WritableOnThisDirectory" <| fun () ->
                let input = TestData.mkMap [ "instancetype", ["4"] ]
                Expect.isTrue (List.contains "WritableOnThisDirectory" (Fiewport.LDAPDataHandlers.handleInstanceType input)["instancetype"])
        ]
