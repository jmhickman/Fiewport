namespace Fiewport.Tests

module LDAPDataHandlerTests =

    open Expecto
    open Fiewport

    let dataHandlerTests =
        testList "LDAPDataHandlers" [
            test "handleThingsWithTicks converts FILETIME" {
                let input = TestData.mkMap [ "pwdlastset", ["132345678901234567"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTicks input
                Expect.stringContains (List.head actual.["pwdlastset"]) "2020" "year 2020 in result"
            }

            test "handleThingsWithTicks MaxValue is no expiry" {
                let input = TestData.mkMap [ "accountexpires", ["9223372036854775807"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTicks input
                Expect.equal (List.head actual.["accountexpires"]) "no expiry" "MaxValue maps to no expiry"
            }

            test "handleThingsWithTicks zero is never" {
                let input = TestData.mkMap [ "lastlogon", ["0"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTicks input
                Expect.equal (List.head actual.["lastlogon"]) "never logged in/out" "zero maps to never"
            }

            test "handleThingsWithTicks skips unknown keys" {
                let input = TestData.mkMap [ "cn", ["test"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTicks input
                Expect.equal actual.["cn"] ["test"] "unknown key unchanged"
            }

            test "handleUserAccountControl 512" {
                let input = TestData.mkMap [ "useraccountcontrol", ["512"] ]
                let actual = Fiewport.LDAPDataHandlers.handleUserAccountControl input
                Expect.isTrue (List.contains "NORMAL_ACCOUNT" actual.["useraccountcontrol"]) "512 is NORMAL_ACCOUNT"
            }

            test "handleUserAccountControl 66048 multi-flag" {
                let input = TestData.mkMap [ "useraccountcontrol", ["66048"] ]
                let actual = Fiewport.LDAPDataHandlers.handleUserAccountControl input
                Expect.isTrue (List.contains "NORMAL_ACCOUNT" actual.["useraccountcontrol"]) "contains NORMAL_ACCOUNT"
                Expect.isTrue (List.contains "DONT_EXPIRE_PASSWORD" actual.["useraccountcontrol"]) "contains DONT_EXPIRE_PASSWORD"
            }

            test "handleUserAccountControl missing key" {
                let input = TestData.mkMap [ "cn", ["test"] ]
                let actual = Fiewport.LDAPDataHandlers.handleUserAccountControl input
                Expect.isFalse (Map.containsKey "useraccountcontrol" actual) "no useraccountcontrol key"
            }

            test "handleThingsWithTimespans ticks to hours" {
                let input = TestData.mkMap [ "maxpwdage", ["-864000000000"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTimespans input
                Expect.stringContains (List.head actual.["maxpwdage"]) "24" "24 hours in result"
            }

            test "handleThingsWithTimespans MinValue" {
                let input = TestData.mkMap [ "forcelogoff", ["-9223372036854775808"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithTimespans input
                Expect.equal (List.head actual.["forcelogoff"]) "no expiry" "MinValue maps to no expiry"
            }

            test "handleThingsWithZulus" {
                let input = TestData.mkMap [ "whencreated", ["20240115123045.0Z"] ]
                let actual = Fiewport.LDAPDataHandlers.handleThingsWithZulus input
                Expect.stringContains (List.head actual.["whencreated"]) "2024" "year 2024 in result"
            }

            test "handleGroupType SECURITY" {
                let input = TestData.mkMap [ "grouptype", ["-2147483646"] ]
                let actual = Fiewport.LDAPDataHandlers.handleGroupType input
                Expect.isTrue (List.contains "SECURITY" actual.["grouptype"]) "SECURITY flag present"
            }

            test "handleGenericStrings ADString" {
                let input = Map.ofList [ "cn", [Fiewport.Types.ADString "test"] ]
                let actual = Fiewport.LDAPDataHandlers.handleGenericStrings input
                Expect.equal actual.["cn"] ["test"] "ADString converted"
            }

            test "handleGenericStrings ADBytes to UTF-8" {
                let bytes = System.Text.Encoding.UTF8.GetBytes "hello"
                let input = Map.ofList [ "description", [Fiewport.Types.ADBytes bytes] ]
                let actual = Fiewport.LDAPDataHandlers.handleGenericStrings input
                Expect.equal actual.["description"] ["hello"] "ADBytes decoded as UTF-8"
            }

            test "handleTrustDirection OUTBOUND" {
                let input = TestData.mkMap [ "trustdirection", ["2"] ]
                let actual = Fiewport.LDAPDataHandlers.handleTrustDirection input
                Expect.isTrue (List.contains "TRUST_DIRECTION_OUTBOUND" actual.["trustdirection"]) "OUTBOUND present"
            }

            test "handleRepSto removes repsto" {
                let input = TestData.mkMap [ "repsto", ["CN=DC,DC=test"] ]
                let actual = Fiewport.LDAPDataHandlers.handleRepSto input
                Expect.isFalse (Map.containsKey "repsto" actual) "repsto removed"
            }

            test "handleInstanceType WritableOnThisDirectory" {
                let input = TestData.mkMap [ "instancetype", ["4"] ]
                let actual = Fiewport.LDAPDataHandlers.handleInstanceType input
                Expect.isTrue (List.contains "WritableOnThisDirectory" actual.["instancetype"]) "WritableOnThisDirectory present"
            }
        ]
