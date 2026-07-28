namespace Fiewport.Tests

module GPOHandlerTests =

    open Expecto
    open Fiewport
    open Fiewport.Types

    let mkMap (pairs : (string * string list) list) : Map<string, string list> =
        Map.ofList pairs

    let handlerTests =
        testList "GPO CSE Handler" 
            [
            test "resolves single extension pair" // [{CSE_GUID}{AdminTool_GUID}]
                { let input = mkMap ["gpcmachineextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"] ]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcmachineextensionnames"] ["[Security -> Computer Restricted Groups]"] "Pair resolved" }

            test "resolves multiple extension pairs" // Real AD format: [{GUID}{GUID}][{GUID}{GUID}]...
                { let input = 
                    mkMap 
                      [ "gpcmachineextensionnames", 
                      [ "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]" ]]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcmachineextensionnames"] ["[Registry Settings -> Certificates] [Security -> Computer Restricted Groups] [EFS Recovery -> Certificates]"] "All 3 pairs resolved" }

            test "resolves LAPS AdmPwd extension" 
                { let input = 
                    mkMap ["gpcmachineextensionnames", ["[{D76B9641-3288-4F75-942D-087DE603E3EA}{D76B9641-3288-4F75-942D-087DE603E3EA}]"] ]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcmachineextensionnames"] ["[AdmPwd (LAPS) -> AdmPwd (LAPS)]"] "LAPS GUID resolved" }

            test "resolves Scripts extension" 
                { let input = 
                    mkMap ["gpcmachineextensionnames", ["[{40B6664F-4972-11D1-A7CA-0000F87571E3}{42B5FAAE-6536-11D2-AE5A-0000F87571E3}]"] ]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcmachineextensionnames"] ["[Scripts (Startup/Shutdown) -> ProcessScripts]"] "Scripts GUID resolved" }

            test "preserves unknown GUIDs in pairs" 
                { let input = 
                    mkMap ["gpcmachineextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{12345678-1234-1234-1234-123456789012}]"] ]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcmachineextensionnames"] ["[Security -> {12345678-1234-1234-1234-123456789012}]"] "Known resolved, unknown preserved" }

            test "handles gPCUserExtensionNames" 
                { let input = 
                    mkMap ["gpcuserextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"] ]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcuserextensionnames"] ["[Security -> Computer Restricted Groups]"] "User extension resolved" }

            test "handles both attributes simultaneously" 
                { let input = 
                    mkMap [ "gpcmachineextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"]
                            "gpcuserextensionnames", ["[{40B66650-4972-11D1-A7CA-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]"] ]
                  let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                  Expect.equal actual["gpcmachineextensionnames"] ["[Security -> Computer Restricted Groups]"] "Machine extension resolved"
                  Expect.equal actual["gpcuserextensionnames"] ["[Scripts (Logon/Logoff) -> Scripts (Logon/Logoff)]"] "User extension resolved" }]
