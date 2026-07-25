namespace Fiewport.Tests

module GPOHandlerTests =

    open Expecto
    open Fiewport
    open Fiewport.Types

    let mkMap (pairs : (string * string list) list) : Map<string, string list> =
        Map.ofList pairs

    let handlerTests =
        testList "GPO CSE Handler" [
            test "resolves single extension pair" {
                // [{CSE_GUID}{AdminTool_GUID}]
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Security -> Computer Restricted Groups]"] "Pair resolved"
            }

            test "resolves multiple extension pairs" {
                // Real AD format: [{GUID}{GUID}][{GUID}{GUID}]...
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Registry Settings -> Certificates] [Security -> Computer Restricted Groups] [EFS Recovery -> Certificates]"] "All 3 pairs resolved"
            }

            test "resolves LAPS AdmPwd extension" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{D76B9641-3288-4F75-942D-087DE603E3EA}{D76B9641-3288-4F75-942D-087DE603E3EA}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[AdmPwd (LAPS) -> AdmPwd (LAPS)]"] "LAPS GUID resolved"
            }

            test "resolves Scripts extension" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{40B6664F-4972-11D1-A7CA-0000F87571E3}{42B5FAAE-6536-11D2-AE5A-0000F87571E3}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Scripts (Startup/Shutdown) -> ProcessScripts]"] "Scripts GUID resolved"
            }

            test "preserves unknown GUIDs in pairs" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{12345678-1234-1234-1234-123456789012}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Security -> {12345678-1234-1234-1234-123456789012}]"] "Known resolved, unknown preserved"
            }

            test "handles gPCUserExtensionNames" {
                let input = mkMap [
                    "gpcuserextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcuserextensionnames"] ["[Security -> Computer Restricted Groups]"] "User extension resolved"
            }

            test "handles both attributes simultaneously" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"]
                    "gpcuserextensionnames", ["[{40B66650-4972-11D1-A7CA-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Security -> Computer Restricted Groups]"] "Machine extension resolved"
                Expect.equal actual["gpcuserextensionnames"] ["[Scripts (Logon/Logoff) -> Scripts (Logon/Logoff)]"] "User extension resolved"
            }

            test "leaves map unchanged when no GPO attributes present" {
                let input = mkMap [
                    "cn", ["SomeObject"]
                    "displayname", ["Some Display Name"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual input "No changes when GPO attributes absent"
            }

            test "handles malformed value gracefully" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["Not a valid CSE-GUID format"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["Not a valid CSE-GUID format"] "Malformed value preserved"
            }

            test "case-insensitive GUID lookup" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{827d319e-6eac-11d2-a4ea-00c04f79f83a}{803e14a0-b4fb-11d0-a0d0-00a0c90f574b}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Security -> Computer Restricted Groups]"] "Lowercase GUIDs resolved"
            }

            test "resolves VBS/DeviceGuard extension" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{F312195E-3D9D-447A-A3F5-08DFFA24735E}{F312195E-3D9D-447A-A3F5-08DFFA24735E}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[VirtualizationBasedSecurity (DeviceGuard) -> VirtualizationBasedSecurity (DeviceGuard)]"] "VBS GUID resolved"
            }

            test "resolves Folder Redirection extension" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{25537BA6-77A8-11D2-9B6C-0000F8080861}{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Folder Redirection -> Folder Redirection]"] "Folder Redirection resolved"
            }

            test "resolves Software Installation extension" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{942A8E4F-A261-11D1-A760-00C04FB9603F}{942A8E4F-A261-11D1-A760-00C04FB9603F}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Software Installation (Computers) -> Software Installation (Computers)]"] "Software Install resolved"
            }

            test "resolves IP Security extension" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{E437BC1C-AA7D-11D2-A382-00C04F991E27}{E437BC1C-AA7D-11D2-A382-00C04F991E27}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[IP Security (IPSec) -> IP Security (IPSec)]"] "IPSec resolved"
            }

            test "resolves Core GPO Engine" {
                let input = mkMap [
                    "gpcmachineextensionnames", ["[{00000000-0000-0000-0000-000000000000}{00000000-0000-0000-0000-000000000000}]"] ]
                let actual = LDAPDataHandlers.handleGroupPolicyCseGuids input
                Expect.equal actual["gpcmachineextensionnames"] ["[Core GPO Engine -> Core GPO Engine]"] "Core engine resolved"
            }
        ]
