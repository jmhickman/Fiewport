namespace Fiewport.Tests

module Program =

    open Expecto

    [<Tests>]
    let allTests =
        testList "Fiewport" [
            FilterTests.filterTests
            MoldTests.moldTests
            TeeTests.teeTests
            LDAPDataHandlerTests.dataHandlerTests
            SecurityDescriptorTests.securityDescriptorTests
            ByteHandlerTests.allTests
        ]

    [<EntryPoint>]
    let main argv =
        runTestsWithCLIArgs [] argv allTests
