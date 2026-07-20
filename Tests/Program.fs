namespace Fiewport.Tests

module Program =

    open Expecto

    let allTests =
        testList "Fiewport" [
            FilterTests.filterTests
            MoldTests.moldTests
            TeeTests.teeTests
            LDAPDataHandlerTests.dataHandlerTests
        ]

    [<EntryPoint>]
    let main argv =
        runTestsWithCLIArgs [] argv allTests
