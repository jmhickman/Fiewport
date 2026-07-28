namespace Fiewport.Tests

module Program =

    open Expecto

    [<Tests>]
    let allTests =
        testList "Fiewport" 
            [ FilterTests.filterTests
              GPOHandlerTests.handlerTests
              MoldTests.moldTests
              TeeTests.teeTests
              LDAPDataHandlerTests.dataHandlerTests
              SecurityDescriptorTests.securityDescriptorTests
              ByteHandlerTests.allTests
              SerializerTests.serializerTests ]

    [<EntryPoint>]
    let main argv =
        runTestsWithCLIArgs [] argv allTests
