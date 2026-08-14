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
              SerializerTests.serializerTests
              SearcherTests.searcherTests
              FauliAuthTests.fauliAuthTests
              LdapWireTests.allTests
              LdapSearchTests.allTests ]

    [<EntryPoint>]
    let main argv =
        runTestsWithCLIArgs [] argv allTests
