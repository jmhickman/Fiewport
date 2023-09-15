#i """nuget: C:\Users\Jon\source\Fiewport\bin\Debug"""
#r "nuget: Fiewport"

open Fiewport
open Fiewport.LDAPRecords

// LDAP://ASTRALEXPRESS.local/CN=Schema,CN=Configuration,DC=astralexpress,DC=local
let domainConnection =
    getDomainConnection
        "LDAP://astralexpress.local/CN=Extended-Rights,CN=Configuration,DC=ASTRALEXPRESS,DC=local"
        "administrator"
        "beefb33fBeef"
let defaults = defaultDirectorySearcher ()

//

// not case sensitive in search items himeko|HIMEKO
// distinguishedname=CN=HIMEKO,OU=Domain Controllers,DC=ASTRALEXPRESS,DC=local works
// dn=* does not
// objectcategory=CN=Computer,CN=Schema,CN=Configuration,DC=ASTRALEXPRESS,DC=local works
// objectcategory=CN=Sites,CN=Schema,CN=Configuration,DC=ASTRALEXPRESS,DC=local does not
//
getDomainSearcher {defaults with filter = "(&(objectClass=controlAccessRight))"} domainConnection
|> fun searcher ->
    searcher.FindAll()
    |> createLDAPSearchResults
    //|> List.filter (fun p -> p.LDAPData.ContainsKey "memberOf")
    //|> List.iter(fun i -> [for ii in i.LDAPData do yield printfn $"{ii}"] |> ignore )
    |> List.iter(fun i -> printfn $"""{i.LDAPData["schemaIDGUID"]}""")
    // |> ignore




