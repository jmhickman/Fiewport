#i """nuget: C:\Users\Jon\source\Fiewport\bin\Debug"""
#r "nuget: Fiewport"

open Fiewport
open Fiewport.LDAPRecords

let domainConnection = getDomainConnection "LDAP://astralexpress.local" "administrator" "beefb33fBeef"

getDomainSearcher [||] "(&(objectCategory=person))" domainConnection
|> fun searcher ->
    searcher.FindAll()
    |> createLDAPSearchResults
    |> List.map returnLDAPDataKeys
    |> List.iter (fun l ->
        l |> List.iter (fun v -> printfn $"{v}")
        printfn "---")





