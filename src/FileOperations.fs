namespace Fiewport

[<AutoOpen>]
module Serializer =
    
    open System.IO
    open MessagePack
    open MessagePack.FSharp
    open MessagePack.Resolvers
    
    let resolver = // this is why object programming is awful. Look at this ⬇️
                MessagePackSerializerOptions.Standard
                    .WithResolver(CompositeResolver.Create(FSharpResolver.Instance,StandardResolver.Instance))
                    .WithCompression(MessagePackCompression.Lz4BlockArray)
    
    type Serializer = class end     
        with
        
        static member public serializeToDisk (results: LDAPSearchResult list) =
            results
            |> List.iter(fun result ->
                use fileStream = new FileStream($"""{result.searchConfig.ldapDN}-{result.searchType}-lcache.bin""", FileMode.Create)
                MessagePackSerializer.Serialize (fileStream, results, resolver))
            results
            
        static member public deserializeFromDisk path =
            use fileStream = new FileStream(path, FileMode.Open)
            MessagePackSerializer.Deserialize<LDAPSearchResult list>(fileStream, resolver)