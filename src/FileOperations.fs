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

         ///<summary>
         ///Serializes a list of LDAPSearchResult records to disk using MessagePack.
         ///</summary>
         ///<param name="results">The list of LDAPSearchResult records to serialize.</param>
         ///<returns>Returns the original list of results after serialization.</returns>
         ///<exception cref="System.IO.IOException">
         ///    Thrown if there is an error accessing or writing to the disk file.
         ///</exception>
        static member public serializeToDisk (results: LDAPSearchResult list) =
            results
            |> List.iter(fun result ->
                use fileStream = new FileStream($"""{result.searchConfig.ldapDN}-{result.searchType}-lcache.bin""", FileMode.Create)
                MessagePackSerializer.Serialize (fileStream, results, resolver))
            results
            
        ///<summary>
        ///Deserializes a list of LDAPSearchResult records from a specified binary file using MessagePack.
        ///</summary>
        ///<param name="path">The path to the file containing the serialized data.</param>
        ///<returns>Returns a list of deserialized LDAPSearchResult records.</returns>
        ///<exception cref="System.IO.IOException">
        ///    Thrown if there is an error accessing or reading from the specified file.
        ///</exception>
        static member public deserializeFromDisk path =
            use fileStream = new FileStream(path, FileMode.Open)
            MessagePackSerializer.Deserialize<LDAPSearchResult list>(fileStream, resolver)