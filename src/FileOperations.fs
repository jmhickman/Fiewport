namespace Fiewport

module Serializer =
    
    open System.IO
    open MessagePack
    open MessagePack.FSharp
    open MessagePack.Resolvers


    let private resolver = 
        MessagePackSerializerOptions.Standard
            .WithResolver(CompositeResolver.Create(FSharpResolver.Instance,StandardResolver.Instance))
            .WithCompression(MessagePackCompression.Lz4BlockArray)


    ///<summary>
    ///Serializes a list of LDAPSearchResult records to disk using MessagePack.
    ///</summary>
    ///<param name="results">The list of LDAPSearchResult records to serialize.</param>
    ///<returns>Returns the original list of results after serialization.</returns>
    ///<exception cref="System.IO.IOException">
    ///    Thrown if there is an error accessing or writing to the disk file.
    ///</exception>
    let private fileName (result: LDAPSearchResult) =
        $"{result.searchConfig.ldapDN}-{result.searchType}-lcache.bin"

    let serializeToDisk (results: LDAPSearchResult list) =
        results
        |> List.groupBy fileName
        |> List.iteri (fun _ (file, group) ->
            use fileStream = new FileStream(file, FileMode.Create)
            MessagePackSerializer.Serialize(fileStream, group, resolver))
        results

        
    ///<summary>
    ///Deserializes a list of LDAPSearchResult records from a specified binary file using MessagePack.
    ///</summary>
    ///<param name="path">The path to the file containing the serialized data.</param>
    ///<returns>Returns a list of deserialized LDAPSearchResult records.</returns>
    ///<exception cref="System.IO.IOException">
    ///    Thrown if there is an error accessing or reading from the specified file.
    ///</exception>
    let deserializeFromDisk path =
        use fileStream = new FileStream(path, FileMode.Open)
        MessagePackSerializer.Deserialize<LDAPSearchResult list>(fileStream, resolver)
