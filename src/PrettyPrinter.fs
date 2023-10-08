namespace Fiewport


open System
open Spectre.Console
open SpectreCoff

[<AutoOpen>]
module PrettyPrinter =
    
    let private panelFormat =
        { defaultPanelLayout with
            Sizing = SizingBehaviour.Collapse
            BorderColor = Some Color.White
            Padding = Padding.AllEqual 0 }

    
    let private printFormatter key (datum: ADDataTypes) =
        match datum with
        | ADBool x ->
             node ([MC (Color.Blue, $"{key}: "); MC (Color.White, $"{x}")] |> Many) []
        | ADString x ->
             node ([MC (Color.Blue, $"{key}: "); MC (Color.White, $"{x}")] |> Many) []
        | ADInt x ->
            node ([MC (Color.Blue, $"{key}: "); MC (Color.White, $"{x}")] |> Many) []
        | ADInt64 x ->
            node ([MC (Color.Blue, $"{key}: "); MC (Color.White, $"{x}")] |> Many) []
        | ADBytes x ->
            node ([MC (Color.Grey, $"{key}: "); MC (Color.White, $"{x |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}") ] |> Many) []
        | ADDateTime x ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{x.ToShortDateString ()}")] |> Many) []
        | _ ->  node (P "") []  
    
    let private printer (mbox: MailboxProcessor<LDAPSearchResult>) =
        
        let rec ringRing () = async {
            let! msg = mbox.Receive ()
            let keys = [for key in msg.lDAPData.Keys do yield key]
            let _data = keys |> List.map (fun key -> key, msg.lDAPData[key])
            
            [ V "\n" // BL and NL just utterly obliterate the printing of panels and I don't know why
              MC (Color.Gold1, $"Object Category: {msg.objectCategory}\n")
              MC (Color.Gold1, $"""Object Class: {msg.objectClass |> String.concat ", "}""")
              V "\n"
              tree (V "attributes") (_data |> List.map (fun (key, datum) -> printFormatter key datum)) ]
            |> Many
            |> customPanel panelFormat (MC (Color.Wheat1, $"objectGUID: {msg.objectGUID}") |> toMarkedUpString)            
            |> toConsole
            
            do! ringRing ()
        }

        ringRing ()
        
    let private pPrinter =
        // Stupid bodge to deal with nonsense. Spectre will not emit a Panel (or any markedup text really)
        // from inside the MailboxProcessor without first printing it _outside_ the mailbox. It doesn't make any
        // sense. So I print a panel and then reset the cursor and print normally. 🙄🙄
        let struct (left, top) = Console.GetCursorPosition ()
        Many [MC (Color.Black, "")]
        |> panel "objectGUID"
        |> toConsole
        Console.SetCursorPosition(left, top)
       
        MailboxProcessor.Start printer
        
    let public prettyPrint (res: LDAPSearchResult list) =
        res |> List.iter (fun r -> pPrinter.Post r; System.Threading.Thread.Sleep 4)
        