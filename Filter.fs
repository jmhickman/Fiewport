namespace Fiewport

open Types

module Filter =
    
    
    type Filter = class end
    
        with        
        
        static member anyOne filterAttribute (res: LDAPSearchResult) =
            res.LDAPData.ContainsKey filterAttribute

