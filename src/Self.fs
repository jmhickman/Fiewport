namespace Fiewport

open System.DirectoryServices.ActiveDirectory

module Self =    
    
    ///
    /// Shoves Domain object data into a record that ...approximates a real Domain record that would be difficult to
    /// deal with (mutually recursive Domain/Forest definitions) for not a lot of real gain, IMO.
    /// 
    let private domainCoercer (domain: Domain) =
        { children = [for cd in domain.Children do yield cd.Name]
          domainControllers  = [for dc in domain.DomainControllers do yield dc.Name] 
          domainMode = domain.DomainMode
          domainModeLevel = domain.DomainModeLevel
          forest = domain.Forest.Name
          infrastructureRoleOwner = domain.InfrastructureRoleOwner.Name
          name = domain.Name
          parent = domain.Parent.Name |> Some
          pdcRoleOwner = domain.PdcRoleOwner.Name
          ridRoleOwner = domain.RidRoleOwner.Name }
        
    
    ///
    /// <summary>
    /// This type provides some basic .Net-based introspection, as opposed to the LDAP-based approach of the Searcher.
    /// `None` results typically mean that the computer or user process running the script isn't joined to a domain,
    /// but can also indicate other errors. You may attempt to connect to a domain manually using the `tryGetDomain`
    /// method.
    /// </summary>
    type Self = class end
        with
        
        static member tryGetComputerDomain () =
            try Domain.GetComputerDomain () |> domainCoercer  |> Some            
            with _ -> None

        
        static member tryGetCurrentDomain () =
            try Domain.GetCurrentDomain () |> domainCoercer  |> Some
            with _ -> None
            
            
        static member tryGetDomain domain username password =
            try
                Domain.GetDomain(DirectoryContext(DirectoryContextType.Domain, domain, username, password))
                |> domainCoercer |> Some
            with _ -> None