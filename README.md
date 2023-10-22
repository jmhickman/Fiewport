This is Fiewport, an **F**# Power**View** **port**.

(Yes, the name is silly.)

Fiewport is a library intended for use inside .fsx files. It provides a set of primitives for enumerating information from Microsoft Active Directory environments.

It includes useful filtering and manipulation functionality to quickly find the information pertinent to your investigation.

Eventually. It's not done yet. But here's what we have so far.

### Scripts

Fiewport is primarily intended to be used from inside F# script files (.fsx). The reason comes from Fiewport's roots. 

Most AD tooling for security professionals comes from Powershell, not least of which is the titular PowerView. Part of the appeal of PowerView and tools like it was that, in leveraging the shell, commands could be piped into one another to fort through a bulk of data.

I wanted to directly support that flexibility. And nothing pipes better than F#. (Fight me.)

Fiewport can be used as a normal library in a compiled application of course. I might even provide such a front end at some point. But the freedom of `fsi` and `fsx` allows a tester to quickly iterate on what they find important.

Fiewport ships with a scrip that's intended to be `#load`-ed into your actual script. This both to keep boilerplate to a minimum and to handle some imports of our own. Fiewport uses `Spectre` via the `SpectreCoff` library, plus the `System.DirectoryServices` package. No need to see that each time you want to use the library.

A short demonstration of Fiewport might look like this:

```fsharp


```

