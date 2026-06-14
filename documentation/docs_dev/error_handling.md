# Error Handling
- There are two parts to heretek userpace, the heretek cli (htek) and the heretek daemon (htekd). 
  These each have different error handling strategies.
- There are two exceptions to all the following rules. 
  - Const contexts (effectively a compile error as opposed to a runtime failure)
  - Assert contents, (where the `ASSERTS` build parameter is true) (since this should always be
    false for production builds)

## Heretek CLI
- This should fail/exit fast and display error messages to the user via eprintln!().
- These failures/exits should consist of messages to the user via `eprintln!()` or simmilar, and
  exit via `std::process::exit()` or simmilar (never `panic!()`). 

## Heretek Daemon
- As this is the daemon that should stay running forever, this process should never fail/exit 
  except at startup. 
- Outside of the above exceptions, daemon code should never call `.unwrap()`, `panic!()`, 
  `println!()`, `std::process::exit()` or any other operation that can panic/exit. 
- In terms of notifying the user of errors/warnings, the daemon should use the macros provided 
  by the tracing crate.
  - `ERROR` -> For errors that causes the daemon to exit
  - `WARN` -> For errors that don't cause the daemon to exit
  - `INFO` -> All other info (like performanst stats)
  - `TRACE` -> Unused
  - `Debug` -> Unused
- In assert contexts, daemon code may also use incident files. 


## Shared Code
- Code shared between the daemon and the CLI should never run operations than can panic/exit, 
  print anything to stdio, or use macros from the tracing crate.
- The only way this code should report errors is by returning result types.
