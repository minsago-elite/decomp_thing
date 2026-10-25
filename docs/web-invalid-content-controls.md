# Invalid-content and storage privacy controls

The invalid-content component controls join the actual API client and decoder
to the attempt view. After an ordinary validated metadata read, an explicit
refresh receives one of three controlled responses:

- A declared body size above the one-MiB JSON limit.
- Malformed UTF-8 followed by private text and markup.
- An unsupported API version with an additional private field.

Each case must clear the prior editable/displayed attempt evidence, show bounded
locally authored feedback, perform only the two explicit GETs and write nothing
to browser storage. Raw body text, host-path markers and markup cannot appear
as user feedback or active DOM. Transport and decoder failures retain their
specific typed codes.

These cases complement the retained streamed/declared byte, JSON depth/node,
schema, source-row/window, inert preview and display-preference controls.
Display preferences admit only version/theme/motion enums; the separately
documented upload recovery slot retains its bounded retry metadata and no file
bytes or session credentials. This change adds no storage writer.

All reads, session callbacks and clock advances are controlled in memory.
No real browser, service, native process, auth provider or controller is started.
The complete source requires its own ordinary Actions and automatic reviews;
source inspection does not establish current runtime qualification or broader
provider/release readiness.
