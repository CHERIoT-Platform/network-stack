Compartmentalized HTTP Server Example
=====================================

The [HTTP server example](../05.HTTP_SERVER) uses a single compartment.
There are many reasons why one would want to break it down into more compartments: for example, one may want to isolate the part processing incoming requests from the part serving content to make it harder to mount a website defacement attack.
This server is architected in three compartments to show how the network stack's APIs facilitate the design of compartmentalized server software.

Similarly to the previous HTTP server example, note that this is *not* intended as an example of how to build an HTTP server.
