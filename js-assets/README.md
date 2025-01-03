# @pulsebeam/server: Server SDK

Generate tokens for your clients to use @pulsebeam/peer: WebRTC Peer-to-Peer Communication SDK. 

@pulsebeam/peer Simplifies real-time application development. Defines signaling protocol for connection establishment, handling media and data transmission, and provides infrastructure.

You likely want to authenticate the user with your application before providing them with a token. As your PulseBeam account will incur usage based on what your clients use. See https://pulsebeam.dev/ pricing for more information.

Depending on your client's network, it is common to see 6-14% of WebRTC P2P traffic (sometimes higher or lower) going through a TURN server. PulseBeam hosts TURN servers and your customer's data usage accrues to your account. 