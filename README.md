# P4 SYNproxy

### Known issues

Actually the code only works *well* when you disable the Flow Cache. This, however result in decrease of speed, but at least it doesn't stop working after ~1.9M packets. A bit of explanation: Because the program reads and alters tcp.seqNo and tcp.ackNo, it will automagically be part of the Flow Cache Key, so in fact every packet will be a different flow and this can quickly fill the cache, where the items evicts after 30 sec by default.

## Packet flow visualization

```

               Client                        Proxy                                  Server
                   SYN
             ---------------->
             seq = x, ack = 0


                                   k = createCookie()


                   SYN-ACK
             <----------------
             seq = k, ack = x+1


----------------------------------------------------------------------------------------------------------------

                    ACK
             ----------------->
             seq = x+1, ack = k+1
                                   bool = verifyCookie(k)
                                                                              SYN
                                   use the same initial SYN                --------------->
                                                                           seq = x, ack = 0

----------------------------------------------------------------------------------------------------------------

                                                                              SYN-ACK
                                  connection is established                <----------------   r=selectRandomSeq()
                                                                           seq = r, ack = x+1
                                  add state of the connection
                                  to connections table                            ACK
                                                                           ----------------->
                                                                           seq = x+1, ack = r+1

----------------------------------------------------------------------------------------------------------------

                  HTTP GET                                                      HTTP GET
             ----------------->               TRANSFORM                    ------------------>
             seq = x+1, ack = k+1                                          seq = x+1, ack = r+1

----------------------------------------------------------------------------------------------------------------

                   ACK                                                            ACK
             <-----------------               TRANSFORM                    <------------------
             seq = k+1, ack = x+1+ payload                                 seq = r+1, ack = x+1 +payload

```
