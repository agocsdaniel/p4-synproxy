# P4 SYNproxy

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
