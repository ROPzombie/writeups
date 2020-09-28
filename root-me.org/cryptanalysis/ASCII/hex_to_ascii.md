#Encoding - ASCII


**Converting Hex-Values to ASCII Char**

For this cahllenge we are given a sequence of hex values. However as this is not really human readable we convert the hex numbers to ASCII chars.

Piece of a cake in shell:

```bash
4C6520666C6167206465206365206368616C6C656E6765206573743A203261633337363438316165353436636436383964356239313237356433323465 | xxd -r -p
```

#Encoding - UU
###Very used by the HTTP protocol

We are given the following message:

```

_=_ 
_=_ Part 001 of 001 of file root-me_challenge_uudeview
_=_ 

begin 644 root-me_challenge_uudeview
B5F5R>2!S:6UP;&4@.RD*4$%34R`](%5,5%)!4TE-4$Q%"@``
`
end
```

The easiest way to solve this challenge is by using **uudeview**. 

But if we want to really understand whats going on, we have to dive in this encoding.