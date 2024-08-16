# Command set:
Addr: 0x69

# We will use AES-CTR with a nonce stored in non-volatile memory on the EC.
# Critically, nonces cannot be repeated.

0x00 - Advertising enable | W/R
0x01 - TX Buffer length   | W/R
0x02 - Write to TX        | W
0x03 - RX Buffer length   | R
0x04 - Read from RX       | R
0x05 - Get status         | R
0x06 - Get device ID      | R
