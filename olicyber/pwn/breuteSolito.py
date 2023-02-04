from Crypto.Util.number import bytes_to_long

p = 290413720651760886054651502832804977189
admin_public_key = 285134739578759981423872071328979454683
st = b'get_flag'

def inf():
    i = 0
    while True:
        yield i
        i += 1

def check_signature(signature, command, pub_key):
    return (pub_key * signature) % p == command

st = bytes_to_long(st)
print(st)



p = 290413720651760886054651502832804977189
public_key = 285134739578759981423872071328979454683
command = 7450489111643447655
(pub_key * signature) % p == command

I want the value x that satisfies the following equation: (285134739578759981423872071328979454683 * x) % 290413720651760886054651502832804977189 == 7450489111643447655
I want the value x that satisfies the following equation: (285134739578759981423872071328979454683 * x)  == 7450489111643447655 mod 290413720651760886054651502832804977189