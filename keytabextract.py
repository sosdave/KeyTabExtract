#!/usr/bin/env python3
import binascii,sys

# Take argument 1 as keytab file, import and decode the hex
ktfile = sys.argv[1]
f = open(ktfile, 'rb').read()
hex_encoded = binascii.hexlify(f).decode('utf-8')

def displayhelp():
    print("KeyTabExtract. Extract NTLM Hashes from KeyTab files where RC4-HMAC encryption has been used.")
    print("Usage : ./keytabextract.py [keytabfile]")
    print("Example : ./keytabextract.py service.keytab")

def ktextract():
    rc4hmac = False
    aes128 = False
    aes256 = False 
    
    if '00170010' in hex_encoded:
        print("[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.")
        rc4hmac = True
    else:
        print("[!] No RC4-HMAC located. Unable to extract NTLM hashes.")
        
    if '00120020' in hex_encoded:
        print("[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.")
        aes256 = True
    else:
        print("[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes.")

    if '00110010' in hex_encoded:
        print("[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.")
        aes128 = True
    else:
        print("[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.")

    #if proceed != True:
    if all( [ rc4hmac != True, aes256 != True, aes128 != True]):
        print("Unable to find any useful hashes.\nExiting...")
        sys.exit

    # First 16 bits are dedicated to stating the version of Keytab File
    ktversion = hex_encoded[:4]
    if ktversion == '0502':
        print("[+] Keytab File successfully imported.")
    else:
        print("[!] Only Keytab versions 0502 are supported.\nExiting...")

    # 32 bits indicating the size of the array 
    arrLen = int(hex_encoded[4:12], 16)

    # Number of counted octet strings representing the realm of the principal
    num_components = hex_encoded[12:16]

    # convert the 
    num_realm = int(hex_encoded[16:20], 16)

    # calculate the offset for the realm
    realm_jump = 20 + (num_realm * 2)

    # Determine the realm for the keytab file
    realm = hex_encoded[20:realm_jump]
    print("\tREALM : " + bytes.fromhex(realm).decode('utf-8'))

    # Calculate the number of bytes for the realm of components
    comp_array_calc  = realm_jump + 4
    comp_array = int(hex_encoded[realm_jump:comp_array_calc], 16)

    # Calculates the realm component (HTTP)
    comp_array_offset = comp_array_calc + (comp_array * 2)
    comp_array2 = hex_encoded[comp_array_calc:comp_array_offset]

    # calculate number of bytes for the principal
    principal_array_offset = comp_array_offset + 4

    # extract the principal
    principal_array = hex_encoded[comp_array_offset:principal_array_offset]
    principal_array_int = (int(principal_array, 16) * 2)
    prin_array_start = principal_array_offset
    prin_array_finish = prin_array_start + principal_array_int
    principal_array_value = hex_encoded[prin_array_start:prin_array_finish]
    print("\tSERVICE PRINCIPAL : " + bytes.fromhex(comp_array2).decode('utf-8') + "/" + bytes.fromhex(principal_array_value).decode('utf-8'))

    # Calculate typename - 32 bits from previous value
    typename_offset = prin_array_finish + 8
    typename = hex_encoded[prin_array_finish:typename_offset]

    # Calculate Timestamp - 32 bit from typename value
    timestamp_offset = typename_offset + 8
    timestamp = hex_encoded[typename_offset:timestamp_offset]

    # Calcualte 8 bit VNO Field
    vno_offset = timestamp_offset + 2
    vno = hex_encoded[timestamp_offset:vno_offset]
    #print("\tVersion No : " + vno)

    # Calculate KeyType - 16 bit value
    keytype_offset = vno_offset + 4
    keytype_hex = hex_encoded[vno_offset:keytype_offset]
    keytype_dec = int(keytype_hex, 16)

    # Calculate Length of Key Value - 16 bit value
    key_val_offset = keytype_offset + 4
    key_val_len = int(hex_encoded[keytype_offset:key_val_offset], 16)

    # Extract Key Value
    key_val_start = key_val_offset
    key_val_finish = key_val_start + (key_val_len * 2)
    key_val = hex_encoded[key_val_start:key_val_finish]
    if rc4hmac == True:
        NTLMHash = hex_encoded.split("00170010")[1]
        print("\tNTLM HASH : " + NTLMHash[:32])

    if aes256 == True:
        aes256hash = hex_encoded.split("00120020")[1]
        print("\tAES-256 HASH : " + aes256hash[:64])

    if aes128 == True:
        aes128hash = hex_encoded.split("00110010")[1]
        print("\tAES-128 HASH : " + aes128hash[:32])

if __name__ == "__main__":
    if len(sys.argv) == 1:
        displayhelp()
        sys.exit()
    else:
        ktextract()
