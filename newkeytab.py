#!/usr/local/bin/python3
import binascii

## TO DO
# Import based on argument
# Figure out KeyTypes
# Figure out TypeNames

# Import the keytab file as a hex-encoded string
f = open('keysrvc.keytab', 'rb').read()
hex_encoded = binascii.hexlify(f).decode('utf-8')

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
print("     REALM : " + bytes.fromhex(realm).decode('utf-8'))

# Calculate the number of bytes for the realm of components
comp_array_calc  = realm_jump + 4
comp_array = int(hex_encoded[realm_jump:comp_array_calc])

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
print("     SERVICE PRINCIPAL : " + bytes.fromhex(comp_array2).decode('utf-8') + "/" + bytes.fromhex(principal_array_value).decode('utf-8'))

# Calculate typename - 32 bits from previous value
typename_offset = prin_array_finish + 8
typename = hex_encoded[prin_array_finish:typename_offset]
print("     TYPENAME : " + typename)

# Calculate Timestamp - 32 bit from typename value
timestamp_offset = typename_offset + 8
timestamp = hex_encoded[typename_offset:timestamp_offset]
print("     TIMESTAMP : " + timestamp)

# Calcualte 8 bit VNO Field
vno_offset = timestamp_offset + 2
vno = hex_encoded[timestamp_offset:vno_offset]
print("     VNO : " + vno)

# Calculate KeyType - 16 bit value
keytype_offset = vno_offset + 4
keytype = hex_encoded[vno_offset:keytype_offset]
print("     KEYTYPE : " + keytype)

# Calculate Length of Key Value - 16 bit value
key_val_offset = keytype_offset + 4
key_val_len = int(hex_encoded[keytype_offset:key_val_offset], 16)
#print(key_val_len)

# Extract Key Value
key_val_start = key_val_offset
key_val_finish = key_val_start + (key_val_len * 2)
key_val = hex_encoded[key_val_start:key_val_finish]
print("     NTLM HASH : " + key_val)