""" Script to download, parse and structurate csv extension files
used to map values given by ClientHello to a human readable value."""

import pandas as pd


CIPHER_SUITE_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
SIGNATURE_SCHEME_URL = "https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv"
SUPPORTED_GROUP_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv"

CIPHER_SUITE_PATH = "data/tls-parameters-4.csv"
SIGNATURE_SCHEME_PATH = "data/tls-signaturescheme.csv"
SUPPORTED_GROUP_PATH = "data/tls-parameters-8.csv"


def get_cipher_dict(local=False):
    """ Return a cleaned mapping between values of cipher suite values used
    by ClientHello and the human readable string. """

    if(local):
        df_cipher = pd.read_csv(CIPHER_SUITE_PATH)
    else:
        df_cipher = pd.read_csv(CIPHER_SUITE_URL)

    dict_cipher = {}

    for i in df_cipher.index:
        v = df_cipher.iloc[i, 0]

        # Ignore the unnasigned values (<=> contains a '*' or a '-')
        if('-' in v or '*' in v):
            continue

        v = v.replace(",", "")
        v = v.replace("0x", "")
        a = int.from_bytes(bytes.fromhex(v), byteorder='big')
        dict_cipher[a] = {'cipher': df_cipher.iloc[i, 1],
                          'recommended': df_cipher.iloc[i, 3] == "Y"}

    return dict_cipher


def get_signature_dict(local=False):
    """ Return a cleaned mapping between values of signature scheme values used
    by ClientHello and the human readable string. """

    if(local):
        df_signature = pd.read_csv(SIGNATURE_SCHEME_PATH)
    else:
        df_signature = pd.read_csv(SIGNATURE_SCHEME_URL)

    dict_signatures = {}

    for i in df_signature.index:
        # Ignore the unnasigned values (<=> contains a '*' or a '-')

        v = df_signature.iloc[i, 0]
        description = df_signature.iloc[i, 1]

        if("Reserved for backward compatibility" in description or
           "Unassigned" in description or
           '-' in v):
            continue

        v = v.replace("0x", "")
        a = int.from_bytes(bytes.fromhex(v), byteorder='big')
        dict_signatures[a] = description

    return dict_signatures


def get_group_dict(local=False):
    """ Return a cleaned mapping between values of supported group values used
    by ClientHello and the human readable string. """
    
    set_groups = {}
    if(local):
        df_groups = pd.read_csv(SUPPORTED_GROUP_PATH)
    else:
        df_groups = pd.read_csv(SUPPORTED_GROUP_URL)

    for i in df_groups.index:
        description = df_groups.iloc[i, 1]
        if("Unassigned" in description or
           "Reserved" in description):
            continue
        set_groups[df_groups.iloc[i, 0]] = description

    return set_groups
