from collections import defaultdict

import pandas as pd
from charm.core.math.pairing import pair
from charm.toolbox.pairinggroup import ZR, GT
from charm.toolbox.pairinggroup import PairingGroup

from pucture_main_code import P_MACP_ABE


def main():
    groupObj = PairingGroup('SS512')

    puncture_maabe_obj = P_MACP_ABE(groupObj)

    # Setup
    (prv_DO, pub_DO, pk, mk) = puncture_maabe_obj.setup()

    epsilon_value = 'epsilon'

    # SetupAA
    # WE consider three AAs
    # ----------------------------------------------------------------
    authority_id = 1
    authority_name = "AA1"
    attrs_1 = ['attribute1']
    puncture_maabe_obj.setupAA(authority_id, authority_name, attrs_1)

    authority_id = 2
    authority_name = "AA2"
    attrs_2 = ['attribute2']
    puncture_maabe_obj.setupAA(authority_id, authority_name, attrs_2)

    authority_id = 3
    authority_name = "AA3"
    attrs_3 = ['attribute3', 'attribute4']
    puncture_maabe_obj.setupAA(authority_id, authority_name, attrs_3)
    # ----------------------------------------------------------------

    # set of user attributes
    attrs = {}
    attrs['attribute1'] = 'attribute1$ONE'
    attrs['attribute2'] = 'attribute2$TWO'
    attrs['attribute3'] = 'attribute3$THREE'
    attrs['attribute4'] = 'attribute4$FOUR'

    # we register a user with anonymity level
    user_gid = 'gid'
    anonymity_level = 10
    user = puncture_maabe_obj.regUser(gid=user_gid, attributes=attrs, anonymity_level=anonymity_level)

    access_policy = f"(({attrs['attribute4']} or {attrs['attribute3']}) and ({attrs['attribute3']} or {attrs['attribute1']}))"
    access_policy_schema = f"(({attrs['attribute4'].split('$',1)[0]} or {attrs['attribute3'].split('$',1)[0]}) and ({attrs['attribute3'].split('$',1)[0]} or {attrs['attribute1'].split('$',1)[0]}))"

    hiden_attr_1 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon')
    hiden_attr_2 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon')
    hiden_attr_3 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon')
    hiden_attr_4 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon')

    hidden_attrs = {}
    hidden_attrs['attribute1'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_1, compression=False).hex().upper()
    hidden_attrs['attribute2'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_2, compression=False).hex().upper()
    hidden_attrs['attribute3'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_3, compression=False).hex().upper()
    hidden_attrs['attribute4'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_4, compression=False).hex().upper()

    hidden_access_policy = f"(({hidden_attrs['attribute4']} or {hidden_attrs['attribute3']}) and ({hidden_attrs['attribute3']} or {hidden_attrs['attribute1']}))"

    print(f" the value of the ******* hidden policy ******** is {hidden_access_policy}\n\n\n")

    if debug:
        print("Unhidden Attributes =>", attrs, "\n")
        print("Policy =>", access_policy, "\n")

    # 1- DO generate the DO Key
    do_key = puncture_maabe_obj.keygen1(mk, puncture_maabe_obj.users[user_gid].get(user_gid), prv_DO, epsilon_value)

    # 2- DU hides the set of attributes originally in the plain form
    puncture_maabe_obj.users[user_gid]['attributes'] = puncture_maabe_obj.hide_attr(
        puncture_maabe_obj.users[user_gid].get('gid'), do_key, puncture_maabe_obj.users[user_gid].get('attributes'))

    # AAs compute Keygen2
    aa_key_1 = puncture_maabe_obj.keygen2(AA_ID=1, gid=puncture_maabe_obj.users[user_gid].get('gid'),
                                          S_DU=puncture_maabe_obj.users[user_gid]['attributes'])
    print(f" the gid is {puncture_maabe_obj.users[user_gid].get('gid')} and the set of attributes is {puncture_maabe_obj.users[user_gid].get('attributes')} \n\n")

    aa_key_2 = puncture_maabe_obj.keygen2(AA_ID=2, gid=puncture_maabe_obj.users[user_gid].get('gid'),
                                          S_DU=puncture_maabe_obj.users[user_gid]['attributes'])

    aa_key_3 = puncture_maabe_obj.keygen2(AA_ID=3, gid=puncture_maabe_obj.users[user_gid].get('gid'),
                                          S_DU=puncture_maabe_obj.users[user_gid]['attributes'])

    input_aa_key = list()
    input_aa_key.append(aa_key_1)
    input_aa_key.append(aa_key_2)
    input_aa_key.append(aa_key_3)

    if debug:
        print(f"Hidden Attributes => \n {puncture_maabe_obj.users[user_gid]['attributes']} \n")

    tk_key = puncture_maabe_obj.keygen3(input_aa_key, user_gid)
    DU_key, DU_hkey = puncture_maabe_obj.keygen4(do_key, tk_key)

    # ******************Encryption******************
    rand_msg = puncture_maabe_obj.crs['group'].random(GT)

    CT = puncture_maabe_obj.encrypt(pk, mk, rand_msg, access_policy, prv_DO, epsilon_value, hidden_access_policy)


    if puncturing is True:
        # we perform puncture operations
            if single_puncture:
                print("\n=== SINGLE TAG PUNCTURING ===\n")
                tag_to_puncture = "revoked_user_001"
                DU_key, DU_hkey, T_prime, desc_T_prime = puncture_maabe_obj.DU_single_puncture(
                    DU_key, DU_hkey, tag_to_puncture, user_gid, anonymity_level)
                print(f"Punctured tag: {tag_to_puncture}")
                print(f"Anonymous set size: {len(T_prime)} (1 real + {anonymity_level - 1} dummy)")
            else:
                print("\n=== BATCH TAG PUNCTURING ===\n")
                tags_to_puncture = {"revoked_user_001", "revoked_user_002", "revoked_user_003"}
                DU_key, DU_hkey, T_prime, desc_T_prime = puncture_maabe_obj.DU_batch_puncture(
                DU_key, DU_hkey, tags_to_puncture, user_gid, anonymity_level)
                print(f"Punctured tags: {tags_to_puncture}")
                print(f"Anonymous set size: {len(T_prime)} ({len(tags_to_puncture)} real + {anonymity_level - len(tags_to_puncture)} dummy)")

            # DU outsources remaining puncturing to CSP
            DU_hkey, sig_ACC = puncture_maabe_obj.csp_puncture(
                CT, DU_hkey, T_prime, desc_T_prime, user_gid)

            # Store CSP attestation data in CT for verification
            CT['sig_ACC'] = sig_ACC


            print(f"Accumulator value after CSP puncturing: {CT['ACC'].acc_get_value()}")
            print(f"Accumulator size: {CT['ACC'].acc_get_size()}")
            print(f"CSP attestation signature generated.\n")

    # ******************Transform******************
    TC, I = puncture_maabe_obj.transform(CT=CT, DU_hkey=DU_hkey, gid=puncture_maabe_obj.users[user_gid].get('gid'))

    # ******************Decrypt******************
    rec_msg = puncture_maabe_obj.Decrypt(CT, TC, I, DU_key, pub_DO)

    if (rand_msg != rec_msg):
        #
        RED = '\033[91m'
        RESET = '\033[0m'
        print(f"{RED}FAILED Decryption: message is incorrect {RESET}\n\n")
        # assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    else:
        if debug is True:
            print(f" Original msg: {rand_msg} \n")
            print(f" msg recovered: {rec_msg} \n")
            print("Successful Decryption!!!")
        else:
            print("Decryption successful - message recovered correctly.")

    if puncturing is True:
        # we can verify accumulator attestation signature
        acc_val = CT['ACC'].acc_get_value()
        left_pair = pair(puncture_maabe_obj.crs['g1'], CT['sig_ACC'])
        right_pair = pair(puncture_maabe_obj.crs['g1'] ** puncture_maabe_obj.crs['group'].hash(str(acc_val), ZR), puncture_maabe_obj.public_attestation_key)
        assert left_pair == right_pair, "Accumulator attestation signature verification failed!"
        print("Accumulator attestation signature verified successfully.")


if __name__ == "__main__":
    debug = False
    # ******************PUNCTURING PHASE******************
    # whether to puncture or not
    puncturing = False
    # whether to perform batch or single puncture
    single_puncture = True
    #
    main()
