'''
| --- ADAPTED VERSION ---
| Authors:      Arthur Sandor Voundi Koe
| Date:         04/2025
|
| FROM
|
| https://github.com/DoreenRiepel/FABEO  
| Authors:      Doreen Riepel
| Date:         06/2023
|
'''
import cProfile
import gc
import hashlib
import pstats
import random
import threading
import timeit
from sys import getsizeof

from charm.core.math.pairing import ZR
from charm.toolbox.pairinggroup import PairingGroup, GT

import datetime
import time

import sys

import pandas as pd

from FABEO.abenc_maabe_rw15 import MaabeRW15, merge_dicts
from FABEO.abenc_maabe_yj14 import MAABE
from FABEO.msp import MSP
from FABEO.abenc_maabe_rw15 import MaabeRW15, merge_dicts
from SR_MACP_ABE import SR_MACP_ABE

# global variables to output data as CSV
output_data_srmacpabe = {
    'Scheme': list(),
    '#attributes': list(),
    'Setup (ms)': list(),
    'Keygen (ms)': list(),
    'Encrypt (ms)': list(),
    'Transform (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list(),
    'URevocation (ms)': list(),
    'ARevocation (ms)': list(),
    'URegistration (ms)': list(),
    'AASetup (ms)': list(),
    'Merkle tree size (bytes)': list()
}

output_data_kyxj = {
    'Scheme': list(),
    '#attributes': list(),
    'Setup (ms)': list(),
    'Keygen (ms)': list(),
    'Encrypt (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list(),
    'URevocation (ms)': list(),
    'URegistration (ms)': list(),
    'AASetup (ms)': list()
}

output_data_rw15 = {
    'Scheme': list(),
    '#attributes': list(),
    'Setup (ms)': list(),
    'Keygen (ms)': list(),
    'Encrypt (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list(),
    'URegistration (ms)': list(),
    'AASetup (ms)': list()
}

# global variable to measure the time/size of encryption and decryption for intermediate ciphertexts in FAHDABE
sr_macp_abe_cph_data = {
    'Scheme': list(),
    '#attributes': list(),
    'Keygen1 (ms)': list(),
    'Keygen2 (ms)': list(),
    'Keygen3 (ms)': list(),
    'Keygen4 (ms)': list(),
    'Encrypt (ms)': list(),
    'Transform (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list(),
    'Revoke 1 (ms)': list(),
    'Revoke 2 (ms)': list(),
    'Revoke 3 (ms)': list(),
    'Revoke 4 (ms)': list(),
    'Uregistration (ms)': list(),
    'AASetup (ms)': list(),
    'Urevocation (ms)': list(),
    'Arevocation (ms)': list(),
    'Merkle tree size (bytes)': list()
}

# SS512, SS1024
curve_type = "SS512"


def measure_average_times(abe, attr_list, policy_str, revoked_user_list, k1, k2, k3, msg, N=10):
    # for SR_MACP_ABE
    # calling the garbage collector
    gc.collect(0)
    gc.collect(1)
    gc.collect(2)
    gc.collect()

    sum_setup_srmacpabe = 0
    sum_reg_user_srmacpabe = 0
    sum_reg_aa_srmacpabe = 0
    sum_keygen_srmacpabe = 0
    sum_keygen_1 = 0
    sum_keygen_2 = 0
    sum_keygen_3 = 0
    sum_keygen_4 = 0
    sum_transform = 0
    sum_revoke_1 = 0
    sum_revoke_2 = 0
    sum_revoke_3 = 0
    sum_revoke_4 = 0
    sum_decrypt = 0
    sum_enc_srmacpabe = 0
    sum_decrypt_srmacpabe = 0
    sum_revoke_user_srmacpabe = 0
    sum_revoke_attribute_srmacpabe = 0
    sum_generate_update_inf_AA_srmacpabe = 0
    sum_update_DU_key_srmacpabe = 0
    size_cph = 0
    size_merkle_tree = 0

    # for Kan Yang and Xiaohua Jia
    sum_setup_kyxj = 0
    sum_enc_kyxj = 0
    sum_keygen_kyxj = 0
    sum_dec_kyxj = 0
    sum_revoke_user_kyxj = 0
    sum_reg_user_kyxj = 0
    size_cph_kyxj = 0
    sum_AA_setup_kyxj = 0
    sum_generate_update_inf_AA_kyxj = 0
    sum_update_DU_key_kyxj = 0
    sum_update_CT_kyxj = 0

    # for ROuselakis and Waters
    sum_setup_rw = 0
    sum_enc_rw = 0
    sum_keygen_rw = 0
    sum_dec_rw = 0
    sum_reg_user_rw = 0
    size_cph_rw = 0
    sum_AA_setup_rw = 0
    sum_update_CT_rw = 0

    for i in range(N):

        # calling the garbage collector
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)
        gc.collect()

        if abe.name == "SR-MACP-ABE":
            list_length = int(len(attr_list) / 3)
            attr_list_1 = attr_list[0:list_length]
            attr_list_2 = attr_list[list_length:(2 * list_length)]
            attr_list_3 = attr_list[(2 * list_length):len(attr_list)]

            # setup time
            gc.collect(0)
            gc.collect(1)
            gc.collect(2)
            gc.collect()
            start_setup =time.perf_counter()
            (prv_DO, pub_DO, pk, msk) = abe.setup()
            end_setup =time.perf_counter()
            time_setup = end_setup - start_setup
            sum_setup_srmacpabe += time_setup

            # Register a single user
            # such user stands as the target user
            start_setup_1 =time.perf_counter()
            alice = abe.regUser('alice', attr_list)
            end_setup_1 =time.perf_counter()
            time_setup_1 = end_setup_1 - start_setup_1
            # sum_setup_srmacpabe += time_setup_1
            sum_reg_user_srmacpabe += time_setup_1

            # Register AAs (three AAs)

            start_setup_2 =time.perf_counter()
            #
            AA1_ID = 1
            AA1_name = "AA_1"
            abe.setupAA(AA1_ID, AA1_name, attr_list_1)
            #
            AA2_ID = 2
            AA2_name = "AA_2"
            abe.setupAA(AA2_ID, AA2_name, attr_list_2)
            #
            AA3_ID = 3
            AA3_name = "AA_3"
            abe.setupAA(AA3_ID, AA3_name, attr_list_3)
            #
            end_setup_2 =time.perf_counter()
            time_setup_2 = end_setup_2 - start_setup_2
            # sum_setup_srmacpabe += time_setup_2
            sum_reg_aa_srmacpabe += time_setup_2

            # DO Keygen1
            start_keygen_1 = time.perf_counter()
            alice['DO_key'] = abe.keygen1(msk, alice['gid'])
            end_keygen_1 =time.perf_counter()
            time_keygen = end_keygen_1 - start_keygen_1
            sum_keygen_srmacpabe += time_keygen
            sum_keygen_1 += time_keygen

            # AA keygen2
            start_keygen_2 =time.perf_counter()
            #
            hash_gid = abe.crs['group'].hash(str(alice['gid']), ZR)

            aa_key_1 = abe.keygen2(AA_ID=1, hash_gid=hash_gid, S_DU=alice['attributes'])
            aa_key_2 = abe.keygen2(AA_ID=2, hash_gid=hash_gid, S_DU=alice['attributes'])
            aa_key_3 = abe.keygen2(AA_ID=3, hash_gid=hash_gid, S_DU=alice['attributes'])
            #
            end_keygen_2 =time.perf_counter()
            time_keygen = end_keygen_2 - start_keygen_2
            sum_keygen_srmacpabe += time_keygen
            sum_keygen_2 += time_keygen

            # TEE-CS Keygen3
            start_keygen_3 =time.perf_counter()
            #
            alice['TK_DU'] = abe.keygen3((aa_key_1, aa_key_2, aa_key_3))
            #
            end_keygen_3 =time.perf_counter()
            time_keygen = end_keygen_3 - start_keygen_3
            sum_keygen_srmacpabe += time_keygen
            sum_keygen_3 += time_keygen

            # DU keygen4 time
            start_keygen_4 =time.perf_counter()
            alice['DU_key'], alice['DU_hkey'] = abe.keygen4(alice['DO_key'], alice['TK_DU'])
            end_keygen_4 =time.perf_counter()
            time_keygen = end_keygen_4 - start_keygen_4
            sum_keygen_srmacpabe += time_keygen
            sum_keygen_4 += time_keygen

            # DO encryption
            start_enc_1 =time.perf_counter()
            #
            ctxt = abe.encrypt_(pk, msg, policy_str, prv_DO)
            #
            end_enc_1 =time.perf_counter()
            time_enc = end_enc_1 - start_enc_1
            sum_enc_srmacpabe += time_enc

            # size of ciphertext
            size_cph += len(abe.crs['group'].serialize(ctxt['C_tilde'], compression=False)) + len(
                abe.crs['group'].serialize(ctxt['C'], compression=False)) + len(
                abe.crs['group'].serialize(ctxt['W'], compression=False)) + len(
                abe.crs['group'].serialize(ctxt['sig_W'], compression=False)) + len(
                str.encode(ctxt['policy'], encoding='utf-8'))
            for value in ctxt['C_y'].values():
                size_cph += len(abe.crs['group'].serialize(value, compression=False))

            for value in ctxt['T_y'].values():
                size_cph += len(abe.crs['group'].serialize(value, compression=False))

            for value in ctxt['C_attr'].values():
                # size_cph += len(abe.crs['group'].serialize(value, compression=False))
                size_cph += len(value)  # , compression=False))

            for value in ctxt['attributes']:
                size_cph += len(str.encode(value, encoding='utf-8'))
                # len(abe.crs['group'].serialize(value, compression=False))

            # DO User revocation
            start_revoke_DU_1 =time.perf_counter()
            state_DO, rk_Urev_DO, umrk = abe.revoke1(prv_DO, msk, UL=revoked_user_list)#['bob', 'calvin', 'dorothee'])
            end_revoke_DU_1 =time.perf_counter()
            time_revoke_DU_1 = end_revoke_DU_1 - start_revoke_DU_1
            sum_revoke_1 += time_revoke_DU_1
            sum_revoke_user_srmacpabe += time_revoke_DU_1

            size_merkle_tree += state_DO[-1].get('MHT').leaves.__sizeof__()
            # for i in range(1, state_DO[-1].get('MHT').get_leaf_count()):
            #     new_leaf = state_DO[-1].get('MHT').get_leaf(i)
            #     size_merkle_tree += new_leaf.__sizeof__()


            # TEE-CS User revocation update
            # revocation updates by the cloud
            start_revoke_DU_3 =time.perf_counter()
            gid_bytes = bytes(alice['gid'], 'utf-8')
            mht_hash_gid = hashlib.sha256(gid_bytes).hexdigest()
            RC1, alice['DU_hkey'] = abe.revoke3(rk_Urev_DO, umrk, mht_hash_gid, alice['DU_hkey'], ctxt, pub_DO)
            end_revoke_DU_3 =time.perf_counter()
            time_revoke_DU_3 = end_revoke_DU_3 - start_revoke_DU_3
            sum_revoke_3 += time_revoke_DU_3
            sum_revoke_user_srmacpabe += time_revoke_DU_3

            # AA attribute revocation
            start_revoke_DU_2 =time.perf_counter()
            state_AA_1, amrk_1 = abe.revoke2(abe.authorities[1]['attributes'], AA_ID=1)
            state_AA_2, amrk_2 = abe.revoke2(abe.authorities[2]['attributes'], AA_ID=2)
            state_AA_3, amrk_3 = abe.revoke2(abe.authorities[3]['attributes'], AA_ID=3)
            end_revoke_DU_2 =time.perf_counter()
            time_revoke_DU_2 = end_revoke_DU_2 - start_revoke_DU_2
            sum_revoke_2 += time_revoke_DU_2
            sum_revoke_attribute_srmacpabe += time_revoke_DU_2
            sum_generate_update_inf_AA_srmacpabe += time_revoke_DU_2

            # TEE-CS Attribute revocation update
            # revocation updates by the cloud
            start_revoke_DU_4 =time.perf_counter()
            gid_bytes = bytes(alice['gid'], 'utf-8')
            hash_gid = hashlib.sha256(gid_bytes).hexdigest()
            RC2, alice['DU_hkey'] = abe.revoke4(amrk_1, hash_gid, alice['DU_hkey'], ctxt, pub_DO, AA_ID=1)
            RC3, alice['DU_hkey'] = abe.revoke4(amrk_2, hash_gid, alice['DU_hkey'], RC2, pub_DO, AA_ID=2)
            RC4, alice['DU_hkey'] = abe.revoke4(amrk_3, hash_gid, alice['DU_hkey'], RC3, pub_DO, AA_ID=3)
            end_revoke_DU_4 =time.perf_counter()
            time_revoke_DU_4 = end_revoke_DU_4 - start_revoke_DU_4
            sum_revoke_4 += time_revoke_DU_4
            sum_revoke_attribute_srmacpabe += time_revoke_DU_4

            # TEE-CS ciphertext transformation
            # outsourced decryption by the cloud
            start_transform =time.perf_counter()
            TC, I = abe.Transform(RC4, alice['DU_hkey'])
            end_transform =time.perf_counter()
            time_transform = end_transform - start_transform
            sum_transform += time_transform

            # Final decryption stage by Data User
            start_decrypt =time.perf_counter()
            M2 = abe.Decrypt(RC4, TC, I, alice['DO_key'], alice['DU_hkey'], pub_DO)
            end_decrypt =time.perf_counter()
            time_decrypt = end_decrypt - start_decrypt
            sum_decrypt_srmacpabe += time_decrypt

            # sanity check
            assert msg == M2, "FAILED Decryption: message is incorrect"

        elif abe.name == "ROUSELAKIS-WATERS":
            # setup time
            start_setup = time.perf_counter()
            pk = abe.setup()
            end_setup = time.perf_counter()
            time_setup = end_setup - start_setup
            sum_setup_rw += time_setup

            # Register a single user
            # such user stands as the target user
            start_setup_1 = time.perf_counter()
            alice= {}
            alice['gid'] = 'alice'
            end_setup_1 = time.perf_counter()
            time_setup_1 = end_setup_1 - start_setup_1
            # sum_setup_srmacpabe += time_setup_1
            sum_reg_user_rw += time_setup_1

            # Authority Setup
            start_setup_2 = time.perf_counter()
            (public_key1, secret_key1) = abe.authsetup(pk, 'AA1')
            (public_key2, secret_key2) = abe.authsetup(pk, 'AA2')
            (public_key3, secret_key3) = abe.authsetup(pk, 'AA3')
            public_keys = {'AA1': public_key1, 'AA2': public_key2, 'AA3': public_key3}
            end_setup_2 = time.perf_counter()
            time_setup = end_setup_2 - start_setup_2
            sum_AA_setup_rw += time_setup

            # Keygen
            start_keygen = time.perf_counter()
            list_length = int(len(attr_list) / 3)
            attr_list_1 = []  # attr_list[0:list_length]
            attr_list_2 = []  # attr_list[list_length:(2 * list_length)]
            attr_list_3 = []  # attr_list[(2 * list_length):len(attr_list)]
            #
            for index in range(len(attr_list)):
                if '@AA1' in attr_list[index]:
                    attr_list_1.append(attr_list[index])
                #
                if '@AA2' in attr_list[index]:
                    attr_list_2.append(attr_list[index])
                #
                if '@AA3' in attr_list[index]:
                    attr_list_3.append(attr_list[index])
            #
            user_keys1 = abe.multiple_attributes_keygen(pk, secret_key1, alice['gid'], attr_list_1)
            user_keys2 = abe.multiple_attributes_keygen(pk, secret_key2, alice['gid'], attr_list_2)
            user_keys3 = abe.multiple_attributes_keygen(pk, secret_key3, alice['gid'], attr_list_3)
            user_keys = {'GID': alice['gid'], 'keys': merge_dicts(user_keys1, user_keys2, user_keys3)}
            end_keygen = time.perf_counter()
            time_keygen = end_keygen - start_keygen
            sum_keygen_rw += time_keygen

            # Encrypt
            start_enc = time.perf_counter()
            ctxt = abe.encrypt(pk, public_keys, msg, policy_str)
            end_enc = time.perf_counter()
            time_enc = end_enc - start_enc
            sum_enc_rw += time_enc
            #
            size_cph_rw += len(abe.group.serialize(ctxt['C0'], compression=False)) + len(
                str.encode(ctxt['policy'], encoding='utf-8'))
            #
            for value in ctxt['C1'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))
            #
            for value in ctxt['C2'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))
            #
            for value in ctxt['C3'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))
            #
            for value in ctxt['C4'].values():
                size_cph_rw += len(abe.group.serialize(value, compression=False))

            # Decrypt
            start_dec = time.perf_counter()
            rec_msg = abe.decrypt(pk, user_keys, ctxt)
            end_dec = time.perf_counter()
            time_dec = end_dec - start_dec
            sum_dec_rw += time_dec

            # sanity check
            # if rec_msg != msg:
            assert rec_msg == msg, "Decryption in Rouselakis-Waters scheme failed !"

        elif abe.name == "KANYANG-XIAOHUAJIA":

            # splitting the list of attributes into three sublists
            list_length = int(len(attr_list) / 3)
            attr_list_1 = attr_list[0:list_length]
            attr_list_2 = attr_list[list_length:(2 * list_length)]
            attr_list_3 = attr_list[(2 * list_length):len(attr_list)]
            #
            # setup time
            start_setup =time.perf_counter()
            GPP, GMK = abe.setup()
            end_setup =time.perf_counter()
            time_setup = end_setup - start_setup
            sum_setup_kyxj += time_setup
            # ----------------------------------------------------------
            # Register a single user (we only generate a single user secret key)
            start_setup_1 =time.perf_counter()
            users = {}  # public user data
            AADict = {}  # dictionary of authorities
            #
            # target unrevoked user
            user_1 = {
                'id': 'user_1', 'authoritySecretKeys_AA1': {}, 'authoritySecretKeys_AA2': {},
                'authoritySecretKeys_AA3': {}, 'keys': None
            }
            #
            user_1['keys'], users[user_1['id']] = abe.regUser(GPP)
            #
            end_setup_1 =time.perf_counter()
            time_setup_1 = end_setup_1 - start_setup_1
            # sum_setup_kyxj += time_setup
            sum_reg_user_kyxj += time_setup_1
            # ------------------------------------------------------------
            # register three AA (Attribute Authorities)
            start_setup_2 =time.perf_counter()
            #
            AA1 = "AA_1"
            abe.setupAA(GPP, AA1, attr_list_1, AADict)
            #
            AA2 = "AA_2"
            abe.setupAA(GPP, AA2, attr_list_2, AADict)
            #
            AA3 = "AA_3"
            abe.setupAA(GPP, AA3, attr_list_3, AADict)
            #
            end_setup_2 =time.perf_counter()
            time_setup_2 = end_setup_2 - start_setup_2
            # sum_setup_kyxj += time_setup
            sum_AA_setup_kyxj += time_setup_2

            # Keygen
            start_keygen =time.perf_counter()
            # AA1
            for attr in range(len(attr_list_1)):
                abe.keygen(GPP, AADict[AA1], attr_list_1[attr], users[user_1['id']], user_1['authoritySecretKeys_AA1'])

            # AA2
            for attr in range(len(attr_list_2)):
                abe.keygen(GPP, AADict[AA2], attr_list_2[attr], users[user_1['id']], user_1['authoritySecretKeys_AA2'])

            # AA3
            for attr in range(len(attr_list_3)):
                abe.keygen(GPP, AADict[AA3], attr_list_3[attr], users[user_1['id']], user_1['authoritySecretKeys_AA3'])

            end_keygen =time.perf_counter()
            time_keygen = end_keygen - start_keygen
            sum_keygen_kyxj += time_keygen

            # encrypt
            start_enc =time.perf_counter()

            # for simplicity, we reconstruct sub-policies using attributes
            policy_str_1 = '(' + attr_list_1[0]
            policy_str_2 = '(' + attr_list_2[0]
            policy_str_3 = '(' + attr_list_3[0]
            for att in attr_list_1[1:]:
                policy_str_1 += ' and ' + att  # {i}'
            policy_str_1 += ')'

            for att in attr_list_2[1:]:
                policy_str_2 += ' and ' + att  # {i}'
            policy_str_2 += ')'

            for att in attr_list_3[1:]:
                policy_str_3 += ' and ' + att  # {i}'
            policy_str_3 += ')'

            # For simplicity, we assume AAi manages attributes in the access policy over the content key ki and

            # ctxt_1 = abe.encrypt(GPP, policy_str_1, k1, AADict[AA1])
            ctxt_1 = abe.encrypt(GPP, policy_str_1, k1, AADict[AA1])
            ctxt_2 = abe.encrypt(GPP, policy_str_2, k2, AADict[AA2])
            ctxt_3 = abe.encrypt(GPP, policy_str_3, k3, AADict[AA3])

            end_enc =time.perf_counter()
            time_enc = end_enc - start_enc
            sum_enc_kyxj += time_enc
            #
            # encryption ciphertext size
            avg_C1 = (len(abe.group.serialize(ctxt_1['C1'], compression=False)) +
                      len(abe.group.serialize(ctxt_2['C1'], compression=False)) +
                      len(abe.group.serialize(ctxt_3['C1'], compression=False))) / 3
            #
            avg_C2 = (len(abe.group.serialize(ctxt_1['C2'], compression=False)) + len(
                abe.group.serialize(ctxt_2['C2'], compression=False)) + len(
                abe.group.serialize(ctxt_3['C2'], compression=False))) / 3
            #
            avg_C3 = (len(abe.group.serialize(ctxt_1['C3'], compression=False)) + len(
                abe.group.serialize(ctxt_2['C3'], compression=False)) + len(
                abe.group.serialize(ctxt_3['C3'], compression=False))) / 3

            avg_policy_size = (len(str.encode(ctxt_1['policy'], encoding='utf-8'))
                               + len(str.encode(ctxt_2['policy'], encoding='utf-8'))
                               + len(str.encode(ctxt_3['policy'], encoding='utf-8'))) / 3

            size_cph_kyxj += avg_C1 + avg_C2 + avg_C3 + avg_policy_size
            # -----------------------------------------------------------------------------
            size_cph_kyxj_C_1 = 0
            size_cph_kyxj_C_2 = 0
            size_cph_kyxj_C_3 = 0
            #
            for value in ctxt_1['C'].values():
                size_cph_kyxj_C_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['C'].values():
                size_cph_kyxj_C_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['C'].values():
                size_cph_kyxj_C_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_C_1 + size_cph_kyxj_C_2 + size_cph_kyxj_C_3) / 3
            # --------------------------------------------------------------------------------
            size_cph_kyxj_CS_1 = 0
            size_cph_kyxj_CS_2 = 0
            size_cph_kyxj_CS_3 = 0
            #
            for value in ctxt_1['CS'].values():
                size_cph_kyxj_CS_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['CS'].values():
                size_cph_kyxj_CS_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['CS'].values():
                size_cph_kyxj_CS_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_CS_1 + size_cph_kyxj_CS_2 + size_cph_kyxj_CS_3) / 3
            # -------------------------------------------------------------------------------
            size_cph_kyxj_D_1 = 0
            size_cph_kyxj_D_2 = 0
            size_cph_kyxj_D_3 = 0
            #
            for value in ctxt_1['D'].values():
                size_cph_kyxj_D_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['D'].values():
                size_cph_kyxj_D_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['C'].values():
                size_cph_kyxj_D_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_D_1 + size_cph_kyxj_D_2 + size_cph_kyxj_D_3) / 3
            # -------------------------------------------------------------------------------
            size_cph_kyxj_DS_1 = 0
            size_cph_kyxj_DS_2 = 0
            size_cph_kyxj_DS_3 = 0
            #
            for value in ctxt_1['DS'].values():
                size_cph_kyxj_DS_1 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_2['DS'].values():
                size_cph_kyxj_DS_2 += len(abe.group.serialize(value, compression=False))
            for value in ctxt_3['DS'].values():
                size_cph_kyxj_DS_3 += len(abe.group.serialize(value, compression=False))
            #
            size_cph_kyxj += (size_cph_kyxj_DS_1 + size_cph_kyxj_DS_2 + size_cph_kyxj_DS_3) / 3

            # assume user 1 is unrevoked and update user 1 on all attributes
            start_revoke_DU =time.perf_counter()
            #
            # update information for secret keys of non-revoked users
            for att in attr_list_1:
                start_generate_update_inf =time.perf_counter()
                UK = abe.ukeygen(GPP, AADict[AA1], att, users[user_1['id']])
                end_generate_update_inf_AA1 =time.perf_counter()
                current_time_update_inf = end_generate_update_inf_AA1 - start_generate_update_inf
                sum_generate_update_inf_AA_kyxj += current_time_update_inf

                start_update_DU_Key =time.perf_counter()
                abe.skupdate(user_1['authoritySecretKeys_AA1'], att, UK['UKs'])
                end_update_DU_Key =time.perf_counter()
                current_time_update_DU_key = end_update_DU_Key - start_update_DU_Key
                sum_update_DU_key_kyxj += current_time_update_DU_key

                start_update_CT =time.perf_counter()
                abe.ctupdate(GPP, ctxt_1, att, UK['UKc'])
                end_update_CT =time.perf_counter()
                current_time_update_CT = end_update_CT - start_update_CT
                sum_update_CT_kyxj += current_time_update_CT

            for att in attr_list_2:
                start_generate_update_inf =time.perf_counter()
                UK = abe.ukeygen(GPP, AADict[AA2], att, users[user_1['id']])
                end_generate_update_inf_AA2 =time.perf_counter()
                current_time_update_inf = end_generate_update_inf_AA2 - start_generate_update_inf
                sum_generate_update_inf_AA_kyxj += current_time_update_inf

                start_update_DU_Key =time.perf_counter()
                abe.skupdate(user_1['authoritySecretKeys_AA2'], att, UK['UKs'])
                end_update_DU_Key =time.perf_counter()
                current_time_update_DU_key = end_update_DU_Key - start_update_DU_Key
                sum_update_DU_key_kyxj += current_time_update_DU_key

                start_update_CT =time.perf_counter()
                abe.ctupdate(GPP, ctxt_2, att, UK['UKc'])
                end_update_CT =time.perf_counter()
                current_time_update_CT = end_update_CT - start_update_CT
                sum_update_CT_kyxj += current_time_update_CT

            for att in attr_list_3:
                start_generate_update_inf =time.perf_counter()
                UK = abe.ukeygen(GPP, AADict[AA3], att, users[user_1['id']])
                end_generate_update_inf_AA3 =time.perf_counter()
                current_time_update_inf = end_generate_update_inf_AA3 - start_generate_update_inf
                sum_generate_update_inf_AA_kyxj += current_time_update_inf

                start_update_DU_Key =time.perf_counter()
                abe.skupdate(user_1['authoritySecretKeys_AA3'], att, UK['UKs'])
                end_update_DU_Key =time.perf_counter()
                current_time_update_DU_key = end_update_DU_Key - start_update_DU_Key
                sum_update_DU_key_kyxj += current_time_update_DU_key

                start_update_CT =time.perf_counter()
                abe.ctupdate(GPP, ctxt_3, att, UK['UKc'])
                end_update_CT =time.perf_counter()
                current_time_update_CT = end_update_CT - start_update_CT
                sum_update_CT_kyxj += current_time_update_CT

            end_revoke_DU =time.perf_counter()
            time_revoke_DU = end_revoke_DU - start_revoke_DU
            sum_revoke_user_kyxj += time_revoke_DU

            # Decrypt
            start_dec =time.perf_counter()
            rec_msg_1 = abe.decrypt(GPP, ctxt_1, user_1, 'authoritySecretKeys_AA1')
            rec_msg_2 = abe.decrypt(GPP, ctxt_2, user_1, 'authoritySecretKeys_AA2')
            rec_msg_3 = abe.decrypt(GPP, ctxt_3, user_1, 'authoritySecretKeys_AA3')
            end_dec =time.perf_counter()
            time_dec = end_dec - start_dec
            sum_dec_kyxj += time_dec

            assert rec_msg_1 == k1, 'FAILED DECRYPTION!'
            assert rec_msg_2 == k2, 'FAILED DECRYPTION!'
            assert rec_msg_3 == k3, 'FAILED DECRYPTION!'

    # compute average time
    time_setup_kyxj = sum_setup_kyxj / N
    time_setup_srmacpabe = sum_setup_srmacpabe / N
    time_setup_rw = sum_setup_rw / N

    time_enc_kyxj = sum_enc_kyxj / N
    time_enc_srmacpabe = sum_enc_srmacpabe / N
    time_enc_rw = sum_enc_rw / N

    time_keygen_kyxj = sum_keygen_kyxj / N
    time_keygen_srmacpabe = sum_keygen_srmacpabe / N
    time_keygen_rw = sum_keygen_rw / N

    time_dec_kyxj = sum_dec_kyxj / N
    time_dec_srmacpabe = sum_decrypt_srmacpabe / N
    time_dec_rw = sum_dec_rw / N

    time_keygen_1 = sum_keygen_1 / N
    time_keygen_2 = sum_keygen_2 / N
    time_keygen_3 = sum_keygen_3 / N
    time_keygen_4 = sum_keygen_4 / N
    time_transform = sum_transform / N
    avg_size_cph_srcmacpabe = size_cph / N
    # -----------------------------------------------------

    time_AA_setup_kyxj = sum_AA_setup_kyxj / N
    time_AA_setup_srmacpabe = sum_reg_aa_srmacpabe / N
    time_AA_setup_rw = sum_AA_setup_rw / N

    time_reg_user_kyxj = sum_reg_user_kyxj / N
    time_reg_user_srmacpabe = sum_reg_user_srmacpabe / N
    time_reg_user_rw = sum_reg_user_rw / N

    time_revoke_user_kyxj = sum_revoke_user_kyxj / N
    time_revoke_user_srmacpabe = sum_revoke_user_srmacpabe / N
    time_revoke_attribute_srmacpabe = sum_revoke_attribute_srmacpabe / N

    time_revoke_1 = sum_revoke_1 / N
    time_revoke_2 = sum_revoke_2 / N
    time_revoke_3 = sum_revoke_3 / N
    time_revoke_4 = sum_revoke_4 / N

    # time_update_inf_kyxj = sum_generate_update_inf_AA_kyxj / N
    # time_update_DU_key_kyxj = sum_update_DU_key_kyxj / N
    # time_update_CT_kyxj = sum_update_CT_kyxj / N
    # avg_size_cph_srmacpabe = size_sr / N

    # avg_size_cph_srcmacpabe = size_cph / N
    avg_size_cph_kyxj = size_cph_kyxj / N
    avg_size_cph_rw = size_cph_rw / N
    avg_size_merkle_tree = size_merkle_tree / N

    return [time_setup_kyxj, time_keygen_kyxj, time_enc_kyxj, time_revoke_user_kyxj, time_dec_kyxj,
            time_reg_user_kyxj, time_AA_setup_kyxj, time_setup_srmacpabe, time_keygen_srmacpabe, time_enc_srmacpabe,
            time_revoke_user_srmacpabe, time_dec_srmacpabe, time_reg_user_srmacpabe, time_AA_setup_srmacpabe,
            time_revoke_attribute_srmacpabe, time_transform, time_revoke_1, time_revoke_2, time_revoke_3, time_revoke_4,
            time_keygen_1, time_keygen_2, time_keygen_3, time_keygen_4, time_setup_rw, time_keygen_rw, time_enc_rw,
            time_dec_rw, time_reg_user_rw, time_AA_setup_rw, avg_size_cph_kyxj, avg_size_cph_srcmacpabe, avg_size_cph_rw, avg_size_merkle_tree]


def print_running_time(scheme_name, times, attr_number):
    print('{:<26}'.format(scheme_name) + str(attr_number).format(' ') + '         ' + format(times[0] * 1000,
                                                                                             '7.2f') + '        ' + format(
        times[1] * 1000,
        '7.2f') + '       ' + format(
        times[2] * 1000, '7.2f') + '       ' + format(times[3] * 1000, '7.2f'))


def run_all(pairing_group, policy_size, policy_str, attr_list, rw_policy_string, rw_attr_list, revoked_user_list, k1, k2, k3, msg):
    algos = ['#attributes', 'Setup (ms)', 'KeyGen (ms)', 'Enc (ms)', 'Dec (ms)', 'Ciphertext (bytes)']

    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)

    print('Running times (msp) curve', curve_type, ': n1={}  n2={}  m={}  I={}'.format(n1, n2, m, i))
    algo_string = 'CP-ABE {:<13}'.format('') + '  ' + algos[0] + '     ' + algos[1] + '    ' + algos[2] + '     ' + \
                  algos[3] + '      ' + \
                  algos[4] + '      ' + algos[5]
    print('-' * 120)
    print(algo_string)
    print('-' * 120)
    #
    #
    sr_macp_abe24 = SR_MACP_ABE(pairing_group)
    sr_macp_abe_times = measure_average_times(sr_macp_abe24, attr_list, policy_str, revoked_user_list, k1, k2, k3, msg)

    print_running_time(sr_macp_abe24.name, sr_macp_abe_times, len(attr_list))
    print('{:<26}'.format('   | setup') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(sr_macp_abe_times[7] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | keygen 1') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(sr_macp_abe_times[20] * 1000, '7.2f') + '             -' + format(' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | keygen 2') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(sr_macp_abe_times[21] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | keygen 3') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(sr_macp_abe_times[22] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | keygen 4') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(sr_macp_abe_times[23] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | encrypt ') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + ' ' + '{:<6}'.format('') + '      -       ' +
          format(sr_macp_abe_times[9] * 1000, '7.2f') + '             -' + format(' ') + '                   -')

    print('{:<26}'.format('   | transform') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' +
          format(sr_macp_abe_times[15] * 1000, '7.2f') + '                    -')

    print('{:<26}'.format('   | decrypt') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' +
          format(sr_macp_abe_times[11] * 1000, '7.2f') + '                    -')

    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' + '      -               ' +
          format(sr_macp_abe_times[31], '5.1f'))

    print('{:<26}'.format('   | mkl_size (bytes)') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' + '      -               ' +
          format(sr_macp_abe_times[33], '5.1f'))
    #
    output_data_srmacpabe['Scheme'].append(sr_macp_abe24.name)
    output_data_srmacpabe['#attributes'].append(len(attr_list))
    output_data_srmacpabe['Setup (ms)'].append(sr_macp_abe_times[7]*1000)
    output_data_srmacpabe['Keygen (ms)'].append(sr_macp_abe_times[8]*1000)
    output_data_srmacpabe['Encrypt (ms)'].append(sr_macp_abe_times[9]*1000)
    output_data_srmacpabe['Transform (ms)'].append(sr_macp_abe_times[15]*1000)
    output_data_srmacpabe['Decrypt (ms)'].append(sr_macp_abe_times[11]*1000)
    output_data_srmacpabe['Ciphertext size (bytes)'].append(sr_macp_abe_times[31])
    output_data_srmacpabe['URevocation (ms)'].append(sr_macp_abe_times[10]*1000)
    output_data_srmacpabe['ARevocation (ms)'].append(sr_macp_abe_times[14]*1000)
    output_data_srmacpabe['URegistration (ms)'].append(sr_macp_abe_times[12]*1000)
    output_data_srmacpabe['AASetup (ms)'].append(sr_macp_abe_times[13]*1000)
    output_data_srmacpabe['Merkle tree size (bytes)'].append(sr_macp_abe_times[33])

    #
    # output_data['None'].append(0)
    #

    sr_macp_abe_cph_data['Scheme'].append(sr_macp_abe24.name)
    sr_macp_abe_cph_data['#attributes'].append(len(attr_list))
    sr_macp_abe_cph_data['Keygen1 (ms)'].append(sr_macp_abe_times[20]*1000)
    sr_macp_abe_cph_data['Keygen2 (ms)'].append(sr_macp_abe_times[21]*1000)
    sr_macp_abe_cph_data['Keygen3 (ms)'].append(sr_macp_abe_times[22]*1000)
    sr_macp_abe_cph_data['Keygen4 (ms)'].append(sr_macp_abe_times[23]*1000)
    sr_macp_abe_cph_data['Encrypt (ms)'].append(sr_macp_abe_times[9]*1000)
    sr_macp_abe_cph_data['Transform (ms)'].append(sr_macp_abe_times[15]*1000)
    sr_macp_abe_cph_data['Decrypt (ms)'].append(sr_macp_abe_times[11]*1000)
    sr_macp_abe_cph_data['Ciphertext size (bytes)'].append(sr_macp_abe_times[31])
    sr_macp_abe_cph_data['Revoke 1 (ms)'].append(sr_macp_abe_times[16]*1000)
    sr_macp_abe_cph_data['Revoke 2 (ms)'].append(sr_macp_abe_times[17]*1000)
    sr_macp_abe_cph_data['Revoke 3 (ms)'].append(sr_macp_abe_times[18]*1000)
    sr_macp_abe_cph_data['Revoke 4 (ms)'].append(sr_macp_abe_times[19]*1000)
    sr_macp_abe_cph_data['Uregistration (ms)'].append(sr_macp_abe_times[12]*1000)
    sr_macp_abe_cph_data['AASetup (ms)'].append(sr_macp_abe_times[13]*1000)
    sr_macp_abe_cph_data['Urevocation (ms)'].append(sr_macp_abe_times[10]*1000)
    sr_macp_abe_cph_data['Arevocation (ms)'].append(sr_macp_abe_times[14]*1000)
    sr_macp_abe_cph_data['Merkle tree size (bytes)'].append(sr_macp_abe_times[33])

    #
    #
    # return [time_setup_kyxj, time_keygen_kyxj, time_enc_kyxj, time_revoke_user_kyxj, time_dec_kyxj,
    #         time_reg_user_kyxj, time_AA_setup_kyxj, time_setup_srmacpabe, time_keygen_srmacpabe, time_enc_srmacpabe,
    #         time_revoke_user_srmacpabe, time_dec_srmacpabe, time_reg_user_srmacpabe, time_AA_setup_srmacpabe,
    #         time_revoke_attribute_srmacpabe, time_transform, time_revoke_1, time_revoke_2, time_revoke_3, time_revoke_4,
    #         time_keygen_1, time_keygen_2, time_keygen_3, time_keygen_4, avg_size_cph_kyxj, avg_size_cph_srcmacpabe]

    maabe_yj14_cp = MAABE(pairing_group)
    maabe_yj14_cp_times = measure_average_times(maabe_yj14_cp, attr_list, policy_str, revoked_user_list, k1, k2, k3, msg)
    print_running_time(maabe_yj14_cp.name, maabe_yj14_cp_times, len(attr_list))
    print('{:<26}'.format('   | authority setup ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_yj14_cp_times[6] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | user registration ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_yj14_cp_times[5] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | setup ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_yj14_cp_times[0] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | keygen') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(maabe_yj14_cp_times[1] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | encrypt ') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + ' ' + '{:<6}'.format('') + '      -       ' +
          format(maabe_yj14_cp_times[2] * 1000, '7.2f') + '             -' + format(' ') + '                   -')

    print('{:<26}'.format('   | decrypt') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' +
          format(maabe_yj14_cp_times[4] * 1000, '7.2f') + '                    -')

    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' + '      -               ' +
          format(maabe_yj14_cp_times[30], '5.1f'))
    #
    output_data_kyxj['Scheme'].append(maabe_yj14_cp.name)
    output_data_kyxj['#attributes'].append(len(attr_list))
    output_data_kyxj['Setup (ms)'].append(maabe_yj14_cp_times[0] * 1000)
    output_data_kyxj['Keygen (ms)'].append(maabe_yj14_cp_times[1] * 1000)
    output_data_kyxj['Encrypt (ms)'].append(maabe_yj14_cp_times[2] * 1000)
    output_data_kyxj['Decrypt (ms)'].append(maabe_yj14_cp_times[4] * 1000)
    output_data_kyxj['Ciphertext size (bytes)'].append(maabe_yj14_cp_times[30])
    output_data_kyxj['URevocation (ms)'].append(maabe_yj14_cp_times[3] * 1000)
    output_data_kyxj['URegistration (ms)'].append(maabe_yj14_cp_times[5] * 1000)
    output_data_kyxj['AASetup (ms)'].append(maabe_yj14_cp_times[6] * 1000)

    # output_data_kyxj['Transform (ms)'].append(0)
    # output_data_kyxj['ARevocation (ms)'].append(0)

    maabe_rw15_cp = MaabeRW15(pairing_group)
    maabe_rw15_cp_times = measure_average_times(maabe_rw15_cp, rw_attr_list, rw_policy_string, revoked_user_list, k1, k2, k3, msg)
    print_running_time(maabe_rw15_cp.name, maabe_rw15_cp_times, len(rw_attr_list))
    print('{:<26}'.format('   | authority setup ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_rw15_cp_times[29] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | user registration ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_rw15_cp_times[28] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | setup ') + str(len(attr_list)).format(' ') + '{:<9}'.format('') +
          format(maabe_rw15_cp_times[24] * 1000, '7.2f') + '              -' + '             -' + format(
        ' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | keygen') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(maabe_rw15_cp_times[25] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')

    print('{:<26}'.format('   | encrypt ') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + ' ' + '{:<6}'.format('') + '      -       ' +
          format(maabe_rw15_cp_times[26] * 1000, '7.2f') + '             -' + format(' ') + '                   -')

    print('{:<26}'.format('   | decrypt') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' +
          format(maabe_rw15_cp_times[27] * 1000, '7.2f') + '                    -')

    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' + '      -               ' +
          format(maabe_rw15_cp_times[32], '5.1f'))

    #
    output_data_rw15['Scheme'].append(maabe_rw15_cp.name)
    output_data_rw15['#attributes'].append(len(attr_list))
    output_data_rw15['Setup (ms)'].append(maabe_rw15_cp_times[24]*1000)
    output_data_rw15['Keygen (ms)'].append(maabe_rw15_cp_times[25]*1000)
    output_data_rw15['Encrypt (ms)'].append(maabe_rw15_cp_times[26]*1000)
    output_data_rw15['Decrypt (ms)'].append(maabe_rw15_cp_times[27]*1000)
    output_data_rw15['Ciphertext size (bytes)'].append(maabe_rw15_cp_times[32])
    output_data_rw15['URegistration (ms)'].append(maabe_rw15_cp_times[28] * 1000)
    output_data_rw15['AASetup (ms)'].append(maabe_rw15_cp_times[29] * 1000)
    #


# get parameters of the monotone span program
def get_par(pairing_group, policy_str, attr_list):
    msp_obj = MSP(pairing_group)
    policy = msp_obj.createPolicy(policy_str)
    mono_span_prog = msp_obj.convert_policy_to_msp(policy)
    nodes = msp_obj.prune(policy, attr_list)

    n1 = len(mono_span_prog)  # number of rows
    n2 = msp_obj.len_longest_row  # number of columns
    m = len(attr_list)  # number of attributes
    i = len(nodes)  # number of attributes in decryption

    return n1, n2, m, i


# create policy string and attribute list for a boolean formula of the form "1 and 2 and 3"
def create_policy_string_and_attribute_list(n, pairing_group):
    policy_string = '(1'
    attr_list = ['1']
    revoked_user = 'user'
    # we process the hidden access policy
    sr_macpabe_instance = SR_MACP_ABE(pairing_group)


    #we process the policy for Rouselakis-Waters
    rw_policy_string = '(1@AA1'
    rw_attr_list = ['1@AA1']
    AA_list = ['AA1', 'AA2', 'AA3']

    #we process the list of revoked users
    revoked_user_list =[f'{revoked_user}'+'1']

    for i in range(2, n + 1):
        policy_string += ' and ' + str(i)  # {i}'
        attr1 = str(i)  # f'{i}'
        attr_list.append(attr1)
        #
        attr1 = str(i) + '@' + random.choice(AA_list)
        rw_attr_list.append(attr1)
        rw_policy_string += ' and ' + attr1
        #
        revoked_user_list.append(f'{revoked_user}'+str(i))

    policy_string += ')'
    # hidden_policy_string += ')'
    rw_policy_string += ')'

    # attr_list = ['ONE', 'TWO', 'FOUR']

    # rw_policy_string, rw_attr_list
    return policy_string, attr_list, rw_policy_string, rw_attr_list, revoked_user_list


def main():
    # instantiate a bilinear pairing map
    # pairing_group = PairingGroup('MNT159')
    # pairing_group = PairingGroup('MNT224')
    pairing_group = PairingGroup(curve_type)

    msg = pairing_group.random(GT)

    gc.enable()

    # for 'KANYANG-XIAOHUAJIA' we suppose msg = msg1 || msg2 || msg3
    # we generate three content keys to realize E(k_i, m_i)
    k1 = pairing_group.random(GT)
    k2 = pairing_group.random(GT)
    k3 = pairing_group.random(GT)

    policy_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # policy_size = 1
    #
    # policy_str, attr_list, hidden_policy = create_policy_string_and_attribute_list(policy_size, pairing_group)
    # run_all(pairing_group, policy_size, policy_str, attr_list, hidden_policy, msg)

    for policy_size in policy_sizes:
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)
        policy_str, attr_list, rw_policy_string, rw_attr_list, revoked_user_list = create_policy_string_and_attribute_list(policy_size, pairing_group)
        run_all(pairing_group, policy_size, policy_str, attr_list, rw_policy_string, rw_attr_list, revoked_user_list, k1, k2, k3, msg)
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)

    # we write data to files
    df1 = pd.DataFrame(output_data_srmacpabe)
    df2 = pd.DataFrame(output_data_kyxj)
    df3 = pd.DataFrame(sr_macp_abe_cph_data)
    df4 = pd.DataFrame(output_data_rw15)

    df1.to_csv('output_data_srmacpabe.csv')
    df2.to_csv('output_data_kyxj.csv')
    df4.to_csv('output_data_rw15.csv')
    df3.to_csv('sr_macp_abe_cph_data.csv')


if __name__ == "__main__":
    debug = True
    main()
