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
import os
import pstats
import random
import threading
import timeit
import uuid
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
from pucture_main_code import P_MACP_ABE

# global variables to output data as CSV
output_data_pmacpabe = {
    'Scheme': list(),
    '#attributes': list(),
    'anonymity level': list(),
    'Setup (ms)': list(),
    'HideAttr (ms)': list(),
    'Keygen (ms)': list(),
    'Encrypt (ms)': list(),
    'Single puncture (ms)': list(),
    'Batch puncture (ms)': list(),
    'Transform (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list(),
    'URegistration (ms)': list(),
    'AASetup (ms)': list(),
    'Accumulator size (bytes)': list()
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
p_macp_abe_cph_data = {
    'Scheme': list(),
    '#attributes': list(),
    'K level': list(),
    'Keygen1 (ms)': list(),
    'HideAttr (ms)': list(),
    'Keygen2 (ms)': list(),
    'Keygen3 (ms)': list(),
    'Keygen4 (ms)': list(),
    'Encrypt (ms)': list(),
    'Puncture1 (ms)': list(),
    'Puncture2 (ms)': list(),
    'Puncture3 (ms)': list(),
    'Transform (ms)': list(),
    'Decrypt (ms)': list(),
    'Ciphertext size (bytes)': list(),
    'Uregistration (ms)': list(),
    'AASetup (ms)': list(),
    'ACC size (bytes)': list()
}

# SS512, SS1024
curve_type = "SS512"


def measure_average_times(abe, attr_list, policy_str, puncturable_attr_dict, k1, k2, k3, msg, privacy_level, epsilon_str, N=2):
    # for P_MACP_ABE
    # calling the garbage collector
    gc.collect(0)
    gc.collect(1)
    gc.collect(2)
    gc.collect()

    sum_setup_pmacpabe = 0
    sum_reg_user_pmacpabe = 0
    sum_reg_aa_pmacpabe = 0
    sum_hide_attr = 0
    sum_keygen_pmacpabe = 0
    sum_keygen_1 = 0
    sum_keygen_2 = 0
    sum_keygen_3 = 0
    sum_keygen_4 = 0
    sum_puncture_1 = 0
    sum_puncture_2 = 0
    sum_puncture_3 = 0
    sum_puncture_4 = 0
    #
    sum_single_puncture = 0
    sum_batch_puncture = 0
    #
    sum_transform = 0
    sum_decrypt = 0
    sum_enc_pmacpabe = 0
    sum_decrypt_pmacpabe = 0
    sum_puncture_pmacpabe = 0
    size_cph = 0
    size_accumulator_single_puncture = 0
    size_accumulator_batch_puncture = 0

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

        if abe.name == "P-MACP-ABE":
            list_length = int(len(attr_list) // 3)
            attr_list_1 = attr_list[0:list_length]
            attr_list_2 = attr_list[list_length:(2 * list_length)]
            attr_list_3 = attr_list[(2 * list_length):len(attr_list)]


            # setup time
            gc.collect(0)
            gc.collect(1)
            gc.collect(2)
            gc.collect()
            #
            start_setup = time.perf_counter()
            (prv_DO, pub_DO, pk, msk) = abe.setup_()
            end_setup = time.perf_counter()
            time_setup = end_setup - start_setup
            sum_setup_pmacpabe += time_setup


            # Register a single user
            # such user stands as the target user
            start_reg =time.perf_counter()
            # alice = abe.regUser('alice', attr_list, privacy_level)
            # FIX: regUser needs dict, not list
            alice = abe.regUser('alice', puncturable_attr_dict, privacy_level)

            end_reg =time.perf_counter()
            time_setup_1 = end_reg - start_reg
            # sum_setup_srmacpabe += time_setup_1
            sum_reg_user_pmacpabe += time_setup_1



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
            sum_reg_aa_pmacpabe += time_setup_2


            # DO Keygen1
            start_keygen_1 = time.perf_counter()
            alice['DO_key'] = abe.keygen1(msk, alice['gid'], prv_DO, epsilon_str)
            end_keygen_1 =time.perf_counter()
            time_keygen = end_keygen_1 - start_keygen_1
            sum_keygen_pmacpabe += time_keygen
            sum_keygen_1 += time_keygen


            # DU hide timing
            # DU hide timing
            start_hide = time.perf_counter()
            #
            # we need to create subdirectories relative to the use of attributes list per AA
            items = list(puncturable_attr_dict.items())
            list_length = len(items) // 3
            attr_dict_1 = dict(items[0:list_length])
            attr_dict_2 = dict(items[list_length:(2 * list_length)])
            attr_dict_3 = dict(items[(2 * list_length):])
            #
            attr_dict_1_hidden = abe.hide_attr(alice['gid'], alice['DO_key'], attr_dict_1)
            attr_dict_2_hidden = abe.hide_attr(alice['gid'], alice['DO_key'], attr_dict_2)
            attr_dict_3_hidden = abe.hide_attr(alice['gid'], alice['DO_key'], attr_dict_3)
            #
            end_hide = time.perf_counter()
            time_hide = end_hide - start_hide
            sum_hide_attr += time_hide


            # AA keygen2
            start_keygen_2 =time.perf_counter()
            #
            # hash_gid = abe.crs['group'].hash(str(alice['gid']), ZR)

            aa_key_1 = abe.keygen2(AA_ID=1, gid=alice['gid'], S_DU=attr_dict_1_hidden ) #alice['attributes'])
            print(f"the list of AA1 attributes is {attr_dict_1_hidden}")
            aa_key_2 = abe.keygen2(AA_ID=2, gid=alice['gid'], S_DU=attr_dict_2_hidden) #alice['attributes'])
            aa_key_3 = abe.keygen2(AA_ID=3, gid=alice['gid'], S_DU=attr_dict_3_hidden) #alice['attributes'])
            #
            end_keygen_2 =time.perf_counter()
            time_keygen = end_keygen_2 - start_keygen_2
            sum_keygen_pmacpabe += time_keygen
            sum_keygen_2 += time_keygen


            # TEE-CS Keygen3
            start_keygen_3 =time.perf_counter()
            #
            alice['TK_DU'] = abe.keygen3([aa_key_1, aa_key_2, aa_key_3], alice['gid'])
            #
            end_keygen_3 =time.perf_counter()
            time_keygen = end_keygen_3 - start_keygen_3
            sum_keygen_pmacpabe += time_keygen
            sum_keygen_3 += time_keygen


            # DU keygen4 time
            start_keygen_4 =time.perf_counter()
            alice['DU_key'], alice['DU_hkey'] = abe.keygen4(alice['DO_key'], alice['TK_DU'])
            end_keygen_4 =time.perf_counter()
            time_keygen = end_keygen_4 - start_keygen_4
            sum_keygen_pmacpabe += time_keygen
            sum_keygen_4 += time_keygen

            #-----------------------------------------------------------------------------------
            # we can only form the hidden policy from inside this code section
            # -----------------------------------------------------------------------------------
            raw_attr_1 = abe.hide_by_DO(msk, attribute_value=attr_list[0], epsilon=epsilon_str)
            hidden_attr_1 = abe.crs['group'].serialize(raw_attr_1, compression=False).hex().upper()

            #
            hidden_policy_str = f'({hidden_attr_1}'
           #
            for att in attr_list[1:]:
                raw_attr = abe.hide_by_DO(msk, attribute_value=att, epsilon=epsilon_str)
                hidden_attr = abe.crs['group'].serialize(raw_attr, compression=False).hex().upper()
                hidden_policy_str += f' and {hidden_attr}'
            hidden_policy_str += ')'


            # DO encryption
            start_enc_1 =time.perf_counter()
            #
            ctxt = abe.encrypt(pk, msk, msg, policy_str, prv_DO, epsilon_str, hidden_policy_str)

            # we get a copy of ctxt for decryption purposes since the puncturing will prevent normal decryption
            # ctxt_copy = ctxt
            #
            end_enc_1 =time.perf_counter()
            time_enc = end_enc_1 - start_enc_1
            sum_enc_pmacpabe += time_enc


            # size of ciphertext
            size_cph += len(abe.crs['group'].serialize(ctxt['C_tilde'], compression=False)) + len(
                abe.crs['group'].serialize(ctxt['C'], compression=False)) + len(
                abe.crs['group'].serialize(ctxt['W'], compression=False)) + len(
                abe.crs['group'].serialize(ctxt['sig_W'], compression=False)) + len(
                str.encode(ctxt['policy'], encoding='utf-8')) + len(
                abe.crs['group'].serialize(ctxt['ACC'].ACC_value, compression=False)) + len(
                abe.crs['group'].serialize(ctxt['ACC'].acc_len, compression=False))
            #
            for value in ctxt['C_y'].values():
                # size_cph += len(abe.crs['group'].serialize(value, compression=False))
                # C_y values are ints
                size_cph += len(str(value).encode('utf-8'))
            #
            for value in ctxt['T_y'].values():
                size_cph += len(abe.crs['group'].serialize(value, compression=False))
            #
            for value in ctxt['C_attr'].values():
                # size_cph += len(abe.crs['group'].serialize(value, compression=False))
                size_cph += len(value)  # , compression=False))
            #
            for value in ctxt['attributes']:
                size_cph += len(str.encode(value, encoding='utf-8'))
            #
            # for value in ctxt['ACC'].tag_list:
            #     size_cph += len(str.encode(value, encoding='utf-8'))
            #

            # before puncturing we need to safegard the values of DU_jkey and DU_hkey as our implementation applies both sequentially
            # but this can also be tolerated by our seamless design
            DU_key_bak = alice['DU_key']
            DU_hkey_bak = alice['DU_hkey']

            # ---------------------------------------------------------------------------------------------------
            # **************************user single puncturing ******************************
            # ---------------------------------------------------------------------------------------------------
            start_DU_puncture = time.perf_counter()
            tag_to_puncture = uuid.uuid4() # we generate a legit tag
            #
            alice['DU_key'], alice['DU_hkey'], T_prime, desc_T_prime = abe.DU_single_puncture(
                    alice['DU_key'], alice['DU_hkey'], tag_to_puncture, alice['gid'], alice['k_anonymity'])
            end_DU_puncture=time.perf_counter()
            time_puncture1 = end_DU_puncture - start_DU_puncture
            sum_puncture_1 += time_puncture1
            sum_single_puncture +=  time_puncture1

            # then the cloud performs the puncture to support the user  single puncture
            start_CSPpuncture = time.perf_counter()
            alice['DU_hkey'], ctxt['sig_ACC'] = abe.csp_puncture(ctxt, alice['DU_hkey'], T_prime, desc_T_prime, alice['gid'])
            end_CSP_puncture = time.perf_counter()
            time_puncture2 = end_CSP_puncture - start_CSPpuncture
            sum_puncture_2 += time_puncture2
            sum_single_puncture += time_puncture2

            # we need to update the size of the ciphertext here
            size_cph += len(abe.crs['group'].serialize(ctxt['sig_ACC'], compression=False))
            #
            for value in ctxt['ACC'].tag_list:
                size_cph += len(str.encode(value, encoding='utf-8'))
            #-------------------------------------------------------------------------------------------------------

            # we need to update the size of the accumulator for single puncture here
            if ctxt['ACC'].ACC_value is not None:
                size_accumulator_single_puncture += len(abe.crs['group'].serialize(ctxt['ACC'].ACC_value, compression=False))
            #
            for value in ctxt['ACC'].tag_list:
                size_accumulator_single_puncture += len(str.encode(value, encoding='utf-8'))

            # ---------------------------------------------------------------------------------------------------
            # **************************user batch puncturing ******************************
            # ---------------------------------------------------------------------------------------------------
            start_DU_puncture = time.perf_counter()
            #
            # use the original  secret and helper keys
            alice['DU_key'] = DU_key_bak
            alice['DU_hkey'] = DU_hkey_bak

            # k-anonymity should be greater than the number of attributes
            tag_to_puncture_list = [str(uuid.uuid4()) for _ in range(len(attr_list))] # uuid.uuid4() # we generate a legit tag
            #
            alice['DU_key'], alice['DU_hkey'], T_prime, desc_T_prime = abe.DU_batch_puncture(alice['DU_key'], alice['DU_hkey'], tag_to_puncture_list, alice['gid'], alice['k_anonymity'])
            end_DU_puncture=time.perf_counter()
            time_puncture3 = end_DU_puncture - start_DU_puncture
            sum_puncture_3 += time_puncture3
            sum_batch_puncture += time_puncture3

            # then the cloud performs the puncture to support the user  batch puncture
            start_CSPpuncture = time.perf_counter()
            alice['DU_hkey'], ctxt['sig_ACC'] = abe.csp_puncture(ctxt, alice['DU_hkey'], T_prime, desc_T_prime, alice['gid'])
            end_CSP_puncture = time.perf_counter()
            time_puncture4 = end_CSP_puncture - start_CSPpuncture
            sum_puncture_4 += time_puncture4
            sum_batch_puncture += time_puncture4

            # we need to update the size of the ciphertext here
            for value in ctxt['ACC'].tag_list:
                size_cph += len(str.encode(value, encoding='utf-8'))

            # we need to update the size of the accumulator for batch puncture here
            size_cph += len(abe.crs['group'].serialize(ctxt['sig_ACC'], compression=False))
            #
            size_accumulator_batch_puncture += len(
                abe.crs['group'].serialize(ctxt['ACC'].ACC_value, compression=False)) + len(
                abe.crs['group'].serialize(ctxt['ACC'].acc_len, compression=False))
            #
            for value in ctxt['ACC'].tag_list:
                size_accumulator_batch_puncture += len(str.encode(value, encoding='utf-8'))
            # -------------------------------------------------------------------------------------------------------

            # TEE-CS ciphertext transformation
            # outsourced decryption by the cloud
            start_transform =time.perf_counter()
            TC, I = abe.transform(ctxt, alice['DU_hkey'], alice['gid'])
            end_transform =time.perf_counter()
            time_transform = end_transform - start_transform
            sum_transform += time_transform

            # Final decryption stage by Data User
            start_decrypt =time.perf_counter()
            M2 = abe.decrypt(ctxt, TC, I, alice['DU_key'], pub_DO)
            end_decrypt =time.perf_counter()
            time_decrypt = end_decrypt - start_decrypt
            sum_decrypt_pmacpabe += time_decrypt

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
    time_setup_pmacpabe = sum_setup_pmacpabe / N
    # print(f" current summation time for setup {sum_setup_pmacpabe} \n")
    # print(f" current time for setup for P-MACPABE is {time_setup_pmacpabe} and for KYXJ is {time_setup_kyxj} for number of rounds {N} \n\n")
    time_setup_rw = sum_setup_rw / N

    time_hide_pmacpabe = sum_hide_attr / N

    time_keygen_kyxj = sum_keygen_kyxj / N
    time_keygen_pmacpabe = sum_keygen_pmacpabe / N
    time_keygen_rw = sum_keygen_rw / N
    #
    time_enc_kyxj = sum_enc_kyxj / N
    time_enc_pmacpabe = sum_enc_pmacpabe / N
    time_enc_rw = sum_enc_rw / N
    #
    time_dec_kyxj = sum_dec_kyxj / N
    time_dec_srmacpabe = sum_decrypt_pmacpabe / N
    time_dec_rw = sum_dec_rw / N

    time_puncture_1 = sum_puncture_1 / N # DU local single puncture
    time_puncture_2 = sum_puncture_2 / N # CSP single puncture
    time_puncture_3 = sum_puncture_3 / N # DU local batch puncture
    time_puncture_4 = sum_puncture_4 / N # CSP batch puncture

    time_single_puncture = sum_single_puncture / N
    time_batch_puncture = sum_batch_puncture / N

    time_keygen_1 = sum_keygen_1 / N
    time_keygen_2 = sum_keygen_2 / N
    time_keygen_3 = sum_keygen_3 / N
    time_keygen_4 = sum_keygen_4 / N
    time_transform = sum_transform / N
    # -----------------------------------------------------

    time_AA_setup_kyxj = sum_AA_setup_kyxj / N
    time_AA_setup_pmacpabe = sum_reg_aa_pmacpabe / N
    time_AA_setup_rw = sum_AA_setup_rw / N

    time_reg_user_kyxj = sum_reg_user_kyxj / N
    time_reg_user_pmacpabe = sum_reg_user_pmacpabe / N
    time_reg_user_rw = sum_reg_user_rw / N


    # time_update_inf_kyxj = sum_generate_update_inf_AA_kyxj / N
    # time_update_DU_key_kyxj = sum_update_DU_key_kyxj / N
    # time_update_CT_kyxj = sum_update_CT_kyxj / N
    # avg_size_cph_srmacpabe = size_sr / N

    # avg_size_cph_srcmacpabe = size_cph / N
    avg_size_cph_kyxj = size_cph_kyxj / N
    avg_size_cph_rw = size_cph_rw / N
    avg_accumulator_single_puncture = size_accumulator_single_puncture / N
    avg_accumulator_batch_puncture = size_accumulator_batch_puncture / N
    avg_size_cph_pcmacpabe = size_cph / N

    print(f'''{abe.name}--> {[time_setup_kyxj, time_keygen_kyxj, time_enc_kyxj, time_dec_kyxj, time_reg_user_kyxj, time_AA_setup_kyxj, time_setup_pmacpabe, time_keygen_pmacpabe, time_enc_pmacpabe,
    time_hide_pmacpabe, time_dec_srmacpabe, time_reg_user_pmacpabe, time_AA_setup_pmacpabe,
    time_transform, time_puncture_1, time_puncture_2, time_puncture_3, time_puncture_4, time_single_puncture,
            time_batch_puncture, time_keygen_1, time_keygen_2, time_keygen_3, time_keygen_4, time_setup_rw,
            time_keygen_rw, time_enc_rw, time_dec_rw, time_reg_user_rw, time_AA_setup_rw, avg_size_cph_kyxj,
            avg_size_cph_pcmacpabe, avg_size_cph_rw, avg_accumulator_single_puncture, avg_accumulator_batch_puncture]}\n''')

    return [time_setup_kyxj, time_keygen_kyxj, time_enc_kyxj, time_dec_kyxj,
            time_reg_user_kyxj, time_AA_setup_kyxj, time_setup_pmacpabe, time_keygen_pmacpabe, time_enc_pmacpabe,
            time_hide_pmacpabe, time_dec_srmacpabe, time_reg_user_pmacpabe, time_AA_setup_pmacpabe,
            time_transform, time_puncture_1, time_puncture_2, time_puncture_3, time_puncture_4, time_single_puncture,
            time_batch_puncture, time_keygen_1, time_keygen_2, time_keygen_3, time_keygen_4, time_setup_rw,
            time_keygen_rw, time_enc_rw, time_dec_rw, time_reg_user_rw, time_AA_setup_rw, avg_size_cph_kyxj,
            avg_size_cph_pcmacpabe, avg_size_cph_rw, avg_accumulator_single_puncture, avg_accumulator_batch_puncture]


def print_running_time(scheme_name, times, attr_number, privacy_level):
    # print(f" the time variable is {scheme_name}: {times}: {attr_number}: {privacy_level} \n\n")
    if scheme_name == "P-MACP-ABE":
        print('{:<26}'.format(scheme_name) + str(attr_number).format('  ') + 15*' ' + str(privacy_level).format('   ') + 11*' '+
            format(times[6] * 1000, '7.2f') + 8 * ' ' + format(times[7] * 1000, '7.2f') + 8 * ' ' +
            format(times[8] * 1000, '7.2f') + 8 * ' ' + format(times[10] * 1000, '7.2f') + 11 * ' ' +
            format(times[31] * 1000, '7.2f') + 11 * ' ' + format(times[11] * 1000, '7.2f')

            )
    else:
        print('{:<26}'.format(scheme_name) + str(attr_number).format(' ') + '         ' + format(times[0] * 1000,
                                                                                                 '7.2f') + '        ' + format(
            times[1] * 1000,
            '7.2f') + '       ' + format(
            times[2] * 1000, '7.2f') + '       ' + format(times[3] * 1000, '7.2f'))

# def measure_average_times(abe, attr_list, policy_str, revoked_user_list, k1, k2, k3, msg, privacy_level, epsilon_str, hidden_policy_str, N=10):
def run_all(pairing_group, policy_size, policy_str, attr_list, puncturable_attr_dict, rw_policy_string, rw_attr_list, k1, k2, k3, msg, privacy_level, epsilon_str):
    algos = ['#attributes', 'privacy level', 'Setup (ms)', 'KeyGen (ms)', 'Hide (ms)', 'Enc (ms)', 'Puncture (ms)', 'Dec (ms)', 'Ciphertext (bytes)']

    n1, n2, m, i = get_par(pairing_group, policy_str, attr_list)

    print('Running times (msp) curve', curve_type, ': n1={}  n2={}  m={}  I={}'.format(n1, n2, m, i))
    algo_string = 'CP-ABE {:<13}'.format('') + '  ' + algos[0] + '      ' + algos[1] + '     ' + algos[2] + '    ' + algos[3] + '     ' + \
                  algos[4] + '      ' + algos[5] + '      ' + algos[6] + '      ' + algos[7]
    print('-' * 160)
    print(algo_string)
    print('-' * 160)
    #
    #
    p_macp_abe24 = P_MACP_ABE(pairing_group)
    p_macp_abe_times = measure_average_times(p_macp_abe24, attr_list, policy_str, puncturable_attr_dict, k1, k2, k3, msg, privacy_level, epsilon_str)

    # return [time_setup_kyxj, time_keygen_kyxj, time_enc_kyxj, time_dec_kyxj,
    #         time_reg_user_kyxj, time_AA_setup_kyxj, time_setup_pmacpabe, time_keygen_pmacpabe, time_enc_pmacpabe,
    #         time_hide_pmacpabe, time_dec_srmacpabe, time_reg_user_pmacpabe, time_AA_setup_pmacpabe,
    #         time_transform, time_puncture_1, time_puncture_2, time_puncture_3, time_puncture_4, time_single_puncture,
    #         time_batch_puncture, time_keygen_1, time_keygen_2, time_keygen_3, time_keygen_4, time_setup_rw,
    #         time_keygen_rw, time_enc_rw, time_dec_rw, time_reg_user_rw, time_AA_setup_rw, avg_size_cph_kyxj,
    #         avg_size_cph_pcmacpabe, avg_size_cph_rw, avg_accumulator_single_puncture, avg_accumulator_batch_puncture]

    print_running_time(p_macp_abe24.name, p_macp_abe_times, len(attr_list), privacy_level)
    #
    print(f""
          f"1- setup: {p_macp_abe_times[6]}\n"
          f"2- keygen: {p_macp_abe_times[7]}\n"
          f"3- encryption: {p_macp_abe_times[8]}\n")

    print('{:<26}'.format('   | setup') + str(len(attr_list)).format(' ') + '{:<15}'.format(' ') +
          str(privacy_level).format(' ') + 11*' ' + format(p_macp_abe_times[6] * 1000, '7.2f') + 12*' ' + '-' + 14*' '
          + '-' + format(' ') + 3*' ' + format('  ') + 8*' ' + '-' + format(' ') + 16*' ' + '-' +
          format(' ') + 16*' ' + '-')
    #
    print('{:<26}'.format('   | hide') + str(len(attr_list)).format(' ') + '{:<11}'.format(' ') + 14 * ' ' +
          format(p_macp_abe_times[9] * 1000, '7.2f') + '-' + 14 * ' ' + '-' + format(' ') + 3 * ' ' +
          format('  ') + 8 * ' ' + '-' + format(' ') + 13 * ' ' + '-' + format(' ') + 16 * ' ' + '-'
          + format(' ') + 16 * ' ' + '-')
    #
    print('{:<26}'.format('   | keygen 1') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(p_macp_abe_times[20] * 1000, '7.2f') + '             -' + format(' ') + '  ' + format(
        '  ') + '        -' + format(
        ' ') + '                   -')
    #
    print('{:<26}'.format('   | keygen 2') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(p_macp_abe_times[21] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | keygen 3') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(p_macp_abe_times[22] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | keygen 4') + str(len(attr_list)).format(' ') + '{:<9}'.format('') + '      -        ' +
          format(p_macp_abe_times[23] * 1000, '7.2f') + '             -' + format('  ') + '  ' + format(
        '  ') + '       -' + format(
        ' ') + '                   -')
    print('{:<26}'.format('   | encrypt ') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + ' ' + '{:<6}'.format('') + '      -       ' +
          format(p_macp_abe_times[9] * 1000, '7.2f') + '             -' + format(' ') + '                   -')

    print('{:<26}'.format('   | transform') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' +
          format(p_macp_abe_times[15] * 1000, '7.2f') + '                    -')

    print('{:<26}'.format('   | decrypt') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' +
          format(p_macp_abe_times[11] * 1000, '7.2f') + '                    -')

    print('{:<26}'.format('   | cph_size (bytes)') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' + '      -               ' +
          format(p_macp_abe_times[31], '5.1f'))

    print('{:<26}'.format('   | mkl_size (bytes)') + str(len(attr_list)).format(' ') + '               -' + format(
        ' ') + '  ' + '{:<6}'.format('') + '     -' + '             -       ' + '      -               ' +
          format(p_macp_abe_times[33], '5.1f'))
    #

    output_data_pmacpabe['Scheme'].append(p_macp_abe24.name)
    output_data_pmacpabe['#attributes'].append(len(attr_list))
    output_data_pmacpabe['anonymity level'].append(1)
    output_data_pmacpabe['Setup (ms)'].append(p_macp_abe_times[6]*1000)
    output_data_pmacpabe['HideAttr (ms)'].append(p_macp_abe_times[7] * 1000)
    output_data_pmacpabe['Keygen (ms)'].append(p_macp_abe_times[8]*1000)
    output_data_pmacpabe['Encrypt (ms)'].append(p_macp_abe_times[9]*1000)
    output_data_pmacpabe['Single puncture (ms)'].append(p_macp_abe_times[9] * 1000)
    output_data_pmacpabe['Batch puncture (ms)'].append(p_macp_abe_times[9] * 1000)
    output_data_pmacpabe['Transform (ms)'].append(p_macp_abe_times[15]*1000)
    output_data_pmacpabe['Decrypt (ms)'].append(p_macp_abe_times[11]*1000)
    output_data_pmacpabe['Ciphertext size (bytes)'].append(p_macp_abe_times[31])
    #output_data_pmacpabe['URevocation (ms)'].append(p_macp_abe_times[10]*1000)
    # output_data_pmacpabe['ARevocation (ms)'].append(p_macp_abe_times[14]*1000)
    output_data_pmacpabe['URegistration (ms)'].append(p_macp_abe_times[12]*1000)
    output_data_pmacpabe['AASetup (ms)'].append(p_macp_abe_times[13]*1000)
    output_data_pmacpabe['Accumulator size (bytes)'].append(p_macp_abe_times[33])


    #
    p_macp_abe_cph_data['Scheme'].append(p_macp_abe24.name)
    p_macp_abe_cph_data['#attributes'].append(len(attr_list))
    p_macp_abe_cph_data['K level'].append(0)
    p_macp_abe_cph_data['Keygen1 (ms)'].append(p_macp_abe_times[20]*1000)
    p_macp_abe_cph_data['Keygen2 (ms)'].append(p_macp_abe_times[21]*1000)
    p_macp_abe_cph_data['Keygen3 (ms)'].append(p_macp_abe_times[22]*1000)
    p_macp_abe_cph_data['Keygen4 (ms)'].append(p_macp_abe_times[23]*1000)
    p_macp_abe_cph_data['Encrypt (ms)'].append(p_macp_abe_times[9]*1000)
    p_macp_abe_cph_data['Puncture1 (ms)'].append(p_macp_abe_times[9] * 1000)
    p_macp_abe_cph_data['Puncture2 (ms)'].append(p_macp_abe_times[9] * 1000)
    p_macp_abe_cph_data['Puncture3 (ms)'].append(p_macp_abe_times[9] * 1000)
    p_macp_abe_cph_data['Transform (ms)'].append(p_macp_abe_times[15]*1000)
    p_macp_abe_cph_data['Decrypt (ms)'].append(p_macp_abe_times[11]*1000)
    p_macp_abe_cph_data['Ciphertext size (bytes)'].append(p_macp_abe_times[31])
    p_macp_abe_cph_data['Uregistration (ms)'].append(p_macp_abe_times[12]*1000)
    p_macp_abe_cph_data['AASetup (ms)'].append(p_macp_abe_times[13]*1000)
    p_macp_abe_cph_data['ACC size (bytes)'].append(p_macp_abe_times[31])

    #
    #
    # return [time_setup_kyxj, time_keygen_kyxj, time_enc_kyxj, time_revoke_user_kyxj, time_dec_kyxj,
    #         time_reg_user_kyxj, time_AA_setup_kyxj, time_setup_srmacpabe, time_keygen_srmacpabe, time_enc_srmacpabe,
    #         time_revoke_user_srmacpabe, time_dec_srmacpabe, time_reg_user_srmacpabe, time_AA_setup_srmacpabe,
    #         time_revoke_attribute_srmacpabe, time_transform, time_revoke_1, time_revoke_2, time_revoke_3, time_revoke_4,
    #         time_keygen_1, time_keygen_2, time_keygen_3, time_keygen_4, avg_size_cph_kyxj, avg_size_cph_srcmacpabe]

    maabe_yj14_cp = MAABE(pairing_group)
    maabe_yj14_cp_times = measure_average_times(maabe_yj14_cp, attr_list, policy_str, puncturable_attr_dict, k1, k2, k3, msg, privacy_level, epsilon_str)
    print_running_time(maabe_yj14_cp.name, maabe_yj14_cp_times, len(attr_list), privacy_level)
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
    maabe_rw15_cp_times = measure_average_times(maabe_rw15_cp, rw_attr_list, rw_policy_string, puncturable_attr_dict, k1, k2, k3, msg, privacy_level, epsilon_str)
    print_running_time(maabe_rw15_cp.name, maabe_rw15_cp_times, len(rw_attr_list), privacy_level)
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
    # we process the hidden access policy
    p_macpabe_instance = P_MACP_ABE(pairing_group)


    #we process the policy for Rouselakis-Waters
    rw_policy_string = '(1@AA1'
    rw_attr_list = ['1@AA1']

    # we deal with the lis of attributes for the puncturable scheme
    puncturable_attr_dict = {}
    # {'1': {'1': '1$1'}}
    puncturable_attr_dict['1'] = f'1$1'

    AA_list = ['AA1', 'AA2', 'AA3']


    for i in range(2, n + 1):
        policy_string += ' and ' + str(i)  # {i}'
        attr1 = str(i)  # f'{i}'
        attr_list.append(attr1)
        #
        attr1 = str(i) + '@' + random.choice(AA_list)
        attr2 = str(i) + '$' + str(i)
        rw_attr_list.append(attr1)
        rw_policy_string += ' and ' + attr1
        #
        # puncturable_attr_dict[f'{str(i)}']={f'{str(i)}':f'{attr2}'}
        puncturable_attr_dict[f"{str(i)}"] = f"{attr2}"

    policy_string += ')'
    # hidden_policy_string += ')'
    rw_policy_string += ')'

    # attr_list = ['ONE', 'TWO', 'FOUR']

    # rw_policy_string, rw_attr_list
    return policy_string, attr_list, rw_policy_string, rw_attr_list, puncturable_attr_dict


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

    # the privacy level (k-anonymity for our scheme
    privacy_levels = [20, 40, 60, 80, 100, 120, 140, 160, 180, 200 ]

    # the string used to hide attributes, which is chosen by DO
    epsilon_str = 'epsilon'

    # policy_size = 1
    #
    # policy_str, attr_list, hidden_policy = create_policy_string_and_attribute_list(policy_size, pairing_group)
    # run_all(pairing_group, policy_size, policy_str, attr_list, hidden_policy, msg)

    for policy_size in policy_sizes:
    # we do pair the first policy size with the first privacy level, the second with the second, etc.,
    # we assume that the number of real tags in batch puncturing is the same as the policy size
    # for policy_size, privacy_level in zip(policy_sizes, privacy_levels):
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)
        policy_str, attr_list, rw_policy_string, rw_attr_list, puncturable_attr_dict = create_policy_string_and_attribute_list(policy_size, pairing_group)
        privacy_level = 2* policy_size
        #
        print(f" the list of attributes for puncture is {puncturable_attr_dict}")
        print(f" the list of attributes for other schemes is {attr_list}")
        print(f" the policy for other schemes is {policy_str}")

        list_length = int(len(attr_list) // 3)
        attr_list_1 = attr_list[0:list_length]
        attr_list_2 = attr_list[list_length:(2 * list_length)]
        attr_list_3 = attr_list[(2 * list_length):len(attr_list)]
    #
        print(f"attr_list_1: {attr_list_1} \n")
        print(f"attr_list_2: {attr_list_2} \n")
        print(f"attr_list_3: {attr_list_3} \n")

        # instance
        p_mmacp_abe_instance = P_MACP_ABE(pairing_group)
        # setup time
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)
        gc.collect()
        #
        if debug:
            print("we start setup \n\n")
        #
        sum_setup_pmacpabe = 0
        start_setup = time.perf_counter()
        (prv_DO, pub_DO, pk, msk) = p_mmacp_abe_instance.setup_()
        end_setup = time.perf_counter()
        time_setup = end_setup - start_setup
        sum_setup_pmacpabe += time_setup


        # Register a single user
        # such user stands as the target user
        sum_reg_user_pmacpabe = 0
        start_reg =time.perf_counter()
        # alice = abe.regUser('alice', attr_list, privacy_level)
        # FIX: regUser needs dict, not list
        alice = p_mmacp_abe_instance.regUser('alice', puncturable_attr_dict, privacy_level)

        end_reg =time.perf_counter()
        time_setup_1 = end_reg - start_reg
        # sum_setup_srmacpabe += time_setup_1
        sum_reg_user_pmacpabe += time_setup_1



        # Register AAs (three AAs)
        sum_reg_aa_pmacpabe = 0
        start_setup_2 =time.perf_counter()
        #
        AA1_ID = 1
        AA1_name = "AA_1"
        p_mmacp_abe_instance.setupAA(AA1_ID, AA1_name, attr_list_1)
        #
        AA2_ID = 2
        AA2_name = "AA_2"
        p_mmacp_abe_instance.setupAA(AA2_ID, AA2_name, attr_list_2)
        #
        AA3_ID = 3
        AA3_name = "AA_3"
        p_mmacp_abe_instance.setupAA(AA3_ID, AA3_name, attr_list_3)
        #
        end_setup_2 =time.perf_counter()
        time_setup_2 = end_setup_2 - start_setup_2
        # sum_setup_srmacpabe += time_setup_2
        sum_reg_aa_pmacpabe += time_setup_2


        # DO Keygen1
        sum_keygen_pmacpabe = 0
        start_keygen_1 = time.perf_counter()
        alice['DO_key'] = p_mmacp_abe_instance.keygen1(msk, alice['gid'], prv_DO, epsilon_str)
        end_keygen_1 =time.perf_counter()
        time_keygen = end_keygen_1 - start_keygen_1
        sum_keygen_pmacpabe += time_keygen
        # sum_keygen_1 += time_keygen


        # DU hide timing
        # DU hide timing
        sum_hide_attr = 0
        start_hide = time.perf_counter()
        #
        # we need to create subdirectories relative to the use of attributes list per AA
        items = list(puncturable_attr_dict.items())
        list_length = len(items) // 3
        attr_dict_1 = dict(items[0:list_length])
        attr_dict_2 = dict(items[list_length:(2 * list_length)])
        attr_dict_3 = dict(items[(2 * list_length):])
        #
        attr_dict_1_hidden = p_mmacp_abe_instance.hide_attr(alice['gid'], alice['DO_key'], attr_dict_1)
        attr_dict_2_hidden = p_mmacp_abe_instance.hide_attr(alice['gid'], alice['DO_key'], attr_dict_2)
        attr_dict_3_hidden = p_mmacp_abe_instance.hide_attr(alice['gid'], alice['DO_key'], attr_dict_3)
            #
        end_hide = time.perf_counter()
        time_hide = end_hide - start_hide
        sum_hide_attr += time_hide

        # mid printing
        print(f" sum_setup_pmacpabe ->{sum_setup_pmacpabe}")
        print(f"sum_keygen_pmacpabe ->{sum_keygen_pmacpabe}")
        print(f"sum_hide_attr -> {sum_hide_attr}")

           #  # AA keygen2
           #  start_keygen_2 =time.perf_counter()
           #  #
           #  # hash_gid = abe.crs['group'].hash(str(alice['gid']), ZR)
           #
           #  aa_key_1 = abe.keygen2(AA_ID=1, gid=alice['gid'], S_DU=attr_dict_1_hidden ) #alice['attributes'])
           #  print(f"the list of AA1 attributes is {attr_dict_1_hidden}")
           #  aa_key_2 = abe.keygen2(AA_ID=2, gid=alice['gid'], S_DU=attr_dict_2_hidden) #alice['attributes'])
           #  aa_key_3 = abe.keygen2(AA_ID=3, gid=alice['gid'], S_DU=attr_dict_3_hidden) #alice['attributes'])
           #  #
           #  end_keygen_2 =time.perf_counter()
           #  time_keygen = end_keygen_2 - start_keygen_2
           #  sum_keygen_pmacpabe += time_keygen
           #  sum_keygen_2 += time_keygen
           #
           #
           #  # TEE-CS Keygen3
           #  start_keygen_3 =time.perf_counter()
           #  #
           #  alice['TK_DU'] = abe.keygen3([aa_key_1, aa_key_2, aa_key_3], alice['gid'])
           #  #
           #  end_keygen_3 =time.perf_counter()
           #  time_keygen = end_keygen_3 - start_keygen_3
           #  sum_keygen_pmacpabe += time_keygen
           #  sum_keygen_3 += time_keygen
           #
           #
           #  # DU keygen4 time
           #  start_keygen_4 =time.perf_counter()
           #  alice['DU_key'], alice['DU_hkey'] = abe.keygen4(alice['DO_key'], alice['TK_DU'])
           #  end_keygen_4 =time.perf_counter()
           #  time_keygen = end_keygen_4 - start_keygen_4
           #  sum_keygen_pmacpabe += time_keygen
           #  sum_keygen_4 += time_keygen
           #
           #  #-----------------------------------------------------------------------------------
           #  # we can only form the hidden policy from inside this code section
           #  # -----------------------------------------------------------------------------------
           #  raw_attr_1 = abe.hide_by_DO(msk, attribute_value=attr_list[0], epsilon=epsilon_str)
           #  hidden_attr_1 = abe.crs['group'].serialize(raw_attr_1, compression=False).hex().upper()
           #
           #  #
           #  hidden_policy_str = f'({hidden_attr_1}'
           # #
           #  for att in attr_list[1:]:
           #      raw_attr = abe.hide_by_DO(msk, attribute_value=att, epsilon=epsilon_str)
           #      hidden_attr = abe.crs['group'].serialize(raw_attr, compression=False).hex().upper()
           #      hidden_policy_str += f' and {hidden_attr}'
           #  hidden_policy_str += ')'
           #
           #
           #  # DO encryption
           #  start_enc_1 =time.perf_counter()
           #  #
           #  ctxt = abe.encrypt(pk, msk, msg, policy_str, prv_DO, epsilon_str, hidden_policy_str)
           #
           #  # we get a copy of ctxt for decryption purposes since the puncturing will prevent normal decryption
           #  # ctxt_copy = ctxt
           #  #
           #  end_enc_1 =time.perf_counter()
           #  time_enc = end_enc_1 - start_enc_1
           #  sum_enc_pmacpabe += time_enc
           #
           #
           #  # size of ciphertext
           #  size_cph += len(abe.crs['group'].serialize(ctxt['C_tilde'], compression=False)) + len(
           #      abe.crs['group'].serialize(ctxt['C'], compression=False)) + len(
           #      abe.crs['group'].serialize(ctxt['W'], compression=False)) + len(
           #      abe.crs['group'].serialize(ctxt['sig_W'], compression=False)) + len(
           #      str.encode(ctxt['policy'], encoding='utf-8')) + len(
           #      abe.crs['group'].serialize(ctxt['ACC'].ACC_value, compression=False)) + len(
           #      abe.crs['group'].serialize(ctxt['ACC'].acc_len, compression=False))
           #  #
           #  for value in ctxt['C_y'].values():
           #      # size_cph += len(abe.crs['group'].serialize(value, compression=False))
           #      # C_y values are ints
           #      size_cph += len(str(value).encode('utf-8'))
           #  #
           #  for value in ctxt['T_y'].values():
           #      size_cph += len(abe.crs['group'].serialize(value, compression=False))
           #  #
           #  for value in ctxt['C_attr'].values():
           #      # size_cph += len(abe.crs['group'].serialize(value, compression=False))
           #      size_cph += len(value)  # , compression=False))
           #  #
           #  for value in ctxt['attributes']:
           #      size_cph += len(str.encode(value, encoding='utf-8'))
           #  #
           #  # for value in ctxt['ACC'].tag_list:
           #  #     size_cph += len(str.encode(value, encoding='utf-8'))
           #  #
           #
           #  # before puncturing we need to safegard the values of DU_jkey and DU_hkey as our implementation applies both sequentially
           #  # but this can also be tolerated by our seamless design
           #  DU_key_bak = alice['DU_key']
           #  DU_hkey_bak = alice['DU_hkey']
           #
           #  # ---------------------------------------------------------------------------------------------------
           #  # **************************user single puncturing ******************************
           #  # ---------------------------------------------------------------------------------------------------
           #  start_DU_puncture = time.perf_counter()
           #  tag_to_puncture = uuid.uuid4() # we generate a legit tag
           #  #
           #  alice['DU_key'], alice['DU_hkey'], T_prime, desc_T_prime = abe.DU_single_puncture(
           #          alice['DU_key'], alice['DU_hkey'], tag_to_puncture, alice['gid'], alice['k_anonymity'])
           #  end_DU_puncture=time.perf_counter()
           #  time_puncture1 = end_DU_puncture - start_DU_puncture
           #  sum_puncture_1 += time_puncture1
           #  sum_single_puncture +=  time_puncture1
           #
           #  # then the cloud performs the puncture to support the user  single puncture
           #  start_CSPpuncture = time.perf_counter()
           #  alice['DU_hkey'], ctxt['sig_ACC'] = abe.csp_puncture(ctxt, alice['DU_hkey'], T_prime, desc_T_prime, alice['gid'])
           #  end_CSP_puncture = time.perf_counter()
           #  time_puncture2 = end_CSP_puncture - start_CSPpuncture
           #  sum_puncture_2 += time_puncture2
           #  sum_single_puncture += time_puncture2
           #
           #  # we need to update the size of the ciphertext here
           #  size_cph += len(abe.crs['group'].serialize(ctxt['sig_ACC'], compression=False))
           #  #
           #  for value in ctxt['ACC'].tag_list:
           #      size_cph += len(str.encode(value, encoding='utf-8'))
           #  #-------------------------------------------------------------------------------------------------------
           #
           #  # we need to update the size of the accumulator for single puncture here
           #  if ctxt['ACC'].ACC_value is not None:
           #      size_accumulator_single_puncture += len(abe.crs['group'].serialize(ctxt['ACC'].ACC_value, compression=False))
           #  #
           #  for value in ctxt['ACC'].tag_list:
           #      size_accumulator_single_puncture += len(str.encode(value, encoding='utf-8'))
           #
           #  # ---------------------------------------------------------------------------------------------------
           #  # **************************user batch puncturing ******************************
           #  # ---------------------------------------------------------------------------------------------------
           #  start_DU_puncture = time.perf_counter()
           #  #
           #  # use the original  secret and helper keys
           #  alice['DU_key'] = DU_key_bak
           #  alice['DU_hkey'] = DU_hkey_bak
           #
           #  # k-anonymity should be greater than the number of attributes
           #  tag_to_puncture_list = [str(uuid.uuid4()) for _ in range(len(attr_list))] # uuid.uuid4() # we generate a legit tag
           #  #
           #  alice['DU_key'], alice['DU_hkey'], T_prime, desc_T_prime = abe.DU_batch_puncture(alice['DU_key'], alice['DU_hkey'], tag_to_puncture_list, alice['gid'], alice['k_anonymity'])
           #  end_DU_puncture=time.perf_counter()
           #  time_puncture3 = end_DU_puncture - start_DU_puncture
           #  sum_puncture_3 += time_puncture3
           #  sum_batch_puncture += time_puncture3
           #
           #  # then the cloud performs the puncture to support the user  batch puncture
           #  start_CSPpuncture = time.perf_counter()
           #  alice['DU_hkey'], ctxt['sig_ACC'] = abe.csp_puncture(ctxt, alice['DU_hkey'], T_prime, desc_T_prime, alice['gid'])
           #  end_CSP_puncture = time.perf_counter()
           #  time_puncture4 = end_CSP_puncture - start_CSPpuncture
           #  sum_puncture_4 += time_puncture4
           #  sum_batch_puncture += time_puncture4
           #
           #  # we need to update the size of the ciphertext here
           #  for value in ctxt['ACC'].tag_list:
           #      size_cph += len(str.encode(value, encoding='utf-8'))
           #
           #  # we need to update the size of the accumulator for batch puncture here
           #  size_cph += len(abe.crs['group'].serialize(ctxt['sig_ACC'], compression=False))
           #  #
           #  size_accumulator_batch_puncture += len(
           #      abe.crs['group'].serialize(ctxt['ACC'].ACC_value, compression=False)) + len(
           #      abe.crs['group'].serialize(ctxt['ACC'].acc_len, compression=False))
           #  #
           #  for value in ctxt['ACC'].tag_list:
           #      size_accumulator_batch_puncture += len(str.encode(value, encoding='utf-8'))
           #  # -------------------------------------------------------------------------------------------------------
           #
           #  # TEE-CS ciphertext transformation
           #  # outsourced decryption by the cloud
           #  start_transform =time.perf_counter()
           #  TC, I = abe.transform(ctxt, alice['DU_hkey'], alice['gid'])
           #  end_transform =time.perf_counter()
           #  time_transform = end_transform - start_transform
           #  sum_transform += time_transform
           #
           #  # Final decryption stage by Data User
           #  start_decrypt =time.perf_counter()
           #  M2 = abe.decrypt(ctxt, TC, I, alice['DU_key'], pub_DO)
           #  end_decrypt =time.perf_counter()
           #  time_decrypt = end_decrypt - start_decrypt
           #  sum_decrypt_pmacpabe += time_decrypt
           #
           #  # sanity check
           #  assert msg == M2, "FAILED Decryption: message is incorrect"

        # setup time
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)
        gc.collect()
    #
        run_all(pairing_group, policy_size, policy_str, attr_list, puncturable_attr_dict, rw_policy_string, rw_attr_list, k1, k2, k3, msg, privacy_level, epsilon_str)
        gc.collect(0)
        gc.collect(1)
        gc.collect(2)

    # we write data to files
    # df1 = pd.DataFrame(output_data_pmacpabe)
    # df2 = pd.DataFrame(output_data_kyxj)
    # df3 = pd.DataFrame(p_macp_abe_cph_data)
    # df4 = pd.DataFrame(output_data_rw15)
    #
    # df1.to_csv('output_data_pmacpabe.csv')
    # df2.to_csv('output_data_kyxj.csv')
    # df4.to_csv('output_data_rw15.csv')
    # df3.to_csv('p_macp_abe_cph_data.csv')


if __name__ == "__main__":
    debug = True
    # # Open the log file
    # log_file = open("measurements.log", "w")
    #
    # # Duplicate the file descriptors so stdout/stderr write to the file
    # os.dup2(log_file.fileno(), sys.stdout.fileno())
    # os.dup2(log_file.fileno(), sys.stderr.fileno())
    #
    # # Optional: keep a reference so Python doesn't close it prematurely
    # sys.stdout.log_file = log_file
    #
    main()
