"""
Arthur Sandor Voundi Koe, Wei Jian Hong, Chen Xiao Feng

| From: "Large Tag Puncturable Attribute-BAsed ENcryption for CLoud-IoT".
| Published in: 2025
| Available from:
| Notes:
| Security Assumption:
|
| type: multi-authority ciphertext-policy attribute-based encryption (public key)
| setting: Pairing

:Authors: Arthur SAndor Voundi Koe
:Date: 05/2026
"""

import hashlib
import math
import pickle
import re
import secrets
import string
import uuid

from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.policytree import PolicyParser
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output

import merkletools
from typing import List

from collections import defaultdict

from fontTools.misc.bezierTools import epsilon

from PolicyParser_Modified import PolicyParserModified
from accumulator import accumulator

debug = True

# type annotations
crs_t = {'g1': G1, 'g2': G2, 'e_gg': GT}

# type annotations
pp_t = {'h': G1, 'f': G1, 'e_gg_alpha': GT}
msk_t = {'beta': ZR, 'g_alpha': G2}
#

"""
 Puncturable MAABE Main Class
"""


class P_MACP_ABE(ABEnc):

    def __init__(self, group_obj):
        ABEnc.__init__(self)
        self.name = "P_MACP_ABE"
        util = SecretUtil(group_obj, verbose=True)
        group = group_obj

        g1 = group.random(G1)
        g2 = group.random(G2)
        #
        g1.initPP()
        g2.initPP()
        #
        e_gg = pair(g1, g2)

        self.crs = {'g1': g1, 'g2': g2, 'e_gg': e_gg, 'group': group, 'util': util}

        # the accumulator data structure
        self.accumulator = None

        # the string used to blind attributes
        self.epsilon = None

        # the set of attribute authorities
        self.authorities = {}

        # the set of users
        self.users = {}

        # the shared secret ( which is not very important only for troubleshooting purposes)
        self.shared_secret = None

        # the random exponent for a user ( which is not very important only for troubleshooting purposes)
        self.random_user_exponent = None

        # the transformed ciphertext
        self.TC = None

        #-------------------------------------------------
        # Generate CSP attestation key pair (BLS-style)
        #
        # the secret attestation key from the transparent TEE
        self.secret_attestation_key = self.crs['group'].random(ZR)
        #
        # the public attestation key from the transparent TEE
        self.public_attestation_key = self.crs['g2'] ** self.secret_attestation_key
    # --------------------------------------------------------------------------------------------------------

    def regUser(self, gid: str, attributes: list, anonymity_level: int):
        """Generate user keys (executed by the user)."""
        a2 = self.crs['group'].random(ZR)
        b2 = self.crs['group'].random(ZR)
        prv_DU = a2 * b2
        pub_DU = self.crs['g2'] ** prv_DU
        DU_key = {}
        DU_hkey = []

        self.users[gid] = {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey, 'k_anonymity': anonymity_level
        }
        return {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey, 'k_anonymity': anonymity_level
        }

    #

    def setupAA(self, authorityid, authority_name, attributes: list):
        """Generate attribute authority keys (executed by attribute authority)"""
        if authorityid not in self.authorities.keys():
            a1 = self.crs['group'].random(ZR)
            b1 = self.crs['group'].random(ZR)
            prv_AA = a1 * b1
            pub_AA = self.crs['g2'] ** prv_AA

            self.authorities[authorityid] = {
                'name': authority_name, 'pub_AA': pub_AA, 'prv_AA': prv_AA,
                'attributes': attributes
            }
        return self.authorities[authorityid]


    def setup(self):
        a0 = self.crs['group'].random(ZR)
        b0 = self.crs['group'].random(ZR)
        prv_DO = a0 * b0
        pub_DO = self.crs['g2'] ** prv_DO

        beta = self.crs['group'].random(ZR)
        h = self.crs['g1'] ** beta

        alpha = self.crs['group'].random(ZR)
        g_alpha = self.crs['g2'] ** alpha
        e_gg_alpha = self.crs['e_gg'] ** alpha

        pp = {'h': h, 'e_gg_alpha': e_gg_alpha}
        msk = {'beta': beta, 'g_alpha': g_alpha}
        return prv_DO, pub_DO, pp, msk

    def keygen(self, pp, msk, gid):
        pass


    def keygen1(self, msk, gid, prv_DO, epsilon: str):
        gamma = self.crs['group'].hash(str(gid), ZR)
        r = self.crs['group'].random(ZR)
        self.random_user_exponent = r

        sk_DO = (msk['g_alpha'] ** (1 / msk['beta'])) * (self.users[gid]['pub_DU'] ** (1 / (msk['beta']))) * (
            self.crs['g2'] ** (r * (1 / (msk['beta']))))

        hk_DO_1 = (self.crs['g2'] ** gamma) * (self.crs['g2'] ** r) * (self.users[gid]['pub_DU'])
        hk_DO_2 = self.crs['g2'] ** (self.crs['group'].hash(str(epsilon), ZR) * gamma * (1 / msk['beta']))
        hk_DO_3 = self.crs['g2'] ** (gamma * (1 / msk['beta']))

        T = set()
        desc_T = defaultdict(dict)
        sigma_T = self.crs['g2'] ** (self.crs['group'].hash(str(T.__str__()), ZR) * prv_DO)

        DO_key = {'sk': sk_DO, 'hk_1': hk_DO_1, 'hk_2': hk_DO_2, 'hk_3': hk_DO_3, 'T': T, 'sigma_T': sigma_T,
                  'desc_T': desc_T}
        return DO_key


    def hide_attr(self, gid, DO_key, S_DU: dict) -> {}:
        S_DU_hidden = {}
        gamma = self.crs['group'].hash(str(gid), ZR)
        for att_name in S_DU.keys():
            hidden_att_value = (self.crs['g2'] ** (
                self.crs['group'].hash(S_DU.get(att_name).split("$", 1)[1], ZR) * gamma)) * DO_key[
                'hk_2']
            S_DU_hidden[att_name] = (att_name, hidden_att_value)
        return S_DU_hidden


    def hide_by_DO(self, msk, attribute_value: str, epsilon: str):
        return (self.crs['g1'] ** (self.crs['group'].hash(str(attribute_value), ZR))) * (
            self.crs['g1'] ** ((self.crs['group'].hash(str(epsilon), ZR)) * (1 / (msk['beta']))))

    def keygen2(self, AA_ID, gid, S_DU: dict):
        gamma_du = self.crs['group'].hash(str(gid), ZR)
        AA_key = {}

        if AA_ID in self.authorities.keys():
            AA = self.authorities[AA_ID]
            prv_AA = AA['prv_AA']
            pub_AA = AA['pub_AA']
        else:
            raise Exception("AA_ID does not exist !")

        for att_name in list(S_DU.keys()):
            if att_name not in AA['attributes']:
                print(f"{att_name} not in {AA['attributes']} of AA {AA_ID}")
                continue
            # print(f"we focus on attribute {att_name} of value {S_DU.get(att_name)[1]}")
            attr_value = S_DU.get(att_name)[1]
            r_j = self.crs['group'].random(ZR)
            D_j = (attr_value ** (r_j / (prv_AA + gamma_du)))
            T_j = self.crs['g2'] ** (gamma_du * r_j / (prv_AA + gamma_du))
            AA_key[(att_name, attr_value)] = {'D_j': D_j, 'T_j': T_j, 'attr': att_name}
        return AA_key


    def keygen3(self, aa_key_list: list, gid):
        TK_DU = {}
        items = list()
        for aa_key in aa_key_list:
            for att_item in list(aa_key.keys()):
                att_name = att_item[0]
                att_value = att_item[1]
                index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))
                index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()
                TK_DU[index_value_hex] = aa_key[att_item]
                items.append(att_item)
                TK_DU['items'] = items

        # print(f" \n\n****************************this is the structure of TK_DU {TK_DU}\n\n")
        return TK_DU


    def keygen4(self, DO_key, TK_DU):
        DU_key = {'sk': DO_key['sk'], 'hk': TK_DU}
        DU_hkey = {'hk_1': DO_key['hk_1'], 'hk_2': DO_key['hk_2'], 'hk_3': DO_key['hk_3'], 'T': DO_key['T'],
                   'sigma_T': DO_key['sigma_T'], 'desc_T': DO_key['desc_T'], 'TK_DU': TK_DU,
                   'items': TK_DU['items']}
        return DU_key, DU_hkey


    def DU_single_puncture(self, DU_key, DU_hkey, tag_name: str, gid, anonym_level: int):
        T_prime = set()

        r_real_tag = self.crs['group'].random(ZR)
        real_tag_component = self.crs['g2'] ** (
                    r_real_tag * self.crs['group'].hash(str(tag_name), ZR) * self.crs['group'].hash(str(gid), ZR))

        T_prime.add(tag_name)
        desc_T_prime = defaultdict(dict)
        desc_T_prime[tag_name] = real_tag_component

        DU_hkey['T'].add(tag_name)
        DU_hkey['desc_T'][tag_name] = real_tag_component

        dummy_tag_dict = {}
        dummy_tag_generated_list = [str(uuid.uuid4()) for _ in range(anonym_level - 1)]
        dummy_tag_list_apply_hash_per_element = [self.crs['group'].hash(str(item), ZR) for item in
                                                 dummy_tag_generated_list]
        sum_dummy_tag_list_elements = sum(dummy_tag_list_apply_hash_per_element)

        for dummy_tag in dummy_tag_generated_list:
            dummy_tag_name = f'{dummy_tag}'
            r_dummy_tag = self.crs['group'].random(ZR)
            dummy_tag_component = self.crs['g2'] ** (
                        self.crs['group'].hash(str(dummy_tag_name), ZR) * r_dummy_tag * self.crs['group'].hash(
                    str(gid), ZR) / sum_dummy_tag_list_elements)

            dummy_tag_dict[dummy_tag_name] = r_dummy_tag
            T_prime.add(dummy_tag_name)
            desc_T_prime[dummy_tag_name] = dummy_tag_component
            DU_hkey['T'].add(dummy_tag_name)
            DU_hkey['desc_T'][dummy_tag_name] = dummy_tag_component

        for item in DU_hkey['TK_DU']['items']:
            att_name = item[0]
            att_value = item[1]
            index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))
            index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()
            update_term_Dj = self.crs['g2'] ** (self.crs['group'].init(ZR, 0))
            for dummy_tag in dummy_tag_dict.keys():
                r_dummy = dummy_tag_dict[dummy_tag]
                update_term_Dj = update_term_Dj * (att_value ** ((
                            self.crs['group'].hash(str(dummy_tag), ZR) * r_dummy * self.crs['group'].hash(str(gid),
                                                                                                        ZR)) / sum_dummy_tag_list_elements))
            DU_hkey['TK_DU'][index_value_hex]['D_j'] = DU_hkey['TK_DU'][index_value_hex]['D_j'] * update_term_Dj

        product_dummy_tag_list_elements = math.prod(dummy_tag_list_apply_hash_per_element)
        self.user_secret_product = product_dummy_tag_list_elements
        DU_key['sk'] = DU_key['sk'] ** (product_dummy_tag_list_elements)
        DU_hkey['hk_1'] = DU_hkey['hk_1'] ** (product_dummy_tag_list_elements)
        DU_hkey['hk_2'] = DU_hkey['hk_2'] ** (product_dummy_tag_list_elements)

        return DU_key, DU_hkey, T_prime, desc_T_prime


    def DU_batch_puncture(self, DU_key, DU_hkey, tag_name_list: set, gid: str, anonym_level: int):
        T_prime = set()
        desc_T_prime = defaultdict(dict)
        dummy_tag_dict = {}

        for real_tag_name in tag_name_list:
            real_tag_element = self.crs['group'].random(ZR)
            real_tag_component = self.crs['g2'] ** (
                        self.crs['group'].hash(str(real_tag_name), ZR) * real_tag_element * self.crs['group'].hash(
                    str(gid), ZR))
            T_prime.add(real_tag_name)
            desc_T_prime[real_tag_name] = real_tag_component
            DU_hkey['T'].add(real_tag_name)
            DU_hkey['desc_T'][real_tag_name] = real_tag_component

        dummy_tag_generated_list = [str(uuid.uuid4()) for _ in range(anonym_level - len(tag_name_list))]
        dummy_tag_list_apply_hash_per_element = [self.crs['group'].hash(str(item), ZR) for item in
                                                 dummy_tag_generated_list]
        sum_dummy_tag_list_elements = sum(dummy_tag_list_apply_hash_per_element)

        for dummy_tag in dummy_tag_generated_list:
            dummy_tag_name = f'{dummy_tag}'
            r_dummy_tag = self.crs['group'].random(ZR)
            dummy_tag_component = self.crs['g2'] ** (
                        self.crs['group'].hash(str(dummy_tag_name), ZR) * r_dummy_tag * self.crs['group'].hash(
                    str(gid), ZR) / sum_dummy_tag_list_elements)

            dummy_tag_dict[dummy_tag_name] = r_dummy_tag
            T_prime.add(dummy_tag_name)
            desc_T_prime[dummy_tag_name] = dummy_tag_component
            DU_hkey['T'].add(dummy_tag_name)
            DU_hkey['desc_T'][dummy_tag_name] = dummy_tag_component

        for item in DU_hkey['TK_DU']['items']:
            att_name = item[0]
            att_value = item[1]
            index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))
            index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()
            update_term_Dj = self.crs['g2'] ** (self.crs['group'].init(ZR, 0))
            for dummy_tag in dummy_tag_dict.keys():
                r_dummy = dummy_tag_dict[dummy_tag]
                update_term_Dj = update_term_Dj * (att_value ** ((
                            self.crs['group'].hash(str(dummy_tag), ZR) * r_dummy * self.crs['group'].hash(str(gid),
                                                                                                        ZR)) / sum_dummy_tag_list_elements))
            DU_hkey['TK_DU'][index_value_hex]['D_j'] = DU_hkey['TK_DU'][index_value_hex]['D_j'] * update_term_Dj

        product_dummy_tag_list_elements = math.prod(dummy_tag_list_apply_hash_per_element)
        self.user_secret_product = product_dummy_tag_list_elements
        DU_key['sk'] = DU_key['sk'] ** (product_dummy_tag_list_elements)
        DU_hkey['hk_1'] = DU_hkey['hk_1'] ** (product_dummy_tag_list_elements)
        DU_hkey['hk_2'] = DU_hkey['hk_2'] ** (product_dummy_tag_list_elements)

        return DU_key, DU_hkey, T_prime, desc_T_prime


    # ask for attestation secret key
    def csp_puncture(self, CT, DU_hkey, T_prime: set, desc_T_prime: defaultdict(dict), gid: str):
        update_term_Tj = self.crs['g2'] ** (self.crs['group'].init(ZR, 0))
        for tag in desc_T_prime.keys():
            tag_component = desc_T_prime[tag]
            update_term_Tj = update_term_Tj * tag_component

        for item in DU_hkey['TK_DU']['items']:
            att_name = item[0]
            att_value = item[1]
            index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))
            index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()
            DU_hkey['TK_DU'][index_value_hex]['T_j'] = DU_hkey['TK_DU'][index_value_hex]['T_j'] * update_term_Tj

        legit_tags = set()
        for tag_name in T_prime:
            if tag_name not in DU_hkey['T']:
                print(f"we ignore tag {tag_name}\n\n")
                continue
            legit_tags.add(tag_name)

        CT['ACC'].accumulate_tags(legit_tags)

        acc_value = CT['ACC'].acc_get_value()
        sig_ACC = self.crs['g2'] ** (self.crs['group'].hash(str(acc_value), ZR) * self.secret_attestation_key)

        return DU_hkey, sig_ACC

    def encrypt(self, pp, msk, M, policy_str, prv_DO, epsilon, hidden_policy):
        policy = self.crs['util'].createPolicy(hidden_policy)
        a_list = self.crs['util'].getAttributeList(policy)
        print(f" the list of attributes extracted from the policy is {a_list}")
        s = self.crs['group'].random(ZR)
        self.shared_secret = s

        shares = self.crs['util'].calculateSharesDict(s, policy)
        print(f" the shares dictionary is {shares}")
        C_tilde = (pp['e_gg_alpha'] ** s) * M
        C = pp['h'] ** s
        C_y, T_y, C_attr = {}, {}, {}

        W = self.crs['g2'] ** (self.crs['group'].hash(str(M), ZR))
        sig_W = self.crs['g2'] ** (self.crs['group'].hash(str(W), ZR) * prv_DO)

        for i in shares.keys():
            j = self.crs['util'].strip_index(i)
            attribute_value = j
            # print('********************WE check whether bytesfromHex from lower and upper case are the same ****************** \n')
            # print(f" the lower case representation is {attribute_value.lower()} \n")
            # print(f" bytes representation for the lower case is {bytes.fromhex(attribute_value.lower())} \n\n")
            # print(f" the upper case representation is {attribute_value.upper()} \n")
            # print(f" bytes representation for the upper case is {bytes.fromhex(attribute_value.upper())} \n\n")
            attr_byte_value = bytes.fromhex(attribute_value)
            element_attribute_value = self.crs['group'].deserialize(attr_byte_value, compression=False)
            C_y[i] = self.crs['g1'] ** shares[i]
            T_y[i] = element_attribute_value ** shares[i]
            C_attr[j] = i

        # we initialize the accumulator
        self.accumulator = accumulator(self.crs)
        self.accumulator.acc_init()

        CT = {
            'C_tilde': C_tilde,
            'C': C, 'C_y': C_y, 'T_y': T_y, 'C_attr': C_attr, 'policy': hidden_policy,
            'attributes': [item.split('$', 1)[0] for item in a_list], 'W': W,
            'sig_W': sig_W, 'ACC': self.accumulator
        }
        return CT

    def transform(self, CT, DU_hkey, gid):
        policy = self.crs['util'].createPolicy(CT['policy'])

        new_item_list = []
        for item in DU_hkey['items']:
            attr_name = item[0]
            attr_value = item[1]
            attr_value = attr_value ** (1 / self.crs['group'].hash(str(gid), ZR))
            hex_attribute_value = self.crs['group'].serialize(attr_value, compression=False).hex()
            new_item_list.append(f"{hex_attribute_value.upper()}")

        pruned_list = self.crs['util'].prune(policy, new_item_list)
        # print(f" the pruned list is {pruned_list}\n\n")

        if not pruned_list:
            print("Access policy unsatisfied ! \n")
            TC = None
            helper_decryption_term = None
            return TC, helper_decryption_term

        q = self.crs['util'].getCoefficients(policy)
        # print(f" the value of q is {q}\n\n")
        TC = 1

        count = 0
        for i in pruned_list:
            j = i.getAttributeAndIndex()
            # print(f" the full attribute and index value j in transform is {j} \n\n")
            k = i.getAttribute()
            # print(f"value of k in transform is {k}\n\n")
            # print(f"the value of DU_hkey['TK_DU'][k] is {DU_hkey['TK_DU'][k]}\n\n")
            TC *= ((pair((CT['C_y'][j]), (DU_hkey['hk_1'] * DU_hkey['TK_DU'][k]['D_j']))) / (pair(
                (CT['T_y'][j]), (DU_hkey.get('TK_DU')[k]['T_j'])))) ** q[j]
            # print(f"counter---> {count} \n\n")
            count += 1

        print(f" the computed value of TC is: {TC} \n")

        TC = (pair(self.crs['g1'], self.crs['g2']) ** (
            (self.random_user_exponent + self.crs['group'].hash(str(gid), ZR)) * self.shared_secret)) * (
                     (pair(self.crs['g1'], self.crs['g2'])) ** (self.users[gid]['prv_DU'] * self.shared_secret))

        self.TC = TC
        print(f" the value of self.TC is: {self.TC} \n")

        if DU_hkey['hk_3'] is None:
            raise "DU_hkey['hk_3'] is not defined ! contact the Data Owner !"
        else:
            I = pair(CT['C'], DU_hkey['hk_3'])
            return TC, I

    def Decrypt(self, CT, TC, I, DU_key, pub_DO):
        F = pair(CT['C'], DU_key['sk'])
        B = ((F * I) / TC)
        M_prime = CT['C_tilde'] / B

        W_prime = self.crs['g2'] ** (self.crs['group'].hash(str(M_prime), ZR))

        if pair(self.crs['g1'], CT['sig_W']) == pair(self.crs['g1'] ** self.crs['group'].hash(str(W_prime), ZR),
                                                     pub_DO):
            return M_prime
        else:
            return None
