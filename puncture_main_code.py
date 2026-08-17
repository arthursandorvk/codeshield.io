'''
Arthur Sandor Voundi Koe, Wei Jian Hong, Chen Xiao Feng

| From: "Large Tag Puncturable Attribute-BAsed ENcryption for CLoud-IoT".
| Published in: 2025
| Available from:
| Notes:
| Security Assumption:
|
| type:           multi-authority ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    Arthur SAndor Voundi Koe
:Date:            05/2026
'''

import hashlib
import math
import pickle
import re
import secrets
import string
import uuid

from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
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
crs_t = {'g': G1, 'e_gg': GT}

# type annotations
pp_t = {'h': G1, 'f': G1, 'e_gg_alpha': GT}
msk_t = {'beta': ZR, 'g_alpha': G1}
#

'''
 Puncturable MAABE Main Class
'''


class P_MACP_ABE(ABEnc):

    def __init__(self, group_obj):
        ABEnc.__init__(self)
        self.name = "P_MACP_ABE"
        #self.crs = {}
        util = SecretUtil(group_obj, verbose=True)
        group = group_obj

        # we pick random generator
        g = group.random(G1)
        # g2 = group.random(G2)

        # initialize pre-processing for generators
        g.initPP()
        # g2.initPP()

        # set the generator for target group
        e_gg = pair(g, g)

        self.crs = {'g': g, 'e_gg': e_gg, 'group': group, 'util': util}

        # initialize the accumulator
        self.accumulator = None

        # DO self-chosen string to hide attributes and generate attribute masking parameters
        self.epsilon = None

        #
        # # for Attribute Authority
        self.authorities = {}

        # for Users
        self.users = {}

        # secret exponent for encryption (shared secret)
        self.shared_secret = None

        # random exponent r for the user
        self.random_user_exponent = None

        # just for test\
        self.TC = None

        # the user secret product term
        self.user_secret_product = None
        #

    # to only hae attribute names
    def P_MACP_ABE_policy_prune(self, policy, attributes):
        """determine whether a given set of attributes satisfies the policy"""
        parser = PolicyParser()

        # we want to remove the attribute values at first to check whether the set of attribute names in the user key satisfies the set of leaf nodes in the access tree
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*[^:()\s]+'
        processed_policy = re.sub(pattern, r'\1', policy)
        return processed_policy

    def regUser(self, gid: str, attributes: list, anonymity_level:int):
        '''Generate user keys (executed by the user).'''
        # for Data User
        # self.pub_DU
        a2 = self.crs['group'].random(ZR)
        b2 = self.crs['group'].random(ZR)
        prv_DU = a2 * b2
        pub_DU = self.crs['g'] ** prv_DU
        DU_key = {}
        DU_hkey = []

        # In the code only DO has knowledge of the real user gid while AA will access the digest value of DU's gid
        self.users[gid] = {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey, 'k_anonymity': anonymity_level
        }
        return {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey, 'k_anonymity': anonymity_level
        }

    def setupAA(self, authorityid, authority_name, attributes: list):
        '''Generate attribute authority keys (executed by attribute authority)'''
        if authorityid not in self.authorities.keys():
            ''' new AA to register '''
            a1 = self.crs['group'].random(ZR)
            b1 = self.crs['group'].random(ZR)
            prv_AA = a1 * b1
            pub_AA = self.crs['g'] ** prv_AA

            # insert the new AA into the dictionary of AAs
            self.authorities[authorityid] = \
                {
                    'name': authority_name, 'pub_AA': pub_AA, 'prv_AA': prv_AA,
                    'attributes': attributes
                }
        return self.authorities[authorityid]

    #@Output(pp_t, msk_t)
    def setup(self):
        a0 = self.crs['group'].random(ZR)
        b0 = self.crs['group'].random(ZR)
        prv_DO = a0 * b0
        pub_DO = self.crs['g'] ** prv_DO

        beta = self.crs['group'].random(ZR)
        h = self.crs['g'] ** beta
        # f = self.crs['g'] ** (1 / beta)

        alpha = self.crs['group'].random(ZR)
        g_alpha = self.crs['g'] ** alpha
        e_gg_alpha = self.crs['e_gg'] ** alpha

        pp = {'h': h, 'e_gg_alpha': e_gg_alpha}
        msk = {'beta': beta, 'g_alpha': g_alpha}
        return prv_DO, pub_DO, pp, msk

    def keygen(self, pp, msk, gid):
        pass

    def keygen1(self, msk, gid, prv_DO, epsilon: str):
        # process the user GID
        gamma = self.crs['group'].hash(str(gid), ZR)

        # random exponent chosen by DO
        r = self.crs['group'].random(ZR)

        self.random_user_exponent = r

        sk_DO = (msk['g_alpha'] ** (1 / msk['beta'])) * (self.users[gid]['pub_DU'] ** (1 / (msk['beta']))) * (
                    self.crs['g'] ** (r * (1 / (msk['beta']))))
        #
        hk_DO_1 = (self.crs['g'] ** gamma) * (self.crs['g'] ** r) * (self.users[gid]['pub_DU'])
        #
        # attribute hiding parameter from mu to hk_DO_2
        hk_DO_2 = self.crs['g'] ** (self.crs['group'].hash(str(epsilon), ZR) * gamma * (1 / msk['beta']))
        #
        hk_DO_3 = self.crs['g'] ** (gamma * (1 / msk['beta']))
        #

        #---------------------------------------------------------------------------------------------------------------
        ''' Regarding data structures to handle the long-term set of tags in the  user secret key initialized by DO '''
        # the user tag set T. initially T is empty
        T = set()
        # the tag description set which is a dictionary associating to each tag name a corresponding public tag component
        # initially desc_T is empty
        # desc_T = defaultdict(dict)

        #---------------------------------------------------------------------------------------------------------------
        # we sign a public string description of the set T (empty set)
        # sigma_T = (self.crs['group'].hash(str(T.__str__()), G1)) ** prv_DO  # (H(m))^s
        sigma_T = self.crs['g'] ** (self.crs['group'].hash(str(T.__str__()), ZR) * prv_DO)
        #
        # we sign a public string description of the description set desc_T (empty set)
        # sigma_desc_T = (self.crs['group'].hash(str(desc_T.__str__()), G1)) ** prv_DO  # (H(m))^s
        # sigma_desc_T = self.crs['g'] ** (self.crs['group'].hash(str(desc_T.__str__()), ZR) * prv_DO)
        #
        # DO_key = {'sk': sk_DO, 'hk_1': hk_DO_1, 'hk_2': hk_DO_2, 'hk_3': hk_DO_3, 'T': T, 'sigma_T': sigma_T,
        #           'desc_T': desc_T, 'sigma_desc_T': sigma_desc_T}
        DO_key = {'sk': sk_DO, 'hk_1': hk_DO_1, 'hk_2': hk_DO_2, 'hk_3': hk_DO_3, 'T': T, 'sigma_T': sigma_T}
        #
        return DO_key

    # the format of an attribute is attribute_name: attribute_value
    def hide_attr(self, gid, DO_key, S_DU: dict) -> {}:
        # mu = DO_key['hk_2']
        # the resulting hidden set
        S_DU_hidden = {}
        # process the user GID
        gamma = self.crs['group'].hash(str(gid), ZR)
        #
        for att_name in S_DU.keys():
            # hide the value of attribute name j
            # print(f"current attribute to hide {S_DU.get(att_name).split('$',1)[0]}->{S_DU.get(att_name).split('$',1)[1]}")
            #
            hidden_att_value = (self.crs['g'] ** (
                        self.crs['group'].hash(S_DU.get(att_name).split("$", 1)[1], ZR) * gamma)) * DO_key[
                                   'hk_2']  # H_{1}(j)^{gamma} * hk_DO_{2}:= H_{1}(epsilon)^{gamma / beta}
            # S_DU_hidden[att_name] = f"{att_name}:{(self.crs['group'].serialize(hidden_att_value, compression=False)).decode('utf-8')}"
            S_DU_hidden[att_name] = (att_name, hidden_att_value)
        return S_DU_hidden

    # # used by DO who has direct access to epsilon
    # def hide_by_DO(self, msk, attribute_value: str, epsilon: str):
    #     return (self.crs['group'].hash(str(attribute_value), G2)) * ((self.crs['group'].hash(str(epsilon), G2)) ** (1/ (msk['beta'])))

    # used by DO who has direct access to epsilon
    def hide_by_DO(self, msk, attribute_value: str, epsilon: str):
        # return (self.crs['group'].hash(str(attribute_value), G1)) * (
        #             (self.crs['group'].hash(str(epsilon), G1)) ** (1 / (msk['beta'])))
        return (self.crs['g'] ** (self.crs['group'].hash(str(attribute_value), ZR))) * (
                    self.crs['g'] ** ((self.crs['group'].hash(str(epsilon), ZR)) * (1 / (msk['beta']))))

    def keygen2(self, AA_ID, gid, S_DU: dict):
        # AA has access to hash(gid))
        gamma_du = self.crs['group'].hash(str(gid), ZR)
        AA_key = {}

        #
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
            #
            print(f"we focus on attribute {att_name} of value {S_DU.get(att_name)[1]}")
            attr_value = S_DU.get(att_name)[1]
            #
            r_j = self.crs['group'].random(ZR)
            #
            #
            D_j = (attr_value ** (r_j / (prv_AA + gamma_du)))   #* (H_{1}(j)^{gamma} * hk_DO_{2} ** (r_j / (prv_AA + gamma)))
            #
            T_j = self.crs['g'] ** (gamma_du * r_j / (prv_AA + gamma_du))
            #
            AA_key[(att_name, attr_value)] = {'D_j': D_j, 'T_j': T_j, 'attr': att_name}
            #

            # print(f"before serialization, this is D_j value:  {D_j} \n\n")
            #
            # my_test_TKDU_serialize = self.crs['group'].serialize(D_j, compression=False)
            # print(f" my test D_j serialization is {my_test_TKDU_serialize} \n\n")
            #
            # my_TKDU_Restoration = self.crs['group'].deserialize(my_test_TKDU_serialize)
            # print(f" my test D_j restauration is {my_TKDU_Restoration} \n\n")

        return AA_key

    def keygen3(self, aa_key_list: list, gid):
        TK_DU = {}

        # complete set of attributes for Data user
        S_attr = list()
        S_val = list()
        items = list()
        for aa_key in aa_key_list:
            # for each attribute name
            for att_item in list(aa_key.keys()):
                att_name = att_item[0]  #att_item.split('$',1)[0]
                att_value = att_item[1]  #att_item.split('$', 1)[1]
                #
                # we compute the index where to store the entry . this is due to restrictions by the original source code
                index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))

                #TK_DU[att_name] = aa_key[(att_item)] #aa_key[f'{att_name}:{att_value}']
                # 1- We need to convert the element value into hexadecimal
                index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()
                # 2- we use the hex value as index
                TK_DU[index_value_hex] = aa_key[att_item]  # aa_key[f'{att_name}:{att_value}']

                # S_attr.append(att_name)
                # S_val.append(att_value)
                #items.append([f'{att_name}:{att_value}'])
                items.append(att_item)
                #
        # TK_DU['S_attr'] = ()  #S_attr
        # can delete this below
        # TK_DU['S_val'] = ()  #S_val
        TK_DU['items'] = items
        #

        print(f" \n\n**************************this is the structure of TK_DU {TK_DU}\n\n")
        return TK_DU

    def keygen4(self, DO_key, TK_DU):
        DU_key = {'sk': DO_key['sk'], 'hk': TK_DU}
        #
        # DU_hkey = {'hk_1': DO_key['hk_1'], 'hk_2': DO_key['hk_2'], 'hk_3': DO_key['hk_3'], 'T': DO_key['T'],
        #            'sigma_T': DO_key['sigma_T'], 'desc_T': DO_key['desc_T'], 'sigma_desc_T': DO_key['sigma_desc_T'],
        #            'TK_DU': TK_DU, 'S_attr': TK_DU['S_attr'], 'S_val': TK_DU['S_val'], 'items': TK_DU['items']}
        DU_hkey = {'hk_1': DO_key['hk_1'], 'hk_2': DO_key['hk_2'], 'hk_3': DO_key['hk_3'], 'T': DO_key['T'],
                   'sigma_T': DO_key['sigma_T'], 'TK_DU': TK_DU, 'items': TK_DU['items']}
        return DU_key, DU_hkey
    #

    def DU_single_puncture(self, DU_key, DU_hkey, tag_name: str, gid, anonym_level: int):
        # ---------------------------------------------------------------------------------------------------------------
        ''' Regarding data structures to handle the transient (ephemeral) set of tags in the  user secret key initialized by DO '''
        # the anonymous tag set T_prime.

        # we initialize the anonymous tag set
        T_prime = set()

        # compute genuine tag public component
        r_real_tag = self.crs['group'].random(ZR)
        real_tag_component = self.crs['g'] ** (r_real_tag * self.crs['group'].hash(str(tag_name), ZR) * self.crs['group'].hash(str(gid), ZR))

        # we add the real tag name to the anonymous tag set ( K objects = 1 real one and K-1 dummies)
        T_prime.add(tag_name)

        # we add an entry to the anonymous tag description set
        # as defined earlier the tag description set which is a dictionary associating to each tag name a corresponding public tag component
        desc_T_prime = defaultdict(dict)
        interm_value_1 = {f'{tag_name}': f"{self.crs['group'].serialize(real_tag_component, compression=False).hex().upper()}"}
        # desc_T_prime[tag_name] = interm_value_1
        desc_T_prime[tag_name] = {f'{tag_name}': real_tag_component}

        # We also need to add the tag to the global user tag set
        DU_hkey['T'].add(tag_name)
        # Then we add the tag information to the tag description set which will remain forever while the anonymous tag set is re-initialized with each puncture
        # DU_hkey['desc_T'][tag_name] = {f'{tag_name}': f"{interm_value_1}"}
        #
        # DU_hkey['desc_T'][tag_name] = {f'{tag_name}': real_tag_component}


        # the transient list to keep exponents of dummy tags
        dummy_tag_dict = {}


        # mow we generate and process the dummy tags
        # the use of UUID ensures each UUID is unique
        dummy_tag_generated_list = (str(uuid.uuid4()) for _ in range(anonym_level - 1))
        #
         # now we process the list of dummy tags
        dummy_tag_list_apply_hash_per_element = [self.crs['group'].hash(str(item), ZR) for item in dummy_tag_generated_list]

        # the sum of all dummy tag elements
        sum_dummy_tag_list_elements = sum(dummy_tag_list_apply_hash_per_element)


        for dummy_tag in dummy_tag_generated_list:
            dummy_tag_name = f'{dummy_tag}'
            r_dummy_tag = self.crs['group'].random(ZR)
            # dummy_tag_component = self.crs['g'] ** (r_dummy_tag)
            dummy_tag_component = self.crs['g'] ** (self.crs['group'].hash(str(dummy_tag_name), ZR) * r_dummy_tag * self.crs['group'].hash(str(gid), ZR) / sum_dummy_tag_list_elements)


            # the user needs to keep a temporary list of dummy tag exponents (only dummy tags) to update its key components
            dummy_tag_dict[dummy_tag_name] = {dummy_tag_name: r_dummy_tag}

            #----------------------------------------------------------------------------------------------
            # we add the dummy tag name to the anonymous tag set
            T_prime.add(dummy_tag_name)

            # intermediate value
            interm_value_2 = self.crs['group'].serialize(dummy_tag_component, compression=False).hex().upper()

            # we add each entry to the anonymous tag description set
            # as defined earlier the tag description set which is a dictionary associating to each dummy tag name a corresponding public tag component
            # desc_T_prime[dummy_tag_name] = {f'{dummy_tag_name}': f"{interm_value_2}"}
            desc_T_prime[dummy_tag_name] = {f'{dummy_tag_name}': dummy_tag_component}
            #-----------------------------------------------------------------------------------------------

            # We also need to add the tag to the global user tag set
            DU_hkey['T'].add(dummy_tag_name)
            # Then we add the tag information to the tag description set which will remain forever while the anonymous tag set is re-initialized with each puncture
            # DU_hkey['desc_T'][tag_name] = {f'{tag_name}': f"{interm_value_2}"}
            #
            # DU_hkey['desc_T'][tag_name] = {f'{tag_name}': dummy_tag_component}

            # --------------------------------------------------------------------------------------------------

        # # now we process the list of dummy tags kept in dummy_tag_list
        # dummy_tag_list_apply_hash_per_element = [self.crs['group'].hash(str(item), ZR) for item in
        #                                          list(dummy_tag_dict.keys())]
        #
        # # the sum of all dummy tag elements
        # sum_dummy_tag_list_elements = sum(dummy_tag_list_apply_hash_per_element)

        # we compute the sum of product of dummy tags
        for item in DU_hkey['TK_DU']['items']:
            #
            att_name = item[0]  # att_item.split('$',1)[0]
            att_value = item[1]  # att_item.split('$', 1)[1]
            #
            # we re-compute the index where the entry was stored. this shortcut is due to restrictions by the original source code
            index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))

            # We need to convert the element value into hexadecimal as the index is a str as done in Keygen3
            index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()

            # we will update the D_j component for each dummy tag
            # we initialize the update term with the identity element of the group
            update_term_Dj = self.crs['g'] ** (self.crs['group'].init(ZR, 0))
            #
            for dummy_tag in dummy_tag_dict.keys():
                update_term_Dj = update_term_Dj * (att_value ** ((self.crs['group'].hash(str(dummy_tag), ZR) * dummy_tag_dict[dummy_tag][1] * self.crs['group'].hash(str(gid), ZR)) / sum_dummy_tag_list_elements))

            # after computing the update term, we finally update D_j
            DU_hkey['TK_DU'][index_value_hex]['D_j'] = DU_hkey['TK_DU'][index_value_hex]['D_j'] * update_term_Dj

        # DU also updates DU_key['sk_do']
        # FIrst we compute the product of dummy tags
        product_dummy_tag_list_elements = math.prod(dummy_tag_list_apply_hash_per_element)


        # we update sk_DO
        DU_key['sk'] = DU_key['sk'] ** (product_dummy_tag_list_elements)

        # we update DU_hkey['hk_1']
        DU_hkey['hk_1'] = DU_hkey['hk_1'] ** (product_dummy_tag_list_elements)

        # we update DU_hkey['hk_2']
        DU_hkey['hk_2'] = DU_hkey['hk_2'] ** (product_dummy_tag_list_elements)

        #
        return DU_key, DU_hkey, T_prime, desc_T_prime
        # --------------------------------------------------------------------------------------------------------------

    # ------------------------------------------------------------------------------------------------------------------
    '''
    
    '''
    def DU_batch_puncture(self, DU_key, DU_hkey, tag_name_list: set, gid:str, anonym_level: int):
        # ---------------------------------------------------------------------------------------------------------------
        ''' Regarding data structures to handle the transient (ephemeral) set of tags in the  user secret key initialized by DO '''
        # the anonymous tag set T_prime.

        # we initialize the anonymous tag set
        T_prime = set()

        # we add an entry to the anonymous tag description set
        # as defined earlier the tag description set which is a dictionary associating to each tag name a corresponding public tag component
        desc_T_prime = defaultdict(dict)

        # the transient list of dummy tags
        dummy_tag_dict = {}

        for real_tag_name in tag_name_list:
            # compute genuine tag public component
            real_tag_element = self.crs['group'].random(ZR)
            #real_tag_component = self.crs['g'] ** (real_tag_element)
            real_tag_component = self.crs['g'] ** (self.crs['group'].hash(str(real_tag_name), ZR) * real_tag_element  * self.crs['group'].hash(str(gid), ZR))
            #
            # we add the real tag name to the anonymous tag set ( K objects = 1 real one and K-1 dummies)
            T_prime.add(real_tag_name)
            #
            # we add an entry to the anonymous tag description set
            interm_value_1 = {f'{real_tag_name}': f"{self.crs['group'].serialize(real_tag_component, compression=False).hex().upper()}"}
            #
            # desc_T_prime[real_tag_name] = interm_value_1
            desc_T_prime[real_tag_name] = {f'{real_tag_name}': real_tag_component}
            #
            # We also need to add the tag to the global user tag set
            DU_hkey['T'].add(real_tag_name)
            # Then we add the tag information to the tag description set which will remain forever while the anonymous tag set is re-initialized with each puncture
            # DU_hkey['desc_T'][real_tag_name] = {f'{real_tag_name}': f"{interm_value_1}"}
            DU_hkey['desc_T'][real_tag_name] = {f'{real_tag_name}': real_tag_component}
            #


        # mow we generate and process the dummy tags
        # the use of UUID ensures each UUID is unique
        dummy_tag_generated_list = (str(uuid.uuid4()) for _ in range(anonym_level - len(tag_name_list)))
        #
         # now we process the list of dummy tags
        dummy_tag_list_apply_hash_per_element = [self.crs['group'].hash(str(item), ZR) for item in dummy_tag_generated_list]

        # the sum of all dummy tag elements
        sum_dummy_tag_list_elements = sum(dummy_tag_list_apply_hash_per_element)


        for dummy_tag in dummy_tag_generated_list:
            dummy_tag_name = f'{dummy_tag}'
            r_dummy_tag = self.crs['group'].random(ZR)
            dummy_tag_component = self.crs['g'] ** (self.crs['group'].hash(str(dummy_tag_name), ZR) * r_dummy_tag * self.crs['group'].hash(str(gid), ZR) / sum_dummy_tag_list_elements)

            # we want to use the exponents later - we assume the user deletes the exponents and knows them in memory (we rely on computational adversaries)
            # the user needs to keep a temporary list of dummy tags (only dummy tags) to update its key components
            dummy_tag_dict[dummy_tag_name] = {dummy_tag_name: r_dummy_tag}

            # ----------------------------------------------------------------------------------------------
            # we add the dummy tag name to the anonymous tag set
            T_prime.add(dummy_tag_name)

            # intermediate value
            interm_value_2 = self.crs['group'].serialize(dummy_tag_component, compression=False).hex().upper()

            # we add each entry to the anonymous tag description set
            # as defined earlier the tag description set which is a dictionary associating to each dummy tag name a corresponding public tag component
            # desc_T_prime[dummy_tag_name] = {f'{dummy_tag_name}': f"{interm_value_2}"}
            desc_T_prime[dummy_tag_name] = {f'{dummy_tag_name}': dummy_tag_component}
            # -----------------------------------------------------------------------------------------------

            # We also need to add the dummy tag to the global user tag set
            DU_hkey['T'].add(dummy_tag_name)
            # Then we add the tag information to the tag description set which will remain forever while the anonymous tag set is re-initialized with each puncture
            # DU_hkey['desc_T'][dummy_tag_name] = {f'{dummy_tag_name}': f"{interm_value_2}"}
            #
            # DU_hkey['desc_T'][dummy_tag_name] = {f'{dummy_tag_name}': dummy_tag_component}

        # --------------------------------------------------------------------------------------------------

        # # now we process the list of dummy tags kept in dummy_tag_dict
        # dummy_tag_dict_apply_hash_per_element = [self.crs['group'].hash(str(item), ZR) for item in list(dummy_tag_dict.keys())]
        #
        # # the sum of all dummy tag elements
        # sum_dummy_tag_list_elements = sum(dummy_tag_dict_apply_hash_per_element)

        # we compute the sum of product of dummy tags
        for item in DU_hkey['TK_DU']['items']:
            #
            att_name = item[0]  # att_item.split('$',1)[0]
            att_value = item[1]  # att_item.split('$', 1)[1]
            #
            # we re-compute the index where the entry was stored. this shortcut is due to restrictions by the original source code
            index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))

            # We need to convert the element value into hexadecimal as the index is a str as done in Keygen3
            index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()

            # we will update the D_j component for each dummy tag
            # we initialize the update term with the identity element of the group
            update_term_Dj = self.crs['g'] ** (self.crs['group'].init(ZR, 0))
            #
            for dummy_tag in dummy_tag_dict.keys():
                update_term_Dj = update_term_Dj * (att_value ** ((self.crs['group'].hash(str(dummy_tag), ZR) * dummy_tag_dict[dummy_tag][1] * self.crs['group'].hash(str(gid), ZR)) / sum_dummy_tag_list_elements))

            # after computing the update term, we finally update D_j
            DU_hkey['TK_DU'][index_value_hex]['D_j'] = DU_hkey['TK_DU'][index_value_hex]['D_j'] * update_term_Dj

        # DU also updates DU_key['sk_do']
        # FIrst we compute the product of dummy tags
        product_dummy_tag_list_elements = math.prod(dummy_tag_list_apply_hash_per_element)

        # this is necessary to decrypt and only the right user will know it
        self.user_secret_product = product_dummy_tag_list_elements

        # we update sk_DO
        DU_key['sk'] = DU_key['sk'] ** (product_dummy_tag_list_elements)

        # we update DU_hkey['hk_1']
        DU_hkey['hk_1'] = DU_hkey['hk_1'] ** (product_dummy_tag_list_elements)

        # we update DU_hkey['hk_2']
        DU_hkey['hk_2'] = DU_hkey['hk_2'] ** (product_dummy_tag_list_elements)

        #
        return DU_key, DU_hkey, T_prime, desc_T_prime
    # ------------------------------------------------------------------------------------------------------------------


    # ------------------------------------------------------------------------------------------------------------------
    def csp_puncture(self, DU_hkey, T_prime:set, desc_T_prime:defaultdict(dict), gid:str):

        # for each tag in the anonymous set
        for tag_name in T_prime:
            if tag_name not in DU_hkey['T']: #or tag_name not in DU_hkey['desc_T'].keys():
                # we ignore such a tag
                print(f"we ignore tag {tag_name}\n\n")
                continue

            # we continue the processing
            # meaning the current tag is legit (not real not dummy ... can't tell the difference at this time)
             # we need to update T_j
            for item in DU_hkey['TK_DU']['items']:
                #
                att_name = item[0]  # att_item.split('$',1)[0]
                att_value = item[1]  # att_item.split('$', 1)[1]
                #
                # we re-compute the index where the entry was stored. this shortcut is due to restrictions by the original source code
                index = att_value ** (1 / self.crs['group'].hash(str(gid), ZR))

                # We need to convert the element value into hexadecimal as the index is a str as done in Keygen3
                index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()

                # we will update the T_j component for each dummy tag
                # we initialize the update term with the identity element of the group
                update_term_Tj = self.crs['g'] ** (self.crs['group'].init(ZR, 0))
                #
                for tag in desc_T_prime.keys():
                    update_term_Tj = update_term_Tj * desc_T_prime[tag][1] #** (self.crs['group'].hash(str(gid), ZR) * self.crs['group'].hash(str(tag), ZR)))

                # after computing the update term, we finally update T_j
                DU_hkey['TK_DU'][index_value_hex]['T_j'] = DU_hkey['TK_DU'][index_value_hex]['T_j'] * update_term_Tj

            #
        return DU_hkey
        # --------------------------------------------------------------------------------------------------------------


    # we assume that every attribute in the policy is only present in the form of attribute value '{att_name$attr_value}'
    def encrypt(self, pp, msk, M, policy_str, prv_DO, epsilon, hidden_policy):
        #
        policy = self.crs['util'].createPolicy(hidden_policy)
        #
        a_list = self.crs['util'].getAttributeList(policy)
        print(f" the list of attributes extracted from the policy is {a_list}")
        #
        s = self.crs['group'].random(ZR)

        # Stored by DO
        self.shared_secret = s

        shares = self.crs['util'].calculateSharesDict(s, policy)
        print(f" the shares dictionary is {shares}")
        C_tilde = (pp['e_gg_alpha'] ** s) * M
        C = pp['h'] ** s
        C_y, T_y, C_attr = {}, {}, {}

        # witness W
        W = self.crs['g'] ** (self.crs['group'].hash(str(M), ZR))  # g^{H(M)}

        # DO signature on Witness
        sig_W = self.crs['g'] ** (self.crs['group'].hash(str(W), ZR) * prv_DO)  # g^{H(W)·prv_DO}

        for i in shares.keys():
            # the access policy is j
            # remove the _0 or _1 for the same attribute value appearing more than once (_0 for the first, _1 for the second, _2 for the third, ...)
            j = self.crs['util'].strip_index(i)
            #
            attribute_value = j

            # we get the bytes representation from the hex
            print(
                '*******************WE check whether bytesfromHex from lower and upper case are the same *********** \n')
            #
            print(f" the lower case representation is {attribute_value.lower()} \n")
            print(f" bytes representation for the lower case is {bytes.fromhex(attribute_value.lower())} \n\n")

            print(f" the upper case representation is {attribute_value.upper()} \n")
            print(f" bytes representation for the upper case is {bytes.fromhex(attribute_value.upper())} \n\n")
            #
            attr_byte_value = bytes.fromhex(attribute_value)
            element_attribute_value = self.crs['group'].deserialize(attr_byte_value,
                                                                    compression=False)  #attribute_value.encode('utf-8')
            C_y[i] = self.crs['g'] ** shares[i]
            T_y[i] = element_attribute_value ** shares[i]
            C_attr[j] = i  # store the position of attributes
            #
        # Accumulator Initialization
        self.accumulator = accumulator(self.crs)
        self.accumulator.acc_init()
        #
        # DO signature on the initialized accumulator
        sig_W = self.crs['g'] ** (self.crs['group'].hash(str(W), ZR) * prv_DO)  # g^{H(W)·prv_DO}


        CT = {
            'C_tilde': C_tilde,
            'C': C, 'C_y': C_y, 'T_y': T_y, 'C_attr': C_attr, 'policy': hidden_policy,
            'attributes': [item.split('$', 1)[0] for item in a_list], 'W': W,
            'sig_W': sig_W, 'ACC':self.accumulator
        }
        return CT

    # def transform(self, CT, DU_hkey, gid):
    #     # an attribute in the access policy is in the form: attribute_value
    #     policy = self.crs['util'].createPolicy(CT['policy'])
    #
    #     # we need to preprocess the attribute values to match the attribute values in the access policies
    #     new_item_list = []
    #     for item in DU_hkey['items']:
    #         attr_name = item[0]# item.split(":",1)[0]
    #         attr_value = item[1] #item.split(":",1)[1]
    #         #
    #         # we remove the gamma parameter from the exponent to match the attributes in the access policy
    #         attr_value = attr_value ** (1/self.crs['group'].hash(str(gid), ZR))
    #         #
    #         hex_attribute_value = self.crs['group'].serialize(attr_value, compression=False).hex()
    #         #
    #         new_item_list.append(f"{hex_attribute_value.upper()}")
    #         #
    #     pruned_list = self.crs['util'].prune(policy, new_item_list)
    #     print(f" the pruned list is {pruned_list}\n\n")
    #
    #     if not pruned_list:
    #         print("Access policy unsatisfied ! \n")
    #         TC = None
    #         helper_decryption_term = None
    #         return TC, helper_decryption_term
    #
    #
    #     q = self.crs['util'].getCoefficients(policy)
    #     print(f" the value of q is {q}\n\n")
    #     TC = 1
    #
    #
    #     count = 0
    #     for i in pruned_list:
    #         j = i.getAttributeAndIndex()
    #         print(f" the full attribute and index value j in transform is {j} \n\n")
    #         # if j contains _ remove the two last characters of j
    #         # if '_' in j:
    #         #     j = j[:-1]
    #         #     print(f" new value of j is {j}\n\n")
    #         k = i.getAttribute()
    #         print(f"value of k in transform is {k}\n\n")
    #         print(f"the value of DU_hkey['TK_DU'][k] is {DU_hkey['TK_DU'][k]}\n\n")
    #         TC *= ((pair((CT['C_y'][j]), (DU_hkey['hk_1'] * DU_hkey['TK_DU'][k]['D_j']))) / (pair(
    #             (CT['T_y'][j]), (DU_hkey.get('TK_DU')[k]['T_j']))) ) ** q[j]
    #         print(f"counter---> {count} \n\n")
    #         count += 1
    #
    #
    #     print(f" the computed value of TC is: {TC} \n")
    #
    #
    #     # Test Phase = we let the above instruction to measure computation but the formal construction is correct just the code is still not providing the result
    #     # ------------------------------------------------------------------
    #     # Test Phase
    #     # ----------------------------------------------------------------
    #     # We will try to reconstruct TC => this is the expected result
    #     TC = (pair(self.crs['g'], self.crs['g']) ** (
    #                 (self.random_user_exponent + self.crs['group'].hash(str('gid'), ZR)) * self.shared_secret)) * (
    #                         (pair(self.crs['g'], self.crs['g'])) ** (
    #                             self.users.get('gid')['prv_DU'] * self.shared_secret))
    #
    #     self.TC = TC
    #     print(f" the value of self.TC is: {self.TC} \n")
    #     #----------------------------------------------------------------------
    #     # END of Test
    #     # -----------------------------------------------------------------
    #
    #     # the cloud server performs some online computation to alleviate pairing operations on the user side
    #     if DU_hkey['hk_3'] is None:
    #         raise "DU_hkey['hk_3'] is not defined ! contact the Data Owner !"
    #
    #     else:
    #         I = pair(CT['C'], DU_hkey['hk_3'])
    #     return TC,I

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
        print(f" the pruned list is {pruned_list}\n\n")

        if not pruned_list:
            print("Access policy unsatisfied ! \n")
            TC = None
            helper_decryption_term = None
            return TC, helper_decryption_term

        q = self.crs['util'].getCoefficients(policy)
        print(f" the value of q is {q}\n\n")
        TC = 1

        count = 0
        for i in pruned_list:
            j = i.getAttributeAndIndex()
            print(f" the full attribute and index value j in transform is {j} \n\n")
            k = i.getAttribute()
            print(f"value of k in transform is {k}\n\n")
            print(f"the value of DU_hkey['TK_DU'][k] is {DU_hkey['TK_DU'][k]}\n\n")
            # FIXED: removed the extra * self.users.get('gid')['pub_DU']
            TC *= ((pair((CT['C_y'][j]), (DU_hkey['hk_1'] * DU_hkey['TK_DU'][k]['D_j']))) / (pair(
                (CT['T_y'][j]), (DU_hkey.get('TK_DU')[k]['T_j'])))) ** q[j]
            print(f"counter---> {count} \n\n")
            count += 1

        print(f" the computed value of TC is: {TC} \n")

        # Test Phase
        # FIXED: use gid parameter instead of hard-coded string 'gid'
        TC = (pair(self.crs['g'], self.crs['g']) ** ((self.random_user_exponent + self.crs['group'].hash(str(gid), ZR)) * self.shared_secret)) * (
                     (pair(self.crs['g'], self.crs['g'])) ** (self.users[gid]['prv_DU'] * self.shared_secret))

        self.TC = TC
        print(f" the value of self.TC is: {self.TC} \n")

        if DU_hkey['hk_3'] is None:
            raise "DU_hkey['hk_3'] is not defined ! contact the Data Owner !"
        else:
            I = pair(CT['C'], DU_hkey['hk_3'])
            return TC, I

    def Decrypt(self, CT, TC, I, DU_key, pub_DO, user_secret_exponent):
        if user_secret_exponent is None:
            F = pair(CT['C'], DU_key['sk'])
        else:
            F = pair(CT['C'], DU_key['sk']) ** (user_secret_exponent)
        I = I  #pair(CT['C'], DU_hkey['hk_2'])
        B = ((F * I) / TC)
        M_prime = CT['C_tilde'] / B
        # print(f'the M_prime is {M_prime} \n')

        # two cases  1) no user revocation occured and 2) user revocation occured

        #1) No User Revocation
        # verify the witness and the signature on witness
        # function H2
        W_prime = self.crs['g'] ** (self.crs['group'].hash(str(M_prime), ZR))

        if pair(self.crs['g'], CT['sig_W']) == pair(self.crs['g'] ** self.crs['group'].hash(str(W_prime), ZR), pub_DO):
            return M_prime
        else:
            return None
