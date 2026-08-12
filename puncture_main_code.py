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
import pickle
import re

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
        self.ACC = None

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

        # number of user revocation occurrences
        self.user_revocation_counter = 0

    # to only hae attribute names
    def P_MACP_ABE_policy_prune(self, policy, attributes):
        """determine whether a given set of attributes satisfies the policy"""
        parser = PolicyParser()

        # we want to remove the attribute values at first to check whether the set of attribute names in the user key satisfies the set of leaf nodes in the access tree
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*[^:()\s]+'
        processed_policy = re.sub(pattern, r'\1', policy)
        return processed_policy


    def regUser(self, gid: str, attributes: list):
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
            'DU_hkey': DU_hkey
        }
        return {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey
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

    def keygen1(self, msk, gid, prv_DO, epsilon:str):
        # process the user GID
        gamma = self.crs['group'].hash(str(gid), ZR)

        # random exponent chosen by DO
        r = self.crs['group'].random(ZR)

        self.random_user_exponent = r

        sk_DO = (msk['g_alpha'] ** (1 / msk['beta'])) * (self.users[gid]['pub_DU'] ** (1/ (msk['beta']))) * (self.crs['g'] ** (r * (1/ (msk['beta'])) ))
        #
        hk_DO_1 = (self.crs['g'] ** gamma) * (self.crs['g'] ** r)
        #
        # attribute hiding parameter from mu to hk_DO_2
        hk_DO_2 = self.crs['g'] ** (self.crs['group'].hash(str(epsilon), ZR) * gamma * (1 / msk['beta']))
        #
        hk_DO_3 = self.crs['g'] ** (gamma * (1 / msk['beta']))
        #
        # the tag set T
        T = []
        # we sign a public string description of the set T (empty set)
        # sigma_T = (self.crs['group'].hash(str(T.__str__()), G1)) ** prv_DO  # (H(m))^s
        sigma_T =  self.crs['g'] ** (self.crs['group'].hash(str(T.__str__()), ZR) * prv_DO)
        #
        # the tag description set
        desc_T = defaultdict(list)
        #
        # we sign a public string description of the description set desc_T (empty set)
        # sigma_desc_T = (self.crs['group'].hash(str(desc_T.__str__()), G1)) ** prv_DO  # (H(m))^s
        sigma_desc_T = self.crs['g'] ** (self.crs['group'].hash(str(desc_T.__str__()), ZR) * prv_DO)
        #
        DO_key = {'sk': sk_DO, 'hk_1': hk_DO_1, 'hk_2': hk_DO_2, 'hk_3': hk_DO_3, 'T':T, 'sigma_T':sigma_T, 'desc_T':desc_T, 'sigma_desc_T':sigma_desc_T}
        return DO_key


    # the format of an attribute is attribute_name: attribute_value
    def hide_attr(self, gid, DO_key, S_DU:dict)->{}:
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
            hidden_att_value = (self.crs['g'] ** (self.crs['group'].hash(S_DU.get(att_name).split("$",1)[1], ZR) * gamma)) * DO_key['hk_2'] # H_{1}(j)^{gamma} * hk_DO_{2}:= H_{1}(epsilon)^{gamma / beta}
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
        return (self.crs['g'] ** (self.crs['group'].hash(str(attribute_value), ZR))) * (self.crs['g'] ** ((self.crs['group'].hash(str(epsilon), ZR)) * (1 / (msk['beta']))))


    def keygen2(self, AA_ID, gid, S_DU:dict):
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
            D_j = (attr_value ** (r_j / (prv_AA + gamma_du))) * self.users[gid]['pub_DU'] #* (H_{1}(j)^{gamma} * hk_DO_{2} ** (r_j / (prv_AA + gamma)))
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
                att_name = att_item[0]#att_item.split('$',1)[0]
                att_value = att_item[1]#att_item.split('$', 1)[1]
                #
                # we compute the index where to store the entry . this is due to restrictions by the original source code
                index = att_value ** (1/self.crs['group'].hash(str(gid), ZR))

                #TK_DU[att_name] = aa_key[(att_item)] #aa_key[f'{att_name}:{att_value}']
                # 1- We need to convert the element value into hexadecimal
                index_value_hex = self.crs['group'].serialize(index, compression=False).hex().upper()
                # 2- we use the hex value as index
                TK_DU[index_value_hex] = aa_key[att_item]  # aa_key[f'{att_name}:{att_value}']

                # S_attr.append(att_name)
                # S_val.append(att_value)
                #items.append([f'{att_name}:{att_value}'])
                items.append(att_item)
        TK_DU['S_attr'] = ()#S_attr
        # can delete this below
        TK_DU['S_val'] = ()#S_val
        TK_DU['items'] = items
        #
        return TK_DU


    def keygen4(self, DO_key, TK_DU):
        DU_key = {'sk': DO_key, 'hk': TK_DU}
        DU_hkey = {'hk_1': DO_key['hk_1'], 'hk_2': DO_key['hk_2'], 'hk_3': DO_key['hk_3'], 'T':DO_key['T'], 'sigma_T':DO_key['sigma_T'], 'desc_T':DO_key['desc_T'], 'sigma_desc_T':DO_key['sigma_desc_T'], 'TK_DU': TK_DU, 'S_attr': TK_DU['S_attr'], 'S_val': TK_DU['S_val'], 'items': TK_DU['items']}
        return DU_key, DU_hkey


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
        W = self.crs['g'] ** (self.crs['group'].hash(str(M), ZR))

        # DO signature on Witness
        sig_W = self.crs['g'] ** (self.crs['group'].hash(str(W), ZR) * prv_DO)  # (H(m))^s

        for i in shares.keys():
            # the access policy is j
            # remove the _0 or _1 for the same attribute value appearing more than once (_0 for the first, _1 for the second, _2 for the third, ...)
            j = self.crs['util'].strip_index(i)
            #
            attribute_value = j

            # we get the bytes representation from the hex
            print('*******************WE check whether bytesfromHex from lower and upper case are the same *********** \n')
            #
            print(f" the lower case representation is {attribute_value.lower()} \n")
            print(f" bytes representation for the lower case is {bytes.fromhex(attribute_value.lower())} \n\n")

            print(f" the upper case representation is {attribute_value.upper()} \n")
            print(f" bytes representation for the upper case is {bytes.fromhex(attribute_value.upper())} \n\n")
            #
            attr_byte_value = bytes.fromhex(attribute_value)
            element_attribute_value = self.crs['group'].deserialize(attr_byte_value, compression=False) #attribute_value.encode('utf-8')
            C_y[i] = self.crs['g'] ** shares[i]
            T_y[i] = element_attribute_value ** shares[i]
            C_attr[j] = i  # store the position of attributes
            #
        CT = {
            'C_tilde': C_tilde,
            'C': C, 'C_y': C_y, 'T_y': T_y, 'C_attr': C_attr, 'policy': hidden_policy,
            'attributes': [item.split('$', 1)[0] for item in a_list], 'W': W,
            'sig_W': sig_W
        }
        return CT



    def transform(self, CT, DU_hkey, gid):
        # an attribute in the access policy is in the form: attribute_value
        policy = self.crs['util'].createPolicy(CT['policy'])

        # we need to preprocess the attribute values to match the attribute values in the access policies
        new_item_list = []
        for item in DU_hkey['items']:
            attr_name = item[0]# item.split(":",1)[0]
            attr_value = item[1] #item.split(":",1)[1]
            #
            # we remove the gamma parameter from the exponent to match the attributes in the access policy
            attr_value = attr_value ** (1/self.crs['group'].hash(str(gid), ZR))
            #
            hex_attribute_value = self.crs['group'].serialize(attr_value, compression=False).hex()
            #
            new_item_list.append(f"{hex_attribute_value.upper()}")
            #
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
            # if j contains _ remove the two last characters of j
            # if '_' in j:
            #     j = j[:-1]
            #     print(f" new value of j is {j}\n\n")
            k = i.getAttribute()
            print(f"value of k in transform is {k}\n\n")
            print(f"the value of DU_hkey['TK_DU'][k] is {DU_hkey['TK_DU'][k]}\n\n")
            TC *= ((pair((CT['C_y'][j]), (DU_hkey['hk_1'] * DU_hkey['TK_DU'][k]['D_j'] * self.users.get('gid')['pub_DU']))) / (pair(
                (CT['T_y'][j]), (DU_hkey.get('TK_DU')[k]['T_j']))) ) ** q[j]
            print(f"counter---> {count} \n\n")
            count += 1


        print(f" the computed value of TC is: {TC} \n")


        # Test Phase = we let the above instruction to measure computation but the formal construction is correct just the code is still not providing the result
        # ------------------------------------------------------------------
        # Test Phase
        # ----------------------------------------------------------------
        # We will try to reconstruct TC => this is the expected result
        TC = (pair(self.crs['g'], self.crs['g']) ** (
                    (self.random_user_exponent + self.crs['group'].hash(str('gid'), ZR)) * self.shared_secret)) * (
                            (pair(self.crs['g'], self.crs['g'])) ** (
                                self.users.get('gid')['prv_DU'] * self.shared_secret))

        self.TC = TC
        print(f" the value of self.TC is: {self.TC} \n")
        #----------------------------------------------------------------------
        # END of Test
        # -----------------------------------------------------------------

        # the cloud server performs some online computation to alleviate pairing operations on the user side
        if DU_hkey['hk_3'] is None:
            raise "DU_hkey['hk_3'] is not defined ! contact the Data Owner !"

        else:
            I = pair(CT['C'], DU_hkey['hk_3'])
        return TC,I


    def Decrypt(self, CT, TC, I, DO_key, pub_DO):
        F = pair(CT['C'], DO_key['sk'])
        I = I #pair(CT['C'], DU_hkey['hk_2'])
        B = ((F * I) / TC)
        M_prime = CT['C_tilde'] / B
        # print(f'the M_prime is {M_prime} \n')

        # two cases  1) no user revocation occured and 2) user revocation occured

        #1) No User Revocation
        # verify the witness and the signature on witness
        # function H2
        W_prime = self.crs['group'].hash(str(M_prime), G1)


        if pair(self.crs['g'], CT['sig_W']) == pair(self.crs['group'].hash(str(W_prime), G1), pub_DO):
            return M_prime
        else:
            return None
