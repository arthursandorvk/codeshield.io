from collections import defaultdict

import pandas as pd
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
    # we register the first AA
    authority_id = 1
    authority_name = "AA1"
    attrs_1 = ['attribute1']
    puncture_maabe_obj.setupAA(authority_id, authority_name, attrs_1)

    # we register the second AA
    authority_id = 2
    authority_name = "AA2"
    attrs_2 = ['attribute2']
    puncture_maabe_obj.setupAA(authority_id, authority_name, attrs_2)

    # we register the third AA
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

    # we register a user
    user = {}
    user_gid = 'gid'
    user = puncture_maabe_obj.regUser(gid=user_gid, attributes=attrs, anonymity_level= 10)

    #
    access_policy = f"(({attrs['attribute4']} or {attrs['attribute3']}) and ({attrs['attribute3']} or {attrs['attribute1']}))" #f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))"

    # we need to hide the attribute values
    access_policy = f"(({attrs['attribute4']} or {attrs['attribute3']}) and ({attrs['attribute3']} or {attrs['attribute1']}))"  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))"
    access_policy_schema = f"(({attrs['attribute4'].split('$',1)[0]} or {attrs['attribute3'].split('$',1)[0]}) and ({attrs['attribute3'].split('$',1)[0]} or {attrs['attribute1'].split('$',1)[0]}))"  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))"
    #

    '''
    how to save / restore a group element
    print(f"before serialization, this is D_j value:  {D_j} \n\n")

    my_test_TKDU_serialize = self.crs['group'].serialize(D_j, compression=False)
    print(f" my test D_j serialization is {my_test_TKDU_serialize} \n\n")

    my_TKDU_Restoration = self.crs['group'].deserialize(my_test_TKDU_serialize)
    print(f" my test D_j restauration is {my_TKDU_Restoration} \n\n")
    #
    '''
    # hidden_attrs = {}
    # hidden_attrs['attribute1'] = f"attribute1${(puncture_maabe_obj.crs['group'].serialize(puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon'), compression=False)).decode('utf-8')}"
    # hidden_attrs['attribute2'] = f"attribute2${(puncture_maabe_obj.crs['group'].serialize(puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon'), compression=False)).decode('utf-8')}"
    # hidden_attrs['attribute3'] = f"attribute3${(puncture_maabe_obj.crs['group'].serialize(puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon'), compression=False)).decode('utf-8')}"
    # hidden_attrs['attribute4'] = f"attribute4${(puncture_maabe_obj.crs['group'].serialize(puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon'), compression=False)).decode('utf-8')}"
    hiden_attr_1 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon')
    hiden_attr_2 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon')
    hiden_attr_3 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon')
    hiden_attr_4 = puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon')

    # print("********* list attribute values hidden by DO (group elements) ***** \n")
    # print(f"attribute 1: {hiden_attr_1}\n")
    # print(f"attribute 2: {hiden_attr_2}\n")
    # print(f"attribute 3: {hiden_attr_3}\n")
    # print(f"attribute 4: {hiden_attr_4}\n")

    # hidden_attrs = {}
    # hidden_attrs['attribute1'] = f"attribute1${(puncture_maabe_obj.crs['group'].serialize(hiden_attr_1, compression=False)).hex()}"
    # hidden_attrs['attribute2'] = f"attribute2${(puncture_maabe_obj.crs['group'].serialize(hiden_attr_2, compression=False)).hex()}"
    # hidden_attrs['attribute3'] = f"attribute3${(puncture_maabe_obj.crs['group'].serialize(hiden_attr_3, compression=False)).hex()}"
    # hidden_attrs['attribute4'] = f"attribute4${(puncture_maabe_obj.crs['group'].serialize(hiden_attr_4, compression=False)).hex()}"
    #
    hidden_attrs = {}
    hidden_attrs['attribute1'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_1, compression=False).hex().upper()
    hidden_attrs['attribute2'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_2, compression=False).hex().upper()
    hidden_attrs['attribute3'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_3, compression=False).hex().upper()
    hidden_attrs['attribute4'] = puncture_maabe_obj.crs['group'].serialize(hiden_attr_4, compression=False).hex().upper()



    # hidden_attrs_policy = {}
    # hidden_attrs_policy['attribute1'] = f"attribute1${puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon')}"
    # hidden_attrs_policy['attribute2'] = f"attribute2${puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon')}"
    # hidden_attrs_policy['attribute3'] = f"attribute3${puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon')}"
    # hidden_attrs_policy['attribute4'] = f"attribute4${puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon')}"


    # only attribute values
    # hidden_attrs = {}
    # hidden_attrs['attribute1'] = (puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon'))
    # hidden_attrs['attribute2'] = (puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon'))
    # hidden_attrs['attribute3'] = (puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon'))
    # hidden_attrs['attribute4'] = (puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon'))

    # hidden_attrs = {}
    # hidden_attrs['attribute1'] = map(str, 'attribute1$'+{puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon')})
    # hidden_attrs['attribute2'] = map(str, 'attribute2$'+{puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon')})
    # hidden_attrs['attribute3'] = map(str, 'attribute3$'+{puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon')})
    # hidden_attrs['attribute4'] = map(str, 'attribute4$'+{puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon')})

    # hidden_attrs = {}
    # hidden_attr_1 = f"attribute1${puncture_maabe_obj.hide_by_DO(mk, attribute_value='ONE', epsilon='epsilon')}"
    # hidden_attr_2 = f"attribute2${puncture_maabe_obj.hide_by_DO(mk, attribute_value='TWO', epsilon='epsilon')}"
    # hidden_attr_3 = f"attribute3${puncture_maabe_obj.hide_by_DO(mk, attribute_value='THREE', epsilon='epsilon')}"
    # hidden_attr_4 = f"attribute4${puncture_maabe_obj.hide_by_DO(mk, attribute_value='FOUR', epsilon='epsilon')}"

    # hidden_access_policy = f"(({(hidden_attrs['attribute4'].split('$',1)[1])} or {hidden_attrs['attribute3'].split('$',1)[1]}) and ({hidden_attrs['attribute3'].split('$',1)[1]} or {hidden_attrs['attribute1'].split('$',1)[1]}))"  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))"
    # hidden_access_policy = f"(({hidden_attrs['attribute4'].split('$',1)[1]} or {hidden_attrs['attribute3'].split('$',1)[1]}) and ({hidden_attrs['attribute3'].split('$',1)[1]} or {hidden_attrs['attribute1'].split('$',1)[1]}))"  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden}))"
    # hidden_access_policy = f"(({hidden_attrs_policy['attribute4']} or {hidden_attrs_policy['attribute3']}) and ({hidden_attrs_policy['attribute3']} or {hidden_attrs_policy['attribute1']}))"  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden})'
    hidden_access_policy = f"(({hidden_attrs['attribute4']} or {hidden_attrs['attribute3']}) and ({hidden_attrs['attribute3']} or {hidden_attrs['attribute1']}))"  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden})'
    #
    # hidden_access_policy = f'({hidden_attr_4} or {hidden_attr_3}) and ({hidden_attr_3} or {hidden_attr_1})'  # f"(({four_hidden} or {three_hidden}) and ({three_hidden} or {one_hidden})'

    print(f" the value of the ****** hidden policy ******* is  {hidden_access_policy}\n\n\n")
    # print("this is the access policy schema ", access_policy_schema)

    if debug:
        print("Unhidden Attributes =>", attrs, "\n")
        print("Policy =>", access_policy, "\n")


    #1- DO generate the DO Key
    do_key = puncture_maabe_obj.keygen1(mk, puncture_maabe_obj.users[user_gid].get(user_gid), prv_DO, epsilon_value)
    #
    # 2- DU hides the set of attributes originally in the plain form
    # print(" the set of attributes for the current user before hiding them ", puncture_maabe_obj.users[user_gid].get('attributes'))
    puncture_maabe_obj.users[user_gid]['attributes'] = puncture_maabe_obj.hide_attr(puncture_maabe_obj.users[user_gid].get('gid'), do_key, puncture_maabe_obj.users[user_gid].get('attributes'))
    # print(" the set of hidden attributes for the current user ", puncture_maabe_obj.users[user_gid].get('attributes'))
    #
    # AAs compute Keygen2
    # WE consider three AAs
    # set of attributes
    aa_key_1 = puncture_maabe_obj.keygen2(AA_ID=1, gid=puncture_maabe_obj.users[user_gid].get('gid'), S_DU=puncture_maabe_obj.users[user_gid]['attributes'])
    print(f" the gid is {puncture_maabe_obj.users[user_gid].get('gid')} and the set of attributes is {puncture_maabe_obj.users[user_gid].get('attributes')} \n\n")

    # set of attributes
    aa_key_2 = puncture_maabe_obj.keygen2(AA_ID=2, gid=puncture_maabe_obj.users[user_gid].get('gid'), S_DU=puncture_maabe_obj.users[user_gid]['attributes'])

    # set of attributes
    aa_key_3 = puncture_maabe_obj.keygen2(AA_ID=3, gid=puncture_maabe_obj.users[user_gid].get('gid'), S_DU=puncture_maabe_obj.users[user_gid]['attributes'])
    #
    input_aa_key = list()
    input_aa_key.append(aa_key_1)
    input_aa_key.append(aa_key_2)
    input_aa_key.append(aa_key_3)
    # input_aa_key[0]= aa_key_1
    # input_aa_key[1] = aa_key_2
    # input_aa_key[2] = aa_key_3

    if debug:
        print(f"Hidden Attributes => \n {puncture_maabe_obj.users[user_gid]['attributes']} \n")

    tk_key = puncture_maabe_obj.keygen3(input_aa_key, user_gid)
    #
    DU_key, DU_hkey = puncture_maabe_obj.keygen4(do_key, tk_key)
    #

    # ***********************Encryption************
    rand_msg = puncture_maabe_obj.crs['group'].random(GT)
    # print(f' the original  message is {rand_msg} \n')
    #

    CT = puncture_maabe_obj.encrypt(pk, mk, rand_msg, access_policy, prv_DO, epsilon_value, hidden_access_policy)
    #
    TC, I = puncture_maabe_obj.transform(CT=CT, DU_hkey=DU_hkey, gid=puncture_maabe_obj.users[user_gid].get('gid'))

    rec_msg = puncture_maabe_obj.Decrypt(CT, TC, I, do_key, pub_DO, puncture_maabe_obj.user_secret_product)

    # if debug: print("\n\nCiphertext...\n")
    # groupObj.debug(ct)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"

    if debug is True:
        print(f" Original msg: {rand_msg} \n")
        print(f" msg recovered: {rec_msg} \n")
    print("Successful Decryption!!!")

    myset = defaultdict(dict)
    myset['a']=(('a',puncture_maabe_obj.crs['group'].serialize(puncture_maabe_obj.crs['group'].hash('a',ZR), compression=False).hex().upper()))

    myset_list = list()
    myset_list.append(myset)

    print(f"myset: {myset['a']}")


if __name__ == "__main__":
    debug = False
    #
    single_puncture = False
    main()
