from collections import defaultdict

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from fontTools.subset.svg import group_elements_by_id


class accumulator:
    # =====================================================================
    # ADDITIVE POSITIVE BILINEAR ACCUMULATOR FUNCTIONS
    # =====================================================================
    # The initial accumulator value is the identity element of G1
    # Inputs are strings in {0,1}* mapped to ZR via group.hash
    # =====================================================================


    def __init__(self, crs):
        self.acc_len = 0
        # the accumulator
        self.ACC_value = None
        self.crs = crs

    #

    def acc_init(self):
        # Accumulator initialization with identity element of G1 : ACC = 1_{G1} = g^0
        # ACC is the accumulated string
        self.ACC_value = self.crs['g'] ** (self.crs['group'].init(ZR, 0))
        return self.ACC_value

    # ------------------------------------------------------------------------------------------------------------

    # this function hashes a tag and outputs the corresponding group element
    def acc_hash_to_group(self, tag_name: str) :
        """
        Hash a tag to a group  element
        tag ∈ {0,1}*
        Return H(tag)
        """
        tag_group = self.crs['g'] ** (self.crs['group'].hash(str(tag_name), ZR))
        return tag_group
    # -----------------------------------------------------------------------------------------------------------

    # getter for the accumulator
    def acc_get_value(self):
        """Return the current accumulator value."""
        return self.ACC_value

    # -----------------------------------------------------------------------------------------------------------
    # return the number of tags accumualted
    def acc_get_size(self):
        """Return the number of accumulated tags."""
        return self.acc_len

    # ----------------------------------------------------------------------------------------------------------

    # this function accumulates tags into the accumulator
    # (single tag puncturing)
    # the tag given as parameter will only have the name not yet the value which is equivalent to its group element
    # representation
    def accumulate_tags(self, DU_hkey, T_prime:set, desc_T_prime:defaultdict(dict), gid:str):
        """
        Stores the tag and its group element in tag_dict.
        """
        # initialize the accumulator
        if self.ACC_value is None:
            self.acc_init()

        # for each tag in the anonymous set T_prime
        for tag_name in T_prime:
            if tag_name not in DU_hkey['T']:
                # we ignore such a tag
                print(f"we ignore tag {tag_name}\n\n")
                raise ValueError(f"Tag '{tag_name}' is not in the accumulated set")
                # continue
            # the tag is present within DU_hkey['T']
            tag_group_element = self.acc_hash_to_group(tag_name)
            # WE update the accumulator value
            self.ACC_value = self.ACC_value * tag_group_element
            # we augment the length of the accumulated size
            self.acc_len = self.acc_len +1
            #
        return self.ACC_value
    # ------------------------------------------------------------------------------------------------------------

    #--------------------------------------------------------------------------------------------------------------
    # to compute a positive membership witness from the set of tags where the cloud performs O(n) computation
    def acc_membership_witness1(self, tag: str, DU_hkey):
        if tag not in DU_hkey['T']:
            raise ValueError(f"Tag '{tag}' is not in the accumulated set")

        # Compute the product of all elements except 'tag'
        witness = self.crs['g'] ** self.crs['group'].init(ZR, 0)  # identity

        for t in DU_hkey['T']:
            if t != tag:
                witness = witness * self.acc_hash_to_group(t)

        return witness

    # --------------------------------------------------------------------------------------------------------------

    def acc_membership_witness2(self, tag: str, DU_hkey):
        """
        Compute membership witness using the current accumulator value.

        This is more efficient than recomputing from scratch but is somewhat subject to the fact that accumulation of old
        values is trusted
        """
        if self.ACC is None:
            raise ValueError("Accumulator not initialized")

        if tag not in DU_hkey['T']:
            raise ValueError(f"Tag '{tag}' is not in the accumulated set")

        tag_group_element = self.acc_hash_to_group(tag)
        witness = self.ACC_value * (tag_group_element ** -1)
        return witness

    # --------------------------------------------------------------------------------------------------------------

    def acc_verify_membership1(self, tag: str, witness, acc_value) -> bool:
        """
        Verify that 'tag' is in the accumulator using witness W.

        Direct verification (no pairing needed for additive accumulator):
            W · g^{H(tag)} == ACC_Value
        """
        if acc_value is None:
            acc_value = self.ACC
        if acc_value is None:
            raise ValueError("Accumulator not initialized")

        tag_group_element = self.acc_hash_to_group(tag)
        # Direct check: W · g^{H(tag)} == ACC
        return (witness * tag_group_element) == acc_value

    # --------------------------------------------------------------------------------------------------------------

    def acc_verify_membership_with_pairing(self, tag: str, witness: object, acc_value: object) -> bool:
        """
        we can verify using:  e(W, g) · e(g^{H(tag)}, g) == e(ACC, g)
        giving: e(W · g^{H(tag)}, g) == e(ACC, g)
        """
        if acc_value is None:
            acc_value = self.ACC

        if acc_value is None:
            raise ValueError("Accumulator not initialized")

        tag_group_element = self.acc_hash_to_group(tag)

        # we need to compute e(W · g^{H(tag)}, g) == e(ACC, g)
        left_pair = pair(witness * tag_group_element, self.crs['g'])
        right_pair= pair(acc_value, self.crs['g'])

        return left_pair == right_pair

    # --------------------------------------------------------------------------------------------------------------

    def acc_get_value(self) -> object:
        """Return the current accumulator value."""
        return self.ACC

    # --------------------------------------------------------------------------------------------------------------

    def acc_serialize(self) -> bytes:
        """Serialize the accumulator value."""
        if self.ACC is None:
            return None
        return self.crs['group'].serialize(self.ACC, compression=False).hex().upper()

    # --------------------------------------------------------------------------------------------------------------

    def acc_deserialize(self, data: bytes):
        """Deserialize and set the accumulator value."""
        self.ACC = self.crs['group'].deserialize(bytes.fromhex(data), compression=False)
        return self.ACC

    # --------------------------------------------------------------------------------------------------------------

    def acc_batch_witnesses(self, tag_set: set, DU_hkey) -> dict:
        """
        Compute membership witnesses for ALL tags in the set.
        Returns a dictionary: {tag: witness}

        Efficient computation: For each tag, W_tag = ACC / g^{H(tag)}
        """
        if self.ACC is None:
            raise ValueError("Accumulator not initialized")

        witnesses = {}
        for tag in tag_set:
            witnesses[tag] = self.acc_membership_witness1(tag, DU_hkey)

        return witnesses

    # --------------------------------------------------------------------------------------------------------------
