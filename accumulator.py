from collections import defaultdict
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair


class accumulator:
    # =====================================================================
    # ADDITIVE POSITIVE BILINEAR ACCUMULATOR FUNCTIONS
    # =====================================================================
    # The initial accumulator value is the identity element of G1
    # Inputs are strings in {0,1}* mapped to ZR via group.hash
    # =====================================================================

    def __init__(self, crs):
        self.acc_len = 0
        # the accumulator value (group element in G1)
        self.ACC_value = None
        self.crs = crs
        # dictionary: tag_string -> group_element
        # Stores all accumulated tags for order-independent witness computation
        self.tag_dict = {}

    def acc_init(self):
        """
        Initialize the accumulator with the identity element of G1.
        ACC = 1_{G1} = g^0
        """
        self.ACC_value = self.crs['g2'] ** (self.crs['group'].init(ZR, 0))
        self.tag_dict = {}
        self.acc_len = 0
        return self.ACC_value

    # ------------------------------------------------------------------------------------------------------------
    # this function hashes a tag and outputs the corresponding group element
    def acc_hash_to_group(self, tag_name: str):
        """
        Hash a tag to a group element.
        tag \in {0,1}*
        Returns: g^{H(tag)} \in G1
        """
        tag_group = self.crs['g2'] ** (self.crs['group'].hash(str(tag_name), ZR))
        return tag_group

    # -----------------------------------------------------------------------------------------------------------
    # getter for the accumulator value
    def acc_get_value(self):
        """Return the current accumulator value."""
        return self.ACC_value

    # -----------------------------------------------------------------------------------------------------------
    # return the number of tags accumulated
    def acc_get_size(self):
        """Return the number of accumulated tags."""
        return self.acc_len

    # ----------------------------------------------------------------------------------------------------------
    # return the set of accumulated tags
    def acc_get_tag_set(self):
        """Return the set of accumulated tag strings."""
        return set(self.tag_dict.keys())

    # ----------------------------------------------------------------------------------------------------------
    # this function accumulates tags into the accumulator
    # (single or batch tag puncturing)
    def accumulate_tags(self, tag_set: set):
        """
        Accumulate a set of tags into the accumulator.
        ACC_new = ACC_old \cdot \prod_{t \in tag_set} g^{H(t)}

        Parameters:
            tag_set: a set of tag strings in {0,1}*
        """
        if self.ACC_value is None:
            self.acc_init()

        for tag_name in tag_set:
            if tag_name in self.tag_dict:
                continue  # already accumulated, skip
            tag_group_element = self.acc_hash_to_group(tag_name)
            self.tag_dict[tag_name] = tag_group_element
            self.ACC_value = self.ACC_value * tag_group_element
            self.acc_len = self.acc_len + 1

        return self.ACC_value

    # ------------------------------------------------------------------------------------------------------------
    # this function removes tags from the accumulator
    def remove_tags(self, tag_set: set):
        """
        Remove a set of tags from the accumulator.
        ACC_new = ACC_old \cdot \prod_{t \in tag_set} (g^{H(t)})^{-1}
        """
        if self.ACC_value is None:
            raise ValueError("Accumulator not initialized")

        for tag_name in tag_set:
            if tag_name not in self.tag_dict:
                continue
            tag_group_element = self.tag_dict[tag_name]
            self.ACC_value = self.ACC_value * (tag_group_element ** -1)
            del self.tag_dict[tag_name]
            self.acc_len = self.acc_len - 1

        return self.ACC_value

    # --------------------------------------------------------------------------------------------------------------
    # to compute a positive membership witness from the set of tags where the cloud performs O(n) computation
    def acc_membership_witness1(self, tag: str):
        """
        Compute membership witness by iterating over all accumulated tags.
        W = \prod_{t \in tag_dict, t \neq tag} g^{H(t)}
        Order-independent due to commutativity of G1 multiplication.
        """
        if tag not in self.tag_dict:
            raise ValueError(f"Tag '{tag}' is not in the accumulated set")

        witness = self.crs['g'] ** self.crs['group'].init(ZR, 0)  # identity

        for t in self.tag_dict.keys():
            if t != tag:
                witness = witness * self.tag_dict[t]

        return witness

    # --------------------------------------------------------------------------------------------------------------
    def acc_membership_witness2(self, tag: str):
        """
        Compute membership witness using the current accumulator value.
        W = ACC \cdot (g^{H(tag)})^{-1}
        Efficient O(1) computation.
        """
        if self.ACC_value is None:
            raise ValueError("Accumulator not initialized")

        if tag not in self.tag_dict:
            raise ValueError(f"Tag '{tag}' is not in the accumulated set")

        tag_group_element = self.tag_dict[tag]
        witness = self.ACC_value * (tag_group_element ** -1)
        return witness

    # --------------------------------------------------------------------------------------------------------------
    def acc_verify_membership1(self, tag: str, witness, acc_value=None) -> bool:
        """
        Verify that 'tag' is in the accumulator using witness W.
        Direct verification: W \cdot g^{H(tag)} == ACC_value
        """
        if acc_value is None:
            acc_value = self.ACC_value
        if acc_value is None:
            raise ValueError("Accumulator not initialized")

        if tag not in self.tag_dict:
            return False

        tag_group_element = self.tag_dict[tag]
        return (witness * tag_group_element) == acc_value

    # --------------------------------------------------------------------------------------------------------------
    def acc_verify_membership_with_pairing(self, tag: str, witness, acc_value=None) -> bool:
        """
        Bilinear pairing-based verification:
        e(W \cdot g^{H(tag)}, g) == e(ACC, g)
        """
        if acc_value is None:
            acc_value = self.ACC_value
        if acc_value is None:
            raise ValueError("Accumulator not initialized")

        if tag not in self.tag_dict:
            return False

        tag_group_element = self.tag_dict[tag]

        left_pair = pair(witness * tag_group_element, self.crs['g'])
        right_pair = pair(acc_value, self.crs['g'])

        return left_pair == right_pair

    # --------------------------------------------------------------------------------------------------------------
    def acc_batch_witnesses(self) -> dict:
        """
        Compute membership witnesses for ALL accumulated tags.
        Returns a dictionary: {tag: witness}
        Uses efficient O(1) per-tag computation.
        """
        if self.ACC_value is None:
            raise ValueError("Accumulator not initialized")

        witnesses = {}
        for tag in self.tag_dict.keys():
            witnesses[tag] = self.acc_membership_witness2(tag)

        return witnesses

    # --------------------------------------------------------------------------------------------------------------
    def acc_serialize(self) -> bytes:
        """Serialize the accumulator value."""
        if self.ACC_value is None:
            return None
        return self.crs['group'].serialize(self.ACC_value, compression=False)

    # --------------------------------------------------------------------------------------------------------------
    def acc_deserialize(self, data: bytes):
        """Deserialize and set the accumulator value."""
        self.ACC_value = self.crs['group'].deserialize(data, compression=False)
        return self.ACC_value
