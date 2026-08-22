from collections import defaultdict
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair


class accumulator:
    # =====================================================================
    # ADDITIVE POSITIVE BILINEAR ACCUMULATOR FUNCTIONS
    # =====================================================================
    # The initial accumulator value is the identity element of G1
    # Inputs are strings in {0,1}* mapped to ZR via group.hash
    # =====================================================================

    def __init__(self):
        self.acc_len = 0
        # the accumulator value (group element in G1)
        self.ACC_value = None
        # dictionary: tag_string -> group_element
        # Stores all accumulated tags for order-independent witness computation
        self.tag_list = []

    def acc_init(self, crs):
        """
        Initialize the accumulator with the identity element of G1.
        ACC = 1_{G1} = g^0
        """
        self.ACC_value = crs['g'] ** (crs['group'].init(ZR, 0))
        self.tag_list = []
        self.acc_len = 0
        return self.ACC_value

    # ------------------------------------------------------------------------------------------------------------
    # this function hashes a tag and outputs the corresponding group element
    @staticmethod
    def acc_hash_to_group(crs, tag_name: str):
        """
        Hash a tag to a group element.
        tag \in {0,1}*
        Returns: g^{H(tag)} \in G1
        """
        tag_group = crs['g'] ** (crs['group'].hash(str(tag_name), ZR))
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
        return set(self.tag_list)

    # ----------------------------------------------------------------------------------------------------------
    # to accumulate tags be it for single or batch puncturing
    def accumulate_tags(self, crs, DU_hkey, T_prime: set):
        """
        Stores the tags.
        """
        # initialize the accumulator
        if self.ACC_value is None:
            self.acc_init()

        # for each tag in the anonymous set T_prime
        for tag_name in T_prime:
            if tag_name not in DU_hkey['T']:
                # we ignore such a tag
                print(f"we ignore tag {tag_name} which is not in the user tag set \n\n")
                # raise ValueError(f"Tag '{tag_name}' is not in the user tag set")
                continue

            # for efficiency, we will keep the list of accumulated values
            # if not we will need to issue a witness to all accumulated values then perform an O(n) to check
            # whether an item has been previously accumulated
            if tag_name in self.tag_list:
                print(f"{tag_name} was already accumulated \n\n")
                continue  # already accumulated, skip
                # continue

            # else
            tag_group_element = self.acc_hash_to_group(crs, tag_name)
            #
            # we increase the lenght of the counter
            self.acc_len += 1
            # WE update the accumulator value
            self.ACC_value = self.ACC_value * tag_group_element
        return self.ACC_value

    # --------------------------------------------------------------------------------------------------------------
    def acc_serialize(self, crs) -> bytes:
        """Serialize the accumulator value."""
        if self.ACC_value is None:
            return None
        return crs['group'].serialize(self.ACC_value, compression=False)

    # --------------------------------------------------------------------------------------------------------------
    def acc_deserialize(self, crs, data: bytes):
        """Deserialize and set the accumulator value."""
        self.ACC_value = crs['group'].deserialize(data, compression=False)
        return self.ACC_value
