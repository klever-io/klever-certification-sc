#![no_std]


klever_sc::derive_imports!();
klever_sc::imports!();


//  Certificatie struct
#[derive(TopEncode, TopDecode, TypeAbi, PartialEq, Eq, Clone)]
struct Certificate<M: ManagedTypeApi> {
    pub certificate_id: [u8; 32],
    pub issuer: ManagedAddress<M>,
    pub issuance_date: u64,
    pub expiration_date: u64,
    pub is_valid: bool,
    pub merkle_root: [u8; 32],
}

// #[derive(TopEncode, TopDecode, TypeAbi, PartialEq, Eq, Clone, Copy)]
// struct Audit{
//     pub issuance_date: u64,
//     pub expiration_date: u64,
//     pub is_valid: bool,
// }

// Leaf struct
// Leaf struct
#[derive(TopEncode, TopDecode, TypeAbi, PartialEq, Eq, Clone, Copy)]
struct Leaf {
    hash: [u8; 32],
    salt: [u8; 32],
}

// Max leaves per tree
const MAX_LEAVES: usize = 32;
const BATCH_SIZE: usize = 32;

#[klever_sc::contract]
pub trait Issuer {

    #[storage_mapper("trees")]
    fn trees(&self, certification_id: [u8; 32]) -> VecMapper<Leaf>;

    #[storage_mapper("roots")]
    fn roots(&self, certification_id: [u8; 32]) -> SingleValueMapper<[u8; 32]>;

    #[storage_mapper("certificates")]
    fn certifications(&self, certificate_id: [u8; 32]) -> SingleValueMapper<Certificate<Self::Api>>;
    

    #[init]
    fn init(&self) {
    }

    fn sort_and_hash_two_nodes(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let (first, second) = if left <= right { (left, right) } else { (right, left) };
        let mut input: ManagedBuffer = ManagedBuffer::new_from_bytes(first);
        input.append_bytes(second);
        self.crypto().keccak256(input).to_byte_array()
    }

    fn create_certificate_id(&self, data: &[u8], block_timestamp: u64) -> [u8; 32] {
        let mut mb = ManagedBuffer::new_from_bytes(data);
        mb.append(&ManagedBuffer::new_from_bytes(&block_timestamp.to_be_bytes()));
    
        self.crypto().keccak256(mb).to_byte_array()
    }

    fn compute_merkle_tree(&self, certificate_id: [u8; 32],leafs: &[u8], salt:[u8;32]) -> [u8; 32] {
        let mut tree = self.trees(certificate_id);

        let mut current_level: [[u8; 32]; MAX_LEAVES] = [[0; 32]; MAX_LEAVES];
        let mut next_level: [[u8; 32]; MAX_LEAVES] = [[0; 32]; MAX_LEAVES];
        let mut current_level_size = leafs.len() / BATCH_SIZE;

        for i in 0..current_level_size {
            let mut leaf = [0; 32];
            // copy from leafs
            leaf.copy_from_slice(&leafs[BATCH_SIZE * i..BATCH_SIZE * (i + 1)]);
            // leaf = self.hash_leaf(leaf, salt);

            tree.push(&Leaf {
                hash: leaf,
                salt,
            });

            current_level[i] = leaf;
        }
        
        while current_level_size > 1 {
            let mut next_level_size = 0;
            let mut i = 0;

            while i < current_level_size {
                if i + 1 < current_level_size {
                    let (left, right) = (current_level[i], current_level[i + 1]);
                    next_level[next_level_size] = self.sort_and_hash_two_nodes(&left, &right);
                } else {
                    next_level[next_level_size] = current_level[i];
                }
                next_level_size += 1;
                i += 2;
            }

            current_level_size = next_level_size;
            current_level[..current_level_size].copy_from_slice(&next_level[..next_level_size]);
        }
        let root = current_level[0];

        root
    }

        // fn get_proof(&self, certificate_id: [u8; 32], data: [u8; 32]) -> ArrayVec<[u8; 32], MAX_LEAVES> {
    fn get_proof(&self, certificate_id: [u8; 32], data: [u8; 32])  {
        let leaves = self.trees(certificate_id);

        // leaves[0].hash;

        let leaf_index = leaves.iter().position(|x| x.hash == data).expect("Leaf not found");

        let mut _current_level: ArrayVec<[u8; 32], MAX_LEAVES> = ArrayVec::new();
        let mut _next_level: ArrayVec<[u8; 32], MAX_LEAVES> = ArrayVec::new();
        let mut _proof: ArrayVec<[u8; 32], MAX_LEAVES> = ArrayVec::new();
        let mut _current_index = leaf_index;
        let mut _current_level_size = leaves.len();

        // for i in 0..current_level_size {
        //     current_level.push(leaves.get(i + 1).hash);
        // }

        // while current_level_size > 1 {
        //     let mut next_level_size = 0;
        //     let mut i = 0;

        //     while i < current_level_size {
        //         if i + 1 < current_level_size {
        //             let (left, right) = (current_level[i], current_level[i + 1]);
        //             if i == current_index || i + 1 == current_index {
        //                 proof.push(if i == current_index { right } else { left });
        //             }
        //             next_level.push(self.sort_and_hash_two_nodes(&left, &right));
        //         } else {
        //             next_level.push(current_level[i]);
        //         }
        //         next_level_size += 1;
        //         i += 2;
        //     }

        //     current_level.clear();
        //     current_level.try_extend_from_slice(&next_level[..next_level_size]).unwrap();
        //     next_level.clear();
        //     current_level_size = next_level_size;
        //     current_index /= 2;
        // }

        // proof
    }

    fn verify_proof(&self, leaf_hash: [u8; 32], proof: ArrayVec<[u8; 32], MAX_LEAVES>, root: [u8; 32]) -> bool {
        let mut computed_hash = leaf_hash;

        for proof_element in proof.iter() {
            computed_hash = self.sort_and_hash_two_nodes(&computed_hash, proof_element);
        }

        computed_hash == root
    }

    fn hash_leaf(&self, data: [u8; 32], _salt: [u8; 32]) -> [u8; 32] {
        data
    }

    #[endpoint(messejana)]
    fn create_certificate(&self, hashes: &[u8]) -> [u8; 32] {
        require!(hashes.len() <= MAX_LEAVES*BATCH_SIZE, "certicate limited to 32 fields");
        require!(hashes.len() % BATCH_SIZE == 0, "wrong data length");
        
        let block_timestamp = self.blockchain().get_block_timestamp();

        let certificate_id : [u8; 32] = self.create_certificate_id(hashes, block_timestamp);

        let root = self.compute_merkle_tree(certificate_id,&hashes,[0;32]);

        self.roots(certificate_id).set(root);
        
        self.certifications(certificate_id).set(Certificate {
            certificate_id: certificate_id,
            issuer: self.blockchain().get_caller(),
            issuance_date: block_timestamp,
            expiration_date: 0,
            is_valid: true,
            merkle_root: root,
        });

        certificate_id
    }

    #[endpoint(val)]
    fn get_valid(&self, certificate_id: [u8; 32]) -> [u8; 32] {
        let leaves = self.trees(certificate_id);
        
        let leaf = leaves.get(1);
        leaf.hash
    }

    // #[view]
    // fn check_certificate(&self,certificate_id: [u8; 32]) -> bool {
    //     let certificate = self.certifications(certificate_id).get();

    //     certificate.is_valid
    // }

    // #[only_owner]
    // #[endpoint]
    // fn revoke_certificate(self,certificate_id: [u8; 32]) {
    //     self.certifications(certificate_id).update(|certificate| {
    //         certificate.is_valid = false;
    //         certificate.expiration_date = self.blockchain().get_block_timestamp();
    //     });
    // }

    // #[view]
    // fn audit_certificate(&self,certificate_id: [u8; 32]) -> Audit {
    //     let certificate = self.certifications(certificate_id).get();

    //     Audit { issuance_date: certificate.issuance_date,
    //             expiration_date: certificate.expiration_date,
    //             is_valid: certificate.is_valid
    //         }
    // }

    #[endpoint(parangaba)]
    fn proof_certificate(&self,certificate_id: [u8; 32],data: [u8; 32], salt: [u8; 32]) -> bool { 
        let hash = self.hash_leaf(data, salt);
        let _proof = self.get_proof(certificate_id, hash);
        // let root = self.roots(certificate_id).get();
        // self.verify_proof(hash, proof, root)
        true
    }
}
