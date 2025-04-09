use klever_sc_scenario::*;

fn world() -> ScenarioWorld {
    let mut blockchain = ScenarioWorld::new();

    blockchain.register_contract("file:output/issuer.wasm", issuer::ContractBuilder);
    blockchain
}

// Create Tests

#[test]
fn issuer_create_rs() {
    world().run("scenarios/issuer_create.scen.json");
}

// Proof Tests

#[test]
fn issuer_proof_rs() {
    world().run("scenarios/issuer_proof.scen.json");
}

// Revoke Tests

#[test]
fn issuer_revoke_rs() {
    world().run("scenarios/issuer_revoke.scen.json");
}

// Change Expiration Date Tests

#[test]
fn issuer_change_expiration_date_rs() {
    world().run("scenarios/issuer_change_expiration_date.scen.json");
}
