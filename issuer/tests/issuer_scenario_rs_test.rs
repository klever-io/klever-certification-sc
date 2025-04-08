use klever_sc_scenario::*;

fn world() -> ScenarioWorld {
    let mut blockchain = ScenarioWorld::new();

    blockchain.register_contract("file:output/issuer.wasm", issuer::ContractBuilder);
    blockchain
}

// Create and Proof Tests

#[test]
fn issuer_should_fail_proof_rs() {
    world().run("scenarios/issuer_should_fail_proof.scen.json");
}


#[test]
fn issuer_should_work_1_field_proof_rs() {
    world().run("scenarios/issuer_should_work_1_field_proof.scen.json");
}

#[test]
fn issuer_should_work_max_field_proof_rs() {
    world().run("scenarios/issuer_should_work_max_field_proof.scen.json");
}

#[test]
fn issuer_should_work_zero_expiration_rs() {
    world().run("scenarios/issuer_should_work_zero_expiration.json");
}

// Revoke Tests

#[test]
fn issuer_should_work_revoke_rs() {
    world().run("scenarios/issuer_should_work_revoke.scen.json");
}

#[test]
fn issuer_should_fail_revoke_rs() {
    world().run("scenarios/issuer_should_fail_revoke.scen.json");
}

// Change Expiration Date Tests

#[test]
fn issuer_change_expiration_date_rs() {
    world().run("scenarios/issuer_change_expiration_date.scen.json");
}
