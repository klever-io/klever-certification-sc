use klever_sc_scenario::*;

fn world() -> ScenarioWorld {
    let mut blockchain = ScenarioWorld::new();
    // blockchain.set_current_dir_from_workspace("relative path to your workspace, if applicable");

    blockchain.register_contract("file:output/issuer.wasm", issuer::ContractBuilder);
    blockchain
}

#[test]
fn issuer_should_work_1_field_rs() {
    world().run("scenarios/issuer_should_work_1_field.scen.json");
}

#[test]
fn issuer_should_work_max_field_rs() {
    world().run("scenarios/issuer_should_work_max_field.scen.json");
}

#[test]
fn issuer_should_fail_wrong_field_rs() {
    world().run("scenarios/issuer_should_fail_field.scen.json");
}

