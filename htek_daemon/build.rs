use std::{collections::HashMap, env, fs, process, thread};

fn parse_build_param_str(toml: &str, params: &mut HashMap<String, String>) {
    for line in toml.split('\n') {
        let mut kv_str = line.trim();
        if let Some((x, _)) = line.split_once('#') {
            kv_str = x.trim();
        }
        if let Some((k, v)) = kv_str.split_once("=") {
            params.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
}

fn load_build_params() -> HashMap<String, String> {
    let mut build_params: HashMap<String, String> = HashMap::new();

    let bp_str = fs::read_to_string("build-params.toml").expect("build-params.toml can't be read");
    parse_build_param_str(&bp_str, &mut build_params);

    match thread::available_parallelism() {
        Ok(cores) => build_params.insert("NUM_CORES".to_string(), format!("{}", cores)),
        Err(e) => panic!("Failed to get core count: {}", e),
    };

    for (k, v) in build_params.iter_mut() {
        let target_envvar = format!("HTEK_BP_{}", k);

        match env::var(&target_envvar) {
            Ok(r) => *v = r,
            Err(e) => {
                if format!("{e}").contains("environment variable not found") {
                    continue;
                }
                panic!("{e} ({})", target_envvar);
            }
        }
    }

    let _ = fs::write("../build/build_params.log", format!("{:#?}", build_params));
    build_params
}

fn rs_infer_type(key: &str, value: &str) -> &'static str {
    if value.chars().all(|i| "0123456789".contains(i)) {
        return "usize";
    }

    if value.chars().skip(1).all(|i| "0123456789".contains(i)) && value.starts_with("-") {
        return "isize";
    }

    if value.starts_with('"') && value.ends_with('"') {
        return "&'static str";
    }

    if ["true", "false"].contains(&value) {
        return "bool";
    }

    eprintln!("Bad build parameter {}={}", key, value);
    process::exit(1);
}

fn generate_const_rs(build_params: &HashMap<String, String>) {
    let filename = "src/build_params.rs";

    let mut payload = "#![allow(unused)]\n".to_string();
    for (k, v) in build_params.iter() {
        let type_str = rs_infer_type(k, v);
        payload.push_str(&format!("pub const {}: {} = {};\n", k, type_str, v));
    }

    fs::write(filename, payload).unwrap();
}

fn generate_const_c(build_params: &HashMap<String, String>) {
    let filename = "if_bpf/build_params.h";

    let mut payload = String::new();
    for (k, v) in build_params.iter() {
        payload.push_str(&format!("#define {} ({})\n", k, v));
    }

    fs::write(filename, payload).unwrap();
}

fn check_params(_build_params: &HashMap<String, String>) {
    // TODO
}

fn generate_consts(build_params: &HashMap<String, String>) {
    check_params(build_params);
    generate_const_rs(build_params);
    generate_const_c(build_params);
}

fn build_cbpfmap() {
    cc::Build::new()
        .compiler("clang")
        .opt_level(2)
        .file("src/bpf/cbpfmap.c")
        .compile("cbpfmap");

    println!("cargo:rustc-link-lib=bpf");
}

fn main() {
    println!("cargo:rerun-if-changed=build-params.toml");
    println!("cargo:rerun-if-changed=src/bpf/cbpfmap.c");

    watch_envs();

    let build_params = load_build_params();
    generate_consts(&build_params);
    build_cbpfmap();
}

fn watch_envs() {
    println!("cargo:rerun-if-env-changed=HTEK_BP_RING_BUF_SIZE_LOG2");
    println!("cargo:rerun-if-env-changed=HTEK_BP_ASSERTS");
    println!("cargo:rerun-if-env-changed=HTEK_BP_PERF_TRACKING");
    println!("cargo:rerun-if-env-changed=HTEK_BP_CANARY");
    println!("cargo:rerun-if-env-changed=HTEK_BP_NUM_CORES");
}
