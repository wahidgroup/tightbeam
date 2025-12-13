use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
	let args: Vec<String> = env::args().collect();
	let mut output_dir = "built".to_string();

	for (i, arg) in args.iter().enumerate() {
		match arg.as_str() {
			"--output-dir" => {
				if i + 1 < args.len() {
					output_dir = args[i + 1].clone();
				}
			}
			"--test" => {}
			"--help" => {
				println!("Usage: generate_feature_tests [--output-dir DIR]");
				return;
			}
			_ => {}
		}
	}

	// Parse features from tightbeam/Cargo.toml
	let cargo_toml_path = "tightbeam/Cargo.toml";
	let cargo_content = fs::read_to_string(cargo_toml_path).expect("Failed to read tightbeam/Cargo.toml");

	let mut all_features = Vec::new();
	let mut in_features_section = false;

	for line in cargo_content.lines() {
		let trimmed = line.trim();
		if trimmed == "[features]" {
			in_features_section = true;
			continue;
		}
		if trimmed.starts_with('[') && trimmed != "[features]" {
			in_features_section = false;
		}
		if in_features_section && !trimmed.is_empty() && !trimmed.starts_with('#') {
			if let Some(feature_name) = trimmed.split('=').next() {
				let feature = feature_name.trim();
				// Skip default, full, quoted strings, and dependency specifications
				if feature != "default" 
					&& feature != "full"
					&& !feature.starts_with('"')
					&& !feature.contains(']')
					&& !feature.contains('/')
					&& !feature.contains('?') {
					all_features.push(feature.to_string());
				}
			}
		}
	}

	let mut combinations: Vec<Vec<String>> = Vec::new();

	// Generate incremental combinations (1 feature, then 2, then 3, etc.)
	for i in 1..=all_features.len() {
		let mut combo = Vec::new();
		for j in 0..i {
			combo.push(all_features[j].clone());
		}
		combinations.push(combo);
	}

	// Ensure "testing" is always included
	let mut filtered_combinations = Vec::new();
	for combo in &combinations {
		if !combo.contains(&"testing".to_string()) {
			let mut test_combo = combo.clone();
			test_combo.push("testing".to_string());
			filtered_combinations.push(test_combo);
		} else {
			filtered_combinations.push(combo.clone());
		}
	}
	combinations = filtered_combinations;
	// Add testing-only combination
	combinations.insert(0, vec!["testing".to_string()]);

	// Create output directory
	fs::create_dir_all(&output_dir).expect("Failed to create output directory");

	let script_name = "test_all_features.sh";
	let script_path = Path::new(&output_dir).join(script_name);
	let mut file = fs::File::create(&script_path).expect("Failed to create script file");

	writeln!(file, "#!/bin/bash").unwrap();
	writeln!(file, "set -e").unwrap();
	writeln!(file, "").unwrap();

	for features in &combinations {
		if features.is_empty() {
			writeln!(file, "make test --no-default-features").unwrap();
		} else {
			writeln!(
				file,
				"make test no-default=true features=\"{}\"",
				features.join(",")
			)
			.unwrap();
		}
	}

	println!(
		"Generated {} with {} feature combinations",
		script_path.display(),
		combinations.len()
	);
}
