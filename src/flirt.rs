//! FLIRT signature matching integrated with the program database.
use crate::{Error, Program, Result};
use fast_flirt::FlirtSet;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct FlirtOptions {
    /// Maximum number of bytes read from one function for matching.
    pub max_function_bytes: u64,
    /// Rename only automatically named functions when a public FLIRT name is found.
    pub rename_automatic_functions: bool,
}

impl Default for FlirtOptions {
    fn default() -> Self {
        Self {
            max_function_bytes: 1024 * 1024,
            rename_automatic_functions: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlirtMatch {
    pub address: u64,
    pub previous_name: String,
    pub library_name: String,
    pub function_size: u64,
    pub renamed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlirtReport {
    pub signatures_loaded: usize,
    pub functions_scanned: usize,
    pub matches: Vec<FlirtMatch>,
    pub failures: Vec<String>,
}

/// An immutable, shareable FLIRT corpus. Load it once and reuse it across programs.
pub struct FlirtAnalyzer {
    signatures: FlirtSet,
}

impl FlirtAnalyzer {
    pub fn load_dir(path: impl AsRef<Path>) -> Result<Self> {
        let signatures = FlirtSet::load_dir(path)
            .map_err(|error| Error::Lowlevel(format!("failed to load FLIRT signatures: {error}")))?;
        Ok(Self { signatures })
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn analyze(&self, program: &mut Program, options: &FlirtOptions) -> Result<FlirtReport> {
        let functions = program.functions()?;
        let mut report = FlirtReport {
            signatures_loaded: self.signatures.len(),
            ..FlirtReport::default()
        };

        for function in functions {
            let size = match program.function_size(function.address) {
                Ok(size) if size > 0 => size,
                Ok(_) => continue,
                Err(error) => {
                    report.failures.push(format!(
                        "{:#x} ({}): could not determine function size: {}",
                        function.address,
                        function.name,
                        error.explain()
                    ));
                    continue;
                }
            };
            let read_len = size.min(options.max_function_bytes);
            let bytes = match program.read_code(function.address, read_len) {
                Ok(bytes) => bytes,
                Err(error) => {
                    report.failures.push(format!(
                        "{:#x} ({}): could not read function bytes: {}",
                        function.address,
                        function.name,
                        error.explain()
                    ));
                    continue;
                }
            };
            report.functions_scanned += 1;

            let Some(library_name) = self.signatures.match_public_name(&bytes).map(str::to_owned) else {
                continue;
            };

            let automatic = matches!(
                function.source,
                crate::program::FunctionSource::Discovered | crate::program::FunctionSource::Requested
            ) || ["FUN_", "sub_", "func_", "thunk_", "unknown_"]
                .iter()
                .any(|prefix| function.name.starts_with(prefix));

            let renamed = if options.rename_automatic_functions && automatic {
                match program.set_function_name(function.address, &library_name) {
                    Ok(()) => true,
                    Err(error) => {
                        report.failures.push(format!(
                            "{:#x}: FLIRT identified {library_name}, but renaming failed: {}",
                            function.address,
                            error.explain()
                        ));
                        false
                    }
                }
            } else {
                false
            };

            report.matches.push(FlirtMatch {
                address: function.address,
                previous_name: function.name,
                library_name,
                function_size: size,
                renamed,
            });
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_are_bounded_and_conservative() {
        let options = FlirtOptions::default();
        assert_eq!(options.max_function_bytes, 1024 * 1024);
        assert!(options.rename_automatic_functions);
    }
}
