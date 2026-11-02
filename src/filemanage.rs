//! Cross-platform filesystem and search-path utilities corresponding to
//! Ghidra's FileManage support layer.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameMatch {
    Prefix,
    Suffix,
}

/// Ordered search paths for resolving processor specifications and resources.
#[derive(Clone, Debug, Default)]
pub struct FileManage {
    path_list: Vec<PathBuf>,
}

impl FileManage {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a directory to the end of the search path. Empty paths are ignored.
    pub fn add_dir_to_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        if !path.as_os_str().is_empty() {
            self.path_list.push(path.to_path_buf());
        }
    }
    pub fn add_current_dir(&mut self) -> io::Result<()> {
        self.path_list.push(std::env::current_dir()?);
        Ok(())
    }
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.path_list
    }
    /// Resolve an absolute file directly, or search configured paths in order.
    pub fn find_file(&self, name: impl AsRef<Path>) -> Option<PathBuf> {
        let name = name.as_ref();
        if name.as_os_str().is_empty() {
            return None;
        }
        if name.is_absolute() {
            return name.is_file().then(|| name.to_path_buf());
        }
        self.path_list.iter().map(|dir| dir.join(name)).find(|p| p.is_file())
    }
    /// Find entries matching a prefix or suffix across all search directories.
    /// Hidden entries are excluded and results are sorted and deduplicated.
    pub fn match_list(&self, pattern: &str, how: NameMatch) -> io::Result<Vec<PathBuf>> {
        let mut result = Vec::new();
        for dir in &self.path_list {
            Self::match_list_dir(&mut result, pattern, how, dir, false)?;
        }
        result.sort();
        result.dedup();
        Ok(result)
    }
    pub fn match_list_dir(
        result: &mut Vec<PathBuf>,
        pattern: &str,
        how: NameMatch,
        directory: impl AsRef<Path>,
        allow_hidden: bool,
    ) -> io::Result<()> {
        let entries = match fs::read_dir(directory.as_ref()) {
            Ok(entries) => entries,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
                Err(e) => return Err(e),
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !allow_hidden && name.starts_with('.') {
                continue;
            }
            let matched = match how {
                NameMatch::Prefix => name.starts_with(pattern),
                NameMatch::Suffix => name.ends_with(pattern),
            };
            if matched {
                result.push(entry.path());
            }
        }
        Ok(())
    }
    /// List immediate child directories, optionally including hidden entries.
    pub fn directory_list(directory: impl AsRef<Path>, allow_hidden: bool) -> io::Result<Vec<PathBuf>> {
        let mut result = Vec::new();
        let entries = match fs::read_dir(directory.as_ref()) {
            Ok(entries) => entries,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(result);
            }
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
                Err(e) => return Err(e),
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == "." || name == ".." || (!allow_hidden && name.starts_with('.')) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                result.push(entry.path());
            }
        }
        result.sort();
        Ok(result)
    }
    /// Bounded recursive search for directories with an exact basename.
    /// Matching directories are returned but are not traversed further.
    pub fn scan_directory_recursive(
        match_name: &str,
        root: impl AsRef<Path>,
        max_depth: usize,
    ) -> io::Result<Vec<PathBuf>> {
        fn visit(name: &str, root: &Path, depth: usize, out: &mut Vec<PathBuf>) -> io::Result<()> {
            if depth == 0 {
                return Ok(());
            }
            for child in FileManage::directory_list(root, false)? {
                if child.file_name().and_then(|s| s.to_str()) == Some(name) {
                    out.push(child);
                } else {
                    visit(name, &child, depth - 1, out)?;
                }
            }
            Ok(())
        }
        let mut result = Vec::new();
        visit(match_name, root.as_ref(), max_depth, &mut result)?;
        result.sort();
        Ok(result)
    }
    /// Split into parent path and basename. A trailing separator is ignored.
    pub fn split_path(full: impl AsRef<Path>) -> (PathBuf, String) {
        let text = full.as_ref().to_string_lossy();
        let trimmed = text.trim_end_matches(|c| c == '/' || c == '\\');
        if trimmed.is_empty() {
            return (PathBuf::from(std::path::MAIN_SEPARATOR.to_string()), String::new());
        }
        match trimmed.rfind(|c| c == '/' || c == '\\') {
            Some(index) => {
                let parent = if index == 0 { &trimmed[..1] } else { &trimmed[..index] };
                (PathBuf::from(parent), trimmed[index + 1..].to_string())
            }
            None => (PathBuf::new(), trimmed.to_string()),
        }
    }
    /// Conservative discovery of a Ghidra checkout or installed distribution.
    pub fn discover_ghidra_root(argv0: impl AsRef<Path>) -> Option<PathBuf> {
        let executable = argv0.as_ref();
        let executable = if executable.is_absolute() {
            executable.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(executable)
        };
        for ancestor in executable.ancestors() {
            if ancestor.file_name().and_then(|s| s.to_str()) != Some("Ghidra") {
                continue;
            }
            let root = ancestor.parent()?.to_path_buf();
            if root.join("ghidra.git").is_dir() || root.join("server").join("server.conf").is_file() {
                return Some(root);
            }
        }
        None
    }
}
pub fn is_directory(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}
pub fn is_separator(character: char) -> bool {
    character == '/' || character == '\\'
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("ghidra-filemanage-{}-{nonce}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn resolves_files_in_search_order_and_absolute_paths() {
        let root = TestDir::new();
        let first = root.0.join("first");
        let second = root.0.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("processor.sla"), b"first").unwrap();
        fs::write(second.join("processor.sla"), b"second").unwrap();
        let mut manager = FileManage::new();
        manager.add_dir_to_path(&first);
        manager.add_dir_to_path(&second);
        assert_eq!(manager.find_file("processor.sla"), Some(first.join("processor.sla")));
        assert_eq!(
            manager.find_file(second.join("processor.sla")),
            Some(second.join("processor.sla"))
        );
        assert_eq!(manager.find_file("missing.sla"), None);
    }
    #[test]
    fn matches_prefix_and_suffix_and_skips_hidden_entries() {
        let root = TestDir::new();
        fs::write(root.0.join("x86.sla"), b"").unwrap();
        fs::write(root.0.join("arm.sla"), b"").unwrap();
        fs::write(root.0.join(".hidden.sla"), b"").unwrap();
        let mut manager = FileManage::new();
        manager.add_dir_to_path(&root.0);
        assert_eq!(manager.match_list("x86", NameMatch::Prefix).unwrap().len(), 1);
        assert_eq!(manager.match_list(".sla", NameMatch::Suffix).unwrap().len(), 2);
    }
    #[test]
    fn directory_scan_obeys_depth_limit() {
        let root = TestDir::new();
        fs::create_dir_all(root.0.join("one").join("Ghidra")).unwrap();
        fs::create_dir_all(root.0.join("two").join("deep").join("Ghidra")).unwrap();
        fs::create_dir_all(root.0.join(".hidden")).unwrap();
        assert_eq!(FileManage::directory_list(&root.0, false).unwrap().len(), 2);
        assert_eq!(
            FileManage::scan_directory_recursive("Ghidra", &root.0, 3)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            FileManage::scan_directory_recursive("Ghidra", &root.0, 2)
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn splits_paths_and_recognizes_both_separators() {
        let (parent, base) = FileManage::split_path("languages/x86/");
        assert_eq!(parent, PathBuf::from("languages"));
        assert_eq!(base, "x86");
        assert!(is_separator('/'));
        assert!(is_separator('\\'));
        assert!(!is_separator(':'));
    }
}
