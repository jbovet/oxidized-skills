use std::path::Path;

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Config {
    pub allowlist: AllowlistConfig,
    pub strict: StrictConfig,
    pub scanners: ScannersConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct AllowlistConfig {
    pub registries: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct StrictConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ScannersConfig {
    pub shellcheck: bool,
    pub semgrep: bool,
    pub secrets: bool,
    pub prompt: bool,
    pub bash_patterns: bool,
    pub package_install: bool,
    pub frontmatter: bool,
}

impl AllowlistConfig {
    /// Normalize all entries to lowercase in-place.
    ///
    /// Called once at config load time so that scanners can compare against
    /// pre-lowercased values without allocating on every line they scan.
    pub fn normalize(&mut self) {
        for s in &mut self.registries {
            *s = s.to_lowercase();
        }
        for s in &mut self.domains {
            *s = s.to_lowercase();
        }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        // Values are already lowercase; normalize() is a no-op for the default.
        AllowlistConfig {
            registries: vec![
                "registry.npmjs.org".to_string(),
                "pypi.org".to_string(),
                "files.pythonhosted.org".to_string(),
            ],
            domains: vec![
                "registry.npmjs.org".to_string(),
                "npmjs.org".to_string(),
                "github.com".to_string(),
                "githubusercontent.com".to_string(),
                "pypi.org".to_string(),
            ],
        }
    }
}

impl Default for ScannersConfig {
    fn default() -> Self {
        ScannersConfig {
            shellcheck: true,
            semgrep: true,
            secrets: true,
            prompt: true,
            bash_patterns: true,
            package_install: true,
            frontmatter: true,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Config, String> {
        let config_path = if let Some(p) = path {
            if p.exists() {
                Some(p.to_path_buf())
            } else {
                return Err(format!("Config file not found: {}", p.display()));
            }
        } else {
            let default_path = Path::new("oxidized-skills.toml");
            if default_path.exists() {
                Some(default_path.to_path_buf())
            } else {
                None
            }
        };

        match config_path {
            Some(path) => {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;
                let mut config: Config = toml::from_str(&content)
                    .map_err(|e| format!("Failed to parse config {}: {}", path.display(), e))?;
                // Normalize allowlist entries to lowercase once at load time so
                // scanners can skip per-call lowercasing in hot loops.
                config.allowlist.normalize();
                Ok(config)
            }
            None => Ok(Config::default()),
        }
    }

    pub fn is_scanner_enabled(&self, name: &str) -> bool {
        match name {
            "shellcheck" => self.scanners.shellcheck,
            "semgrep" => self.scanners.semgrep,
            "secrets" => self.scanners.secrets,
            "prompt" => self.scanners.prompt,
            "bash_patterns" => self.scanners.bash_patterns,
            "package_install" => self.scanners.package_install,
            "frontmatter" => self.scanners.frontmatter,
            _ => true,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SuppressionFile {
    pub suppress: Vec<Suppression>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Suppression {
    pub rule: String,
    pub file: String,
    pub lines: Option<String>,
    pub reason: String,
    pub ticket: Option<String>,
}

pub fn load_suppressions(skill_path: &Path) -> Vec<Suppression> {
    let ignore_path = skill_path.join(".oxidized-skills-ignore");
    if !ignore_path.exists() {
        return vec![];
    }

    let content = match std::fs::read_to_string(&ignore_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    match toml::from_str::<SuppressionFile>(&content) {
        Ok(file) => file.suppress,
        Err(e) => {
            eprintln!("Warning: failed to parse .oxidized-skills-ignore: {e}");
            vec![]
        }
    }
}
