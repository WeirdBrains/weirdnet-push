use crate::api::Transport;
use crate::error::{Error, Result};
use crate::handle::{ControlSecret, WakeHandle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One device registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// How to reach it.
    pub transport: Transport,
    /// SHA-256 of the control secret, hex.
    pub control: String,
    /// Unix seconds.
    pub created: u64,
}

impl Registration {
    pub(crate) fn new(transport: Transport, control: &ControlSecret) -> Self {
        let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self { transport, control: control.digest(), created }
    }
}

/// Registrations by handle digest, in a JSON file written atomically on every change.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    max: usize,
    map: Mutex<HashMap<String, Registration>>,
}

impl Store {
    /// Opens (or creates) the file.
    pub fn open(path: &Path, max: usize) -> Result<Self> {
        let map = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path: path.to_path_buf(), max, map: Mutex::new(map) })
    }

    fn save(&self, map: &HashMap<String, Registration>) -> Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let tmp = self.path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&serde_json::to_vec(map).unwrap())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// How many registrations there are.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    /// True if there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The registration for a handle.
    pub fn get(&self, h: &WakeHandle) -> Option<Registration> {
        self.map.lock().unwrap().get(&h.digest()).cloned()
    }

    pub(crate) fn insert(&self, h: &WakeHandle, r: Registration) -> Result<()> {
        let mut m = self.map.lock().unwrap();
        if m.len() >= self.max {
            return Err(Error::Invalid("this server is full".into()));
        }
        m.insert(h.digest(), r);
        self.save(&m)
    }

    pub(crate) fn replace(&self, old: &WakeHandle, new: &WakeHandle, r: Registration) -> Result<()> {
        let mut m = self.map.lock().unwrap();
        m.remove(&old.digest()).ok_or(Error::Gone)?;
        m.insert(new.digest(), r);
        self.save(&m)
    }

    pub(crate) fn remove(&self, h: &WakeHandle) -> Result<()> {
        let mut m = self.map.lock().unwrap();
        if m.remove(&h.digest()).is_some() {
            self.save(&m)?;
        }
        Ok(())
    }
}
