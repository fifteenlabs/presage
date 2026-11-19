//! What a write of our own profile sends.

use libsignal_service::profile_name::ProfileName;

/// Our whole profile, as one write sends it.
///
/// The server keeps nothing a write leaves out, so a caller changing one field
/// passes the others as they are. The payment address and phone number sharing
/// are the exception: the write carries them over itself.
#[derive(Debug, Clone)]
pub struct ProfileEdit {
    pub name: ProfileName<String>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
    pub avatar: AvatarEdit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvatarEdit {
    Keep,
    Remove,
    /// The image to show, as uploaded: the caller sizes and encodes it.
    Set(Vec<u8>),
}
