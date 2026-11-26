//! The account's privacy settings: reading them from the `AccountRecord`, and
//! changing them everywhere Signal keeps a copy.
//!
//! Most of these settings live only in the storage service, where every device
//! reads them. Two also have a copy outside it, and a change has to reach both,
//! in the order Signal-Desktop's privacy settings use:
//!
//! - "Who can find me by number" is also held by the chat server, which the
//!   contact-discovery service consults. The server is told first.
//! - "Who can see my number" is also a flag in our encrypted profile, which is
//!   what contacts' clients read. The profile is written last, after the record.
//!
//! Every step is safe to repeat, so a change that failed partway is completed
//! by asking for it again.

use libsignal_service::proto::sync_message;
use tracing::info;

use crate::model::account::{AccountSetting, AccountSettings};
use crate::storage_record::{
    set_account_phone_number_sharing, set_account_read_receipts, set_account_typing_indicators,
    set_account_unlisted_phone_number,
};
use crate::store::Store;
use crate::{Error, Manager};

use super::Registered;

impl<S: Store> Manager<S, Registered> {
    /// The settings the account record holds, or `None` until a storage sync
    /// has read the record.
    pub async fn account_settings(&self) -> Result<Option<AccountSettings>, Error<S::Error>> {
        let Some(identity) = self.store.account_storage_identity().await? else {
            return Ok(None);
        };
        Ok(Some(AccountSettings::from_record(&identity.record)?))
    }

    /// Change one setting on every device and on the server.
    ///
    /// Sharing the number with everybody also makes the account findable by
    /// it, and hiding the account while it shares its number is refused with
    /// [`Error::UnlistedWhileSharingPhoneNumber`]: Signal's clients keep the
    /// two together.
    ///
    /// Callers must hold the storage-service lock.
    pub async fn update_account_setting(
        &mut self,
        setting: AccountSetting,
    ) -> Result<(), Error<S::Error>> {
        info!(?setting, "changing an account setting");
        match setting {
            AccountSetting::ReadReceipts(on) => {
                self.edit_account_record(|record| set_account_read_receipts(record, on))
                    .await
            }
            AccountSetting::TypingIndicators(on) => {
                self.edit_account_record(|record| set_account_typing_indicators(record, on))
                    .await
            }
            AccountSetting::DiscoverableByPhoneNumber(discoverable) => {
                let sharing = self
                    .account_settings()
                    .await?
                    .is_some_and(|settings| settings.phone_number_sharing);
                if sharing && !discoverable {
                    return Err(Error::UnlistedWhileSharingPhoneNumber);
                }
                self.own_account_manager()
                    .await?
                    .set_phone_number_discoverability(discoverable)
                    .await?;
                self.edit_account_record(|record| {
                    set_account_unlisted_phone_number(record, !discoverable)
                })
                .await
            }
            AccountSetting::PhoneNumberSharing(everybody) => {
                let mut account_manager = self.own_account_manager().await?;
                if everybody {
                    account_manager
                        .set_phone_number_discoverability(true)
                        .await?;
                }
                self.edit_account_record(|record| {
                    let record = set_account_phone_number_sharing(record, everybody)?;
                    if everybody {
                        set_account_unlisted_phone_number(&record, false)
                    } else {
                        Ok(record)
                    }
                })
                .await?;
                let aci = self.state.data.service_ids.aci();
                account_manager
                    .set_phone_number_sharing(aci, everybody, &mut rand::rng())
                    .await?;
                self.notify_fetch_latest(sync_message::fetch_latest::Type::LocalProfile)
                    .await;
                Ok(())
            }
        }
    }

    /// Tell the chat server whether the account can be found by its number,
    /// as the account record says. Returns `false`, sending nothing, until a
    /// storage sync has read the record.
    ///
    /// The server keeps its own copy, and builds of presage before linked
    /// devices stopped sending account attributes overwrote it with
    /// "findable" on every connection. This puts the user's choice back
    /// without waiting for the primary to send its attributes again.
    pub async fn republish_phone_number_discoverability(
        &mut self,
    ) -> Result<bool, Error<S::Error>> {
        let Some(settings) = self.account_settings().await? else {
            return Ok(false);
        };
        self.own_account_manager()
            .await?
            .set_phone_number_discoverability(settings.discoverable_by_phone_number)
            .await?;
        Ok(true)
    }
}
