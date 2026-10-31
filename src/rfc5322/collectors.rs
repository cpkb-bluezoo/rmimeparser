//! Collectors that rebuild address and message-id lists from the parser's events.
//!
//! The RFC 5322 layer delivers an address header an address at a time so that
//! nothing has to be held; a handler that does want the list puts the events
//! through a collector and takes it at the end:
//!
//! ```ignore
//! fn start_address_header(&mut self, _name: &str) -> ParseResult<()> {
//!     self.addresses.clear();
//!     Ok(())
//! }
//! fn mailbox(&mut self, display_name: Option<&str>, local: &str, domain: &str) -> ParseResult<()> {
//!     self.addresses.mailbox(display_name, local, domain);
//!     Ok(())
//! }
//! // ... start_group, end_group likewise
//! fn end_address_header(&mut self) -> ParseResult<()> {
//!     let list = self.addresses.take();
//!     Ok(())
//! }
//! ```

use crate::mime::ContentId;

use super::email_address::EmailAddress;
use super::group_email_address::{Address, GroupEmailAddress};

/// Collects an address list, groups included.
#[derive(Debug, Default)]
pub struct AddressListCollector {
    addresses: Vec<Address>,
    group: Option<(String, Vec<EmailAddress>)>,
}

impl AddressListCollector {
    /// Forgets what has been collected.
    pub fn clear(&mut self) {
        self.addresses.clear();
        self.group = None;
    }

    /// A mailbox, in the open group if there is one. (`simple` is whether it had
    /// no display name; the event does not say if it was written with angle
    /// brackets.)
    pub fn mailbox(&mut self, display_name: Option<&str>, local_part: &str, domain: &str) {
        let address = EmailAddress::new(
            display_name.map(str::to_string),
            local_part,
            domain,
            display_name.is_none(),
        );
        match self.group.as_mut() {
            Some((_, members)) => members.push(address),
            None => self.addresses.push(Address::Mailbox(address)),
        }
    }

    pub fn start_group(&mut self, name: &str) {
        self.group = Some((name.to_string(), Vec::new()));
    }

    pub fn end_group(&mut self) {
        if let Some((name, members)) = self.group.take() {
            self.addresses
                .push(Address::Group(GroupEmailAddress::new(name, members, None)));
        }
    }

    /// The list collected so far, which is emptied.
    pub fn take(&mut self) -> Vec<Address> {
        self.end_group();
        std::mem::take(&mut self.addresses)
    }
}

/// Collects a list of message-ids.
#[derive(Debug, Default)]
pub struct MessageIdListCollector {
    ids: Vec<ContentId>,
}

impl MessageIdListCollector {
    pub fn clear(&mut self) {
        self.ids.clear();
    }

    pub fn message_id(&mut self, local_part: &str, domain: &str) {
        self.ids.push(ContentId::new(local_part, domain));
    }

    /// The ids collected so far, which are emptied.
    pub fn take(&mut self) -> Vec<ContentId> {
        std::mem::take(&mut self.ids)
    }
}
