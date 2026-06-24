use rmimeparser::{EmailAddress, GroupEmailAddress};

#[test]
fn test_group_with_members() {
    let member1 = EmailAddress::new(Some("John".into()), "john", "example.com", false);
    let member2 = EmailAddress::new(Some("Jane".into()), "jane", "example.com", false);
    let group = GroupEmailAddress::new("Team", vec![member1, member2], None);
    assert_eq!(group.group_name(), "Team");
    assert_eq!(group.members().len(), 2);
}

#[test]
fn test_empty_group() {
    let group = GroupEmailAddress::new("Empty Group", vec![], None);
    assert_eq!(group.group_name(), "Empty Group");
    assert!(group.members().is_empty());
}

#[test]
fn test_group_with_comments() {
    let member = EmailAddress::new(Some("Alice".into()), "alice", "example.com", false);
    let group = GroupEmailAddress::new(
        "Marketing Team",
        vec![member],
        Some(vec!["Marketing".into()]),
    );
    assert_eq!(group.group_name(), "Marketing Team");
    assert_eq!(group.comments().unwrap().len(), 1);
}

#[test]
fn test_members_unmodifiable() {
    let member = EmailAddress::new(Some("Bob".into()), "bob", "example.com", false);
    let group = GroupEmailAddress::new("Group", vec![member], None);
    let members = group.members();
    assert_eq!(members.len(), 1);
}

#[test]
fn test_to_string() {
    let member = EmailAddress::new(Some("John".into()), "john", "example.com", false);
    let group = GroupEmailAddress::new("Team", vec![member], None);
    let s = group.to_string();
    assert!(s.contains("Team"));
}

#[test]
fn test_group_has_empty_address() {
    let group = GroupEmailAddress::new("Team", vec![], None);
    assert_eq!(group.local_part(), "");
    assert_eq!(group.domain(), "");
    assert_eq!(group.address(), "");
}
