enum_number!(TransactionGroup {
    Test = 0,
    Core = 1,
    Reserved = 1000,
});

impl Default for TransactionGroup {
    fn default() -> TransactionGroup {
        TransactionGroup::Core
    }
}
