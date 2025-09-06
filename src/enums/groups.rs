enum_number!(TransactionGroup {
    Core = 1,
});

impl Default for TransactionGroup {
    fn default() -> TransactionGroup {
        TransactionGroup::Core
    }
}
