enum_number!(TypeGroup {
    Test = 0,
    Core = 1,
    Reserved = 1000,
});

impl Default for TypeGroup {
    fn default() -> TypeGroup {
        TypeGroup::Core
    }
}
