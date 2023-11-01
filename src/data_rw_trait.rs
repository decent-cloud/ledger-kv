pub trait LedgerKvMetadata {
    fn save(&self);
    fn refresh(&mut self);
    fn get_num_entries(&self) -> usize;
    fn inc_num_entries(&mut self);
    fn get_parent_hash(&self) -> &[u8];
}
