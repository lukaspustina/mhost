pub mod soa;

pub trait Differ {
    type FieldType: PartialEq + Eq;

    fn difference(&self, other: &Self) -> Difference<Self::FieldType>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Difference<T: PartialEq + Eq> {
    pub fields: Vec<T>,
}

impl<T: PartialEq + Eq> Difference<T> {
    pub fn new() -> Self {
        Difference {
            fields: Vec::new(),
        }
    }

    pub fn has_differences(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn differences(&self) -> &[T] {
        self.fields.as_slice()
    }
}
