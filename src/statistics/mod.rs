pub mod lookups;
pub mod server_lists;
pub mod whois;

mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};

    lazy_static! {
        pub static ref NORMAL: Style = Style::default();
        pub static ref BOLD: Style = Style::new(Color::White).bold();
        pub static ref GOOD: Style = Style::new(Color::Green);
        pub static ref WARN: Style = Style::new(Color::Yellow);
        pub static ref ERR: Style = Style::new(Color::Red);
    }
}

pub trait Statistics<'a> {
    type StatsOut;

    fn statistics(&'a self) -> Self::StatsOut;
}

#[derive(Debug)]
pub struct Summary<T: Ord + Clone> {
    pub min: Option<T>,
    pub max: Option<T>,
}

impl<T: Ord + Clone> Summary<T> {
    pub fn summary(values: &[T]) -> Summary<T> {
        let min = values.iter().min().cloned();
        let max = values.iter().max().cloned();

        Summary { min, max }
    }
}
