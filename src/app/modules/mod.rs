use crate::app::console;

pub mod discover;
pub mod get_server_lists;
pub mod lookup;
pub mod soa_check;

/** Return type for App modules that go through multiple steps
 *
 * An App module might go through multiple distinct steps to eventually fulfill its task. A long this
 * wait, error might occur. Errors should be reported using `Result`. But what if a step finishes
 * without errors but still couldn't obtain the necessary information for the next step to proceed?
 * For this use case, `ModuleStep` works similar to an Either type for the `Result::Ok` side of the
 * execution.
 *
 * Think of it as a means for early returns.
 */
pub enum Partial<T> {
    Next(T),
    ExitStatus(console::ExitStatus),
}
